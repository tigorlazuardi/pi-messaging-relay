import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Value } from "typebox/value";

import { FakePiHost } from "./fake-pi-host.ts";

const EXPECTED_DISCONNECTED_ERROR =
  "Relay is disconnected. Pair this installation with /relay-pair CODE, then wait for a relay-enabled connection release.";
const EXPECTED_PAIRING_UNCONFIGURED =
  "Pairing failed: set PI_MESSAGING_RELAY_URL to the relay loopback origin, then retry /relay-pair CODE.";
const VALID_PAIRING_CODE = "0123456789abcdefghijklmnopqrstuv";

async function loadRelayExtension() {
  return (await import("../index.ts")).default;
}

function installResourceGuards(resourceAttempts: string[]): () => void {
  const replacements = new Map<string, unknown>([
    [
      "setTimeout",
      (..._args: unknown[]) => {
        resourceAttempts.push("setTimeout");
        throw new Error("Timer creation forbidden while disconnected");
      },
    ],
    [
      "setInterval",
      (..._args: unknown[]) => {
        resourceAttempts.push("setInterval");
        throw new Error("Timer creation forbidden while disconnected");
      },
    ],
    [
      "fetch",
      (..._args: unknown[]) => {
        resourceAttempts.push("fetch");
        throw new Error("Network access forbidden while disconnected");
      },
    ],
    [
      "WebSocket",
      class {
        constructor() {
          resourceAttempts.push("WebSocket");
          throw new Error("Socket creation forbidden while disconnected");
        }
      },
    ],
  ]);
  const originals = new Map<string, PropertyDescriptor | undefined>();

  for (const [name, value] of replacements) {
    originals.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
    Object.defineProperty(globalThis, name, {
      configurable: true,
      writable: true,
      value,
    });
  }

  return () => {
    for (const [name, descriptor] of [...originals].reverse()) {
      if (descriptor) {
        Object.defineProperty(globalThis, name, descriptor);
      } else {
        Reflect.deleteProperty(globalThis, name);
      }
    }
  };
}

function captureStructuredErrors(): {
  lines: string[];
  restore: () => void;
} {
  const lines: string[] = [];
  const original = console.error;
  console.error = (...values: unknown[]) => {
    lines.push(values.map(String).join(" "));
  };
  return {
    lines,
    restore: () => {
      console.error = original;
    },
  };
}

test("loads and runs disconnected handlers without starting resources", { concurrency: false }, async () => {
  const host = new FakePiHost();
  const resourceAttempts: string[] = [];
  const restoreResources = installResourceGuards(resourceAttempts);
  const logs = captureStructuredErrors();
  const previousEndpoint = process.env.PI_MESSAGING_RELAY_URL;
  delete process.env.PI_MESSAGING_RELAY_URL;

  try {
    const extensionUrl = new URL("../index.ts", import.meta.url);
    extensionUrl.searchParams.set("resource-guard", randomUUID());
    const relayExtension = (await import(extensionUrl.href)).default;
    assert.equal(relayExtension.length, 1);

    const result = relayExtension(host.api as never);
    assert.equal(result, undefined);
    await host.executeCommand("relay-pair", VALID_PAIRING_CODE);
    await assert.rejects(host.executeTool("list_peers", {}), {
      name: "Error",
      message: EXPECTED_DISCONNECTED_ERROR,
    });
    await assert.rejects(host.executeTool("list_peers", { cursor: "cur_cGVlcg" }), {
      name: "Error",
      message: EXPECTED_DISCONNECTED_ERROR,
    });
    await assert.rejects(
      host.executeTool("agent_send", {
        to: "/srv/backend@host#route-id",
        body: "sensitive-message-body",
      }),
      { name: "Error", message: EXPECTED_DISCONNECTED_ERROR },
    );
  } finally {
    try {
      logs.restore();
    } finally {
      restoreResources();
      if (previousEndpoint === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
      else process.env.PI_MESSAGING_RELAY_URL = previousEndpoint;
    }
  }

  assert.deepEqual(host.registrations, [
    { kind: "command", name: "relay-pair" },
    { kind: "tool", name: "list_peers" },
    { kind: "tool", name: "agent_send" },
  ]);
  assert.deepEqual([...host.commands.keys()], ["relay-pair"]);
  assert.deepEqual([...host.tools.keys()], ["list_peers", "agent_send"]);
  assert.deepEqual(host.notifications, [
    { message: EXPECTED_PAIRING_UNCONFIGURED, level: "error" },
  ]);
  assert.deepEqual(resourceAttempts, []);
  assert.deepEqual(host.liveAccessAttempts, []);
  assert.deepEqual(host.sendMessageAttempts, []);
  assert.deepEqual(host.sendUserMessageAttempts, []);
  assert.equal(logs.lines.some((line) => line.includes(VALID_PAIRING_CODE)), false);
  assert.equal(logs.lines.some((line) => line.includes("sensitive-message-body")), false);
});

test("unpaired session lifecycle stays disconnected without opening resources", { concurrency: false }, async (context) => {
  const root = await mkdtemp(join(tmpdir(), "pi-relay-unpaired-session-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const stateDirectory = join(root, "missing-state");
  const previousEndpoint = process.env.PI_MESSAGING_RELAY_URL;
  const previousState = process.env.PI_MESSAGING_RELAY_STATE_DIR;
  process.env.PI_MESSAGING_RELAY_URL = "http://127.0.0.1:31415";
  process.env.PI_MESSAGING_RELAY_STATE_DIR = stateDirectory;
  const resourceAttempts: string[] = [];
  const restoreResources = installResourceGuards(resourceAttempts);
  const host = new FakePiHost();

  try {
    const relayExtension = await loadRelayExtension();
    relayExtension(host.api as never);
    await host.emit("session_start");
    await host.emit("session_shutdown");
    await host.emit("session_shutdown");
  } finally {
    restoreResources();
    if (previousEndpoint === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = previousEndpoint;
    if (previousState === undefined) delete process.env.PI_MESSAGING_RELAY_STATE_DIR;
    else process.env.PI_MESSAGING_RELAY_STATE_DIR = previousState;
  }

  assert.deepEqual(resourceAttempts, []);
  await assert.rejects(stat(stateDirectory), { code: "ENOENT" });
  assert.deepEqual(host.sendMessageAttempts, []);
  assert.deepEqual(host.sendUserMessageAttempts, []);
});

test("configured key with missing endpoint rejects startup before WebSocket creation", { concurrency: false }, async (context) => {
  const root = await mkdtemp(join(tmpdir(), "pi-relay-unconfigured-session-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const stateDirectory = join(root, "state");
  const previousEndpoint = process.env.PI_MESSAGING_RELAY_URL;
  const previousState = process.env.PI_MESSAGING_RELAY_STATE_DIR;
  const originalFetch = globalThis.fetch;
  process.env.PI_MESSAGING_RELAY_URL = "http://127.0.0.1:31415";
  process.env.PI_MESSAGING_RELAY_STATE_DIR = stateDirectory;
  globalThis.fetch = async () => new Response('{"client_id":"cli_0123456789abcdef"}', {
    status: 201,
    headers: { "Content-Type": "application/json" },
  });
  const host = new FakePiHost();
  const logs = captureStructuredErrors();

  try {
    const relayExtension = await loadRelayExtension();
    relayExtension(host.api as never);
    await host.executeCommand("relay-pair", VALID_PAIRING_CODE);
    delete process.env.PI_MESSAGING_RELAY_URL;
    const resourceAttempts: string[] = [];
    const restoreResources = installResourceGuards(resourceAttempts);
    try {
      await host.emit("session_start");
      await host.emit("session_shutdown");
    } finally {
      restoreResources();
    }
    assert.deepEqual(resourceAttempts, []);
  } finally {
    logs.restore();
    globalThis.fetch = originalFetch;
    if (previousEndpoint === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = previousEndpoint;
    if (previousState === undefined) delete process.env.PI_MESSAGING_RELAY_STATE_DIR;
    else process.env.PI_MESSAGING_RELAY_STATE_DIR = previousState;
  }

  const events = logs.lines.map((line) => JSON.parse(line) as Record<string, unknown>);
  assert.equal(events.some((event) =>
    event.event === "relay_auth_rejected" && event.reason === "endpoint_not_configured"), true);
  assert.deepEqual(host.sendMessageAttempts, []);
  assert.deepEqual(host.sendUserMessageAttempts, []);
});

test("publishes closed tool schemas matching the accepted model intents", { concurrency: false }, async () => {
  const host = new FakePiHost();
  const relayExtension = await loadRelayExtension();
  relayExtension(host.api as never);

  const listSchema = host.tools.get("list_peers")?.parameters;
  const sendSchema = host.tools.get("agent_send")?.parameters;
  assert.ok(listSchema);
  assert.ok(sendSchema);

  const maximumCursor = `cur_${Buffer.from("a".repeat(4_389), "utf8").toString("base64url")}`;
  assert.equal(maximumCursor.length, 5_856);
  assert.equal(Value.Check(listSchema as never, {}), true);
  assert.equal(Value.Check(listSchema as never, { cursor: "cur_cGVlcg" }), true);
  assert.equal(Value.Check(listSchema as never, { cursor: maximumCursor }), true);
  assert.equal(Value.Check(listSchema as never, { cursor: "" }), false);
  assert.equal(Value.Check(listSchema as never, { cursor: "cur_" }), false);
  assert.equal(Value.Check(listSchema as never, { cursor: "cur_cGVlcg==" }), false);
  assert.equal(Value.Check(listSchema as never, { cursor: `${maximumCursor}a` }), false);
  assert.equal(Value.Check(listSchema as never, { cursor: 12 }), false);
  assert.equal(Value.Check(listSchema as never, { unexpected: true }), false);

  const stringSend = {
    to: "/srv/backend@host#route-id",
    body: "Review the API contract",
    re: "original-message-id",
  };
  const objectSend = {
    to: "/srv/backend@host#route-id",
    body: { action: "review", priority: 1 },
  };
  assert.equal(Value.Check(sendSchema as never, stringSend), true);
  assert.equal(Value.Check(sendSchema as never, objectSend), true);
  assert.equal(Value.Check(sendSchema as never, { ...stringSend, message_id: "client-id" }), false);
  assert.equal(Value.Check(sendSchema as never, { to: stringSend.to, body: ["not", "an", "object"] }), false);
  assert.equal(Value.Check(sendSchema as never, { to: "", body: "message" }), false);
  assert.equal(Value.Check(sendSchema as never, { to: stringSend.to, body: null }), false);
});

test("relay-pair fails closed when endpoint configuration is absent", { concurrency: false }, async () => {
  const previousEndpoint = process.env.PI_MESSAGING_RELAY_URL;
  delete process.env.PI_MESSAGING_RELAY_URL;
  const host = new FakePiHost();
  const relayExtension = await loadRelayExtension();
  relayExtension(host.api as never);
  const logs = captureStructuredErrors();

  try {
    await host.executeCommand("relay-pair", VALID_PAIRING_CODE);
  } finally {
    logs.restore();
    if (previousEndpoint === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = previousEndpoint;
  }

  assert.deepEqual(host.notifications, [
    { message: EXPECTED_PAIRING_UNCONFIGURED, level: "error" },
  ]);
  assert.deepEqual(host.sendMessageAttempts, []);
  assert.deepEqual(host.sendUserMessageAttempts, []);
  assert.deepEqual(host.liveAccessAttempts, []);
  assert.equal(logs.lines.length, 1);
  const event = JSON.parse(logs.lines[0]);
  assert.deepEqual({ ...event, latency_ms: 0 }, {
    level: "warn",
    event: "relay_pair_rejected",
    operation: "relay-pair",
    result: "rejected",
    reason: "endpoint_not_configured",
    pairing_code: "<redacted>",
    private_key: "<redacted>",
    latency_ms: 0,
  });
  assert.equal(typeof event.latency_ms, "number");
  assert.equal(logs.lines[0].includes(VALID_PAIRING_CODE), false);
});

test("both tools fail through Pi's thrown-error path while disconnected", { concurrency: false }, async () => {
  const host = new FakePiHost();
  const relayExtension = await loadRelayExtension();
  relayExtension(host.api as never);
  const logs = captureStructuredErrors();
  const secretBody = "sensitive-message-body";

  try {
    await assert.rejects(host.executeTool("list_peers", {}), {
      name: "Error",
      message: EXPECTED_DISCONNECTED_ERROR,
    });
    await assert.rejects(
      host.executeTool("agent_send", {
        to: "/srv/backend@host#route-id",
        body: secretBody,
      }),
      { name: "Error", message: EXPECTED_DISCONNECTED_ERROR },
    );
  } finally {
    logs.restore();
  }

  assert.deepEqual(
    logs.lines.map((line) => JSON.parse(line)),
    [
      {
        level: "warn",
        event: "relay_operation_failed",
        operation: "list_peers",
        reason: "disconnected",
      },
      {
        level: "warn",
        event: "relay_operation_failed",
        operation: "agent_send",
        reason: "disconnected",
      },
    ],
  );
  assert.equal(logs.lines.some((line) => line.includes(secretBody)), false);
  assert.deepEqual(host.sendMessageAttempts, []);
  assert.deepEqual(host.sendUserMessageAttempts, []);
  assert.deepEqual(host.liveAccessAttempts, []);
});
