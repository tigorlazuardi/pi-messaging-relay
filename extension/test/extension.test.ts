import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { Value } from "typebox/value";

import { FakePiHost } from "./fake-pi-host.ts";

const EXPECTED_DISCONNECTED_ERROR =
  "Relay is disconnected. /relay-pair is unavailable in this shell; install a relay-enabled release before retrying.";
const EXPECTED_PAIRING_UNAVAILABLE =
  "Pairing unavailable: no pairing occurred and the relay remains disconnected. Install a relay-enabled release before retrying.";

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

  try {
    const extensionUrl = new URL("../index.ts", import.meta.url);
    extensionUrl.searchParams.set("resource-guard", randomUUID());
    const relayExtension = (await import(extensionUrl.href)).default;

    const result = relayExtension(host.api as never);
    assert.equal(result, undefined);
    await host.executeCommand("relay-pair", "sensitive-pairing-code");
    await assert.rejects(host.executeTool("list_peers", {}), {
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
    { message: EXPECTED_PAIRING_UNAVAILABLE, level: "error" },
  ]);
  assert.deepEqual(resourceAttempts, []);
  assert.deepEqual(host.liveAccessAttempts, []);
  assert.deepEqual(host.sendMessageAttempts, []);
  assert.deepEqual(host.sendUserMessageAttempts, []);
  assert.equal(logs.lines.some((line) => line.includes("sensitive-pairing-code")), false);
  assert.equal(logs.lines.some((line) => line.includes("sensitive-message-body")), false);
});

test("publishes closed tool schemas matching the accepted model intents", { concurrency: false }, async () => {
  const host = new FakePiHost();
  const relayExtension = await loadRelayExtension();
  relayExtension(host.api as never);

  const listSchema = host.tools.get("list_peers")?.parameters;
  const sendSchema = host.tools.get("agent_send")?.parameters;
  assert.ok(listSchema);
  assert.ok(sendSchema);

  assert.equal(Value.Check(listSchema as never, {}), true);
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

test("relay-pair reports that pairing did not occur without injection", { concurrency: false }, async () => {
  const host = new FakePiHost();
  const relayExtension = await loadRelayExtension();
  relayExtension(host.api as never);
  const logs = captureStructuredErrors();

  try {
    await host.executeCommand("relay-pair", "sensitive-pairing-code");
  } finally {
    logs.restore();
  }

  assert.deepEqual(host.notifications, [
    { message: EXPECTED_PAIRING_UNAVAILABLE, level: "error" },
  ]);
  assert.deepEqual(host.sendMessageAttempts, []);
  assert.deepEqual(host.sendUserMessageAttempts, []);
  assert.deepEqual(host.liveAccessAttempts, []);
  assert.equal(logs.lines.length, 1);
  assert.deepEqual(JSON.parse(logs.lines[0]), {
    level: "warn",
    event: "relay_operation_failed",
    operation: "relay-pair",
    reason: "not_implemented",
  });
  assert.equal(logs.lines[0].includes("sensitive-pairing-code"), false);
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
