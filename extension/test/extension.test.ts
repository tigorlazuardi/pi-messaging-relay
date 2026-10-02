import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Value } from "typebox/value";

import { clientConfigurationPath, ENDPOINT_ENV } from "../internal/client-config.ts";
import { readSessionLogTail } from "../internal/session-log.ts";
import { installReconnectDependenciesForTest } from "../internal/reconnect.ts";
import { FakePiHost } from "./fake-pi-host.ts";

const EXPECTED_DISCONNECTED_ERROR =
  "Relay is disconnected. Write ~/.config/pi/pi-messaging-relay.json with mode 0600 (url required, secret optional) or set PI_MESSAGING_RELAY_URL, then restart the session.";

async function loadRelayExtension() {
  return (await import("../index.ts")).default;
}

async function loadIsolatedRelayExtension(marker: string) {
  return (await import(`../index.ts?${marker}=${randomUUID()}`)).default;
}

async function createHome(context: { after(callback: () => Promise<void>): void }): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), "pi-relay-extension-"));
  context.after(async () => rm(home, { recursive: true, force: true }));
  return home;
}

async function waitUntil(
  predicate: () => boolean | Promise<boolean>,
  action: string,
  timeoutMS = 1_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMS;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`Timed out waiting for ${action}`);
}

async function writeConfig(home: string, text: string, mode: number): Promise<void> {
  await mkdir(join(home, ".config", "pi"), { recursive: true, mode: 0o700 });
  await writeFile(clientConfigurationPath(home), text, { mode: 0o600 });
  await chmod(clientConfigurationPath(home), mode);
}

function installIsolatedHome(home: string): { restore(): void } {
  const previousHome = process.env.HOME;
  const previousXDG = process.env.XDG_CONFIG_HOME;
  const previousEndpoint = process.env[ENDPOINT_ENV];
  process.env.HOME = home;
  delete process.env.XDG_CONFIG_HOME;
  delete process.env[ENDPOINT_ENV];
  return {
    restore: () => {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
      if (previousXDG === undefined) delete process.env.XDG_CONFIG_HOME;
      else process.env.XDG_CONFIG_HOME = previousXDG;
      if (previousEndpoint === undefined) delete process.env[ENDPOINT_ENV];
      else process.env[ENDPOINT_ENV] = previousEndpoint;
    },
  };
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
        throw new Error("Interval creation forbidden while disconnected");
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

test("loads and runs disconnected handlers without starting resources", { concurrency: false }, async (context) => {
  const home = await createHome(context);
  const environment = installIsolatedHome(home);
  const host = new FakePiHost();
  const resourceAttempts: string[] = [];
  const restoreResources = installResourceGuards(resourceAttempts);
  const logs = captureStructuredErrors();

  try {
    const relayExtension = await loadIsolatedRelayExtension("resource-guard");
    assert.equal(relayExtension.length, 1);

    const result = relayExtension(host.api as never);
    assert.equal(result, undefined);
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
      environment.restore();
    }
  }

  assert.deepEqual(host.registrations, [
    { kind: "command", name: "relay-logs" },
    { kind: "tool", name: "list_peers" },
    { kind: "tool", name: "agent_send" },
  ]);
  assert.deepEqual([...host.commands.keys()], ["relay-logs"]);
  assert.deepEqual([...host.tools.keys()], ["list_peers", "agent_send"]);
  assert.deepEqual(resourceAttempts, []);
  assert.deepEqual(host.liveAccessAttempts, []);
  assert.deepEqual(host.sendMessageAttempts, []);
  assert.deepEqual(host.sendUserMessageAttempts, []);
  assert.equal(logs.lines.some((line) => line.includes("sensitive-message-body")), false);
});

test("unconfigured session lifecycle stays disconnected without opening resources", { concurrency: false }, async (context) => {
  const home = await createHome(context);
  const environment = installIsolatedHome(home);
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
    environment.restore();
  }

  assert.deepEqual(resourceAttempts, []);
  await assert.rejects(stat(join(home, ".config")), { code: "ENOENT" });
  assert.deepEqual(host.sendMessageAttempts, []);
  assert.deepEqual(host.sendUserMessageAttempts, []);
});

test("invalid configuration file stays disconnected with one closed diagnostic and no fallback", { concurrency: false }, async (context) => {
  const home = await createHome(context);
  await writeConfig(home, JSON.stringify({ url: "http://127.0.0.1:31415", secret: "config-secret" }), 0o644);
  const environment = installIsolatedHome(home);
  const resourceAttempts: string[] = [];
  const restoreResources = installResourceGuards(resourceAttempts);
  const host = new FakePiHost();
  const logs = captureStructuredErrors();

  try {
    const relayExtension = await loadRelayExtension();
    relayExtension(host.api as never);
    await host.emit("session_start");
    // Connect is fire-and-forget; wait for the closed diagnostic before
    // shutdown. setImmediate polling: the disconnected-resource guards forbid
    // setTimeout here, and microtasks alone would starve config-file I/O.
    while (!logs.lines.some((line) => {
      try {
        return JSON.parse(line).event === "relay_config_rejected";
      } catch {
        return false;
      }
    })) {
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    await host.emit("session_shutdown");
  } finally {
    logs.restore();
    restoreResources();
    environment.restore();
  }

  assert.deepEqual(resourceAttempts, []);
  const events = logs.lines.map((line) => JSON.parse(line) as Record<string, unknown>);
  const rejected = events.filter((event) => event.event === "relay_config_rejected");
  assert.equal(rejected.length, 1);
  assert.deepEqual(
    { level: rejected[0].level, result: rejected[0].result, reason: rejected[0].reason, secret: rejected[0].secret },
    { level: "warn", result: "rejected", reason: "unsafe_config_permissions", secret: "<redacted>" },
  );
  assert.equal(events.some((event) => event.event === "relay_auth_rejected"), false);
  await assert.rejects(host.executeTool("list_peers", {}), {
    name: "Error",
    message: EXPECTED_DISCONNECTED_ERROR,
  });
  assert.equal(logs.lines.some((line) => line.includes("config-secret")), false);
  assert.deepEqual(host.sendMessageAttempts, []);
  assert.deepEqual(host.sendUserMessageAttempts, []);
});

test("environment endpoint alone attempts one bounded connection", { concurrency: false }, async (context) => {
  const home = await createHome(context);
  const environment = installIsolatedHome(home);
  process.env[ENDPOINT_ENV] = "http://127.0.0.1:31415";
  const scheduledDelays: number[] = [];
  const restoreDependencies = installReconnectDependenciesForTest({
    now: () => 1_800_000_000_000,
    randomUnit: () => 0.5,
    schedule: (_callback, delayMS) => {
      scheduledDelays.push(delayMS);
      return { cancel: () => undefined };
    },
  });
  const host = new FakePiHost();
  const logs = captureStructuredErrors();

  try {
    const relayExtension = await loadRelayExtension();
    relayExtension(host.api as never);
    await host.emit("session_start");
    // Connect is fire-and-forget; the synchronous rejection still lands only
    // after the emit returns. Wait for the bounded retry to be scheduled.
    await waitUntil(
      () => scheduledDelays.length >= 1,
      "bounded retry scheduled",
    );
    await host.emit("session_shutdown");
  } finally {
    logs.restore();
    restoreDependencies();
    environment.restore();
  }

  assert.deepEqual(scheduledDelays, [500]);
  const events = logs.lines.map((line) => JSON.parse(line) as Record<string, unknown>);
  const rejected = events.filter((event) => event.event === "relay_auth_rejected");
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason, "connection_failed");
  const scheduled = events.filter((event) => event.event === "relay_reconnect_scheduled");
  assert.deepEqual(
    scheduled.map((event) => ({ result: event.result, reason: event.reason, delay_ms: event.delay_ms })),
    [{ result: "scheduled", reason: "connection_failed", delay_ms: 500 }],
  );
  await assert.rejects(stat(join(home, ".config")), { code: "ENOENT" });
  assert.deepEqual(host.sendMessageAttempts, []);
  assert.deepEqual(host.sendUserMessageAttempts, []);
});

test("publishes the closed list_peers schema", { concurrency: false }, async () => {
  const host = new FakePiHost();
  const relayExtension = await loadRelayExtension();
  relayExtension(host.api as never);

  const listSchema = host.tools.get("list_peers")?.parameters;
  assert.ok(listSchema);

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
});

test("publishes only to, body, and optional canonical reply correlation for agent_send", { concurrency: false }, async () => {
  const host = new FakePiHost();
  const relayExtension = await loadRelayExtension();
  relayExtension(host.api as never);

  const sendSchema = host.tools.get("agent_send")?.parameters as {
    properties?: Record<string, unknown>;
    required?: string[];
    additionalProperties?: boolean;
  } | undefined;
  assert.ok(sendSchema);
  assert.deepEqual(Object.keys(sendSchema.properties ?? {}), ["to", "body", "re"]);
  assert.deepEqual(sendSchema.required, ["to", "body"]);
  assert.equal(sendSchema.additionalProperties, false);

  const stringSend = {
    to: "/srv/backend@host#route-id",
    body: "Review the API contract",
    re: "01993c80-40de-79d7-9b2c-1349f88bb408",
  };
  const objectSend = {
    to: "/srv/backend@host#route-id",
    body: { action: "review", priority: 1 },
  };
  assert.equal(Value.Check(sendSchema as never, stringSend), true);
  assert.equal(Value.Check(sendSchema as never, objectSend), true);
  for (const re of [
    "not-a-uuidv7",
    "01993C80-40DE-79D7-9B2C-1349F88BB408",
    "01993c80-40de-49d7-9b2c-1349f88bb408",
    "01993c80-40de-79d7-7b2c-1349f88bb408",
  ]) {
    assert.equal(Value.Check(sendSchema as never, { ...stringSend, re }), false);
  }
  for (const extra of [
    { message_id: "01993c80-40de-79d7-9b2c-1349f88bb408" },
    { request_id: "01993c80-40de-79d7-9b2c-1349f88bb408" },
    { delivery_id: "01993c80-40de-79d7-9b2c-1349f88bb408" },
    { mode: "reply" },
    { deliverAs: "steer" },
    { delivery_mode: "followUp" },
  ]) {
    assert.equal(Value.Check(sendSchema as never, { ...stringSend, ...extra }), false);
  }
  assert.equal(Value.Check(sendSchema as never, { to: stringSend.to, body: ["not", "an", "object"] }), false);
  assert.equal(Value.Check(sendSchema as never, { to: "", body: "message" }), false);
  assert.equal(Value.Check(sendSchema as never, { to: stringSend.to, body: null }), false);
});

test("diagnostic sink failure never replaces lifecycle or disconnected tool ownership", { concurrency: false }, async (context) => {
  const home = await createHome(context);
  const environment = installIsolatedHome(home);
  const host = new FakePiHost();
  const relayExtension = await loadRelayExtension();
  relayExtension(host.api as never);
  const originalError = console.error;
  console.error = () => { throw new Error("simulated diagnostic sink failure"); };

  try {
    await host.emit("session_start", { type: "session_start", reason: "startup" });
    await assert.rejects(
      host.executeTool("agent_send", {
        to: "/srv/backend@host#route-id",
        body: "private-body-must-not-reach-the-sink",
      }),
      { name: "Error", message: EXPECTED_DISCONNECTED_ERROR },
    );
    await host.emit("session_shutdown");
  } finally {
    console.error = originalError;
    environment.restore();
  }
});

test("both tools fail through Pi's thrown-error path while disconnected", { concurrency: false }, async (context) => {
  const home = await createHome(context);
  const environment = installIsolatedHome(home);
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
    environment.restore();
  }

  assert.deepEqual(
    logs.lines.map((line) => JSON.parse(line)),
    [
      {
        level: "warn",
        event: "relay_operation_failed",
        operation: "list_peers",
        result: "failed",
        reason: "disconnected",
      },
      {
        level: "warn",
        event: "relay_operation_failed",
        operation: "agent_send",
        result: "failed",
        reason: "disconnected",
        body: "<redacted>",
      },
    ],
  );
  assert.equal(logs.lines.some((line) => line.includes(secretBody)), false);
  assert.deepEqual(host.sendMessageAttempts, []);
  assert.deepEqual(host.sendUserMessageAttempts, []);
  assert.deepEqual(host.liveAccessAttempts, []);
});

test("headless host keeps no session log; /relay-logs reports the stderr stream", { concurrency: false }, async (context) => {
  const home = await createHome(context);
  const environment = installIsolatedHome(home);
  const host = new FakePiHost();
  const logs = captureStructuredErrors();

  try {
    const relayExtension = await loadIsolatedRelayExtension("relay-logs-headless");
    relayExtension(host.api as never);
    await host.emit("session_start", { type: "session_start", reason: "startup" });
    await assert.rejects(host.executeTool("list_peers", {}));
    await host.executeCommand("relay-logs");
  } finally {
    logs.restore();
    environment.restore();
  }

  // Headless (print-mode) hosts never capture a file; their stderr stream is
  // the record, and the command says so instead of inventing one.
  assert.ok(logs.lines.some((line) => line.includes("no session log")), JSON.stringify(logs.lines));
  assert.equal(logs.lines.some((line) => line.includes("relay_operation_failed") && line.startsWith("relay diagnostics")), false);
  assert.deepEqual(host.liveAccessAttempts, ["ctx.ui.custom"]);
  assert.deepEqual(host.notifications, []);
});

test("persisted TUI session logs per-session file, stderr stays quiet, /relay-logs tails it", { concurrency: false }, async (context) => {
  const home = await createHome(context);
  const environment = installIsolatedHome(home);
  const logDir = join(home, "relay-logs");
  process.env.PI_MESSAGING_RELAY_LOG_DIR = logDir;
  const host = new FakePiHost();
  host.mode = "tui";
  host.sessionFile = join(home, "session.jsonl");
  const logs = captureStructuredErrors();

  try {
    const relayExtension = await loadIsolatedRelayExtension("relay-logs-tui");
    relayExtension(host.api as never);
    await host.emit("session_start", { type: "session_start", reason: "startup" });
    await assert.rejects(host.executeTool("list_peers", {}));
    // Append writes are fire-and-forget; wait until the events land.
    await waitUntil(
      () => existsSync(join(logDir, "session.jsonl.log.jsonl")),
      "per-session diagnostic log file",
      2_000,
    );
    await waitUntil(
      () => readSessionLogTail(join(logDir, "session.jsonl.log.jsonl"), 200).then((lines) => lines.length >= 2),
      "session log captures started plus failed operation",
      2_000,
    );
    assert.equal(logs.lines.length, 0, "muted TUI hosts must not receive stderr diagnostics");
    await host.executeCommand("relay-logs");
  } finally {
    logs.restore();
    delete process.env.PI_MESSAGING_RELAY_LOG_DIR;
    environment.restore();
  }

  const snapshotLines = logs.lines.filter((line) => line.includes("relay_operation_failed"));
  assert.ok(snapshotLines.length >= 1, `expected tail lines in snapshot, got: ${JSON.stringify(logs.lines)}`);
  assert.ok(logs.lines.some((line) => line.includes(logDir)), `header must name the log file: ${JSON.stringify(logs.lines)}`);
  assert.deepEqual(host.liveAccessAttempts, ["ctx.ui.custom"]);
});
