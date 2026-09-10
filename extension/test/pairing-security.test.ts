import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import test from "node:test";

import { withDirectorySyncObserverForTest } from "../internal/directory-durability.ts";
import { FakePiHost } from "./fake-pi-host.ts";

const VALID_PAIRING_CODE = "A".repeat(32);

type RelayExtension = (pi: unknown) => void;

async function loadRelayExtension(): Promise<RelayExtension> {
  return (await import(`../index.ts?security=${randomUUID()}`)).default as RelayExtension;
}

function captureStructuredErrors(): { lines: string[]; restore: () => void } {
  const lines: string[] = [];
  const original = console.error;
  console.error = (...values: unknown[]) => lines.push(values.map(String).join(" "));
  return { lines, restore: () => (console.error = original) };
}

async function createTestRoot(context: { after(callback: () => Promise<void>): void }): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "pi-relay-extension-security-"));
  await chmod(root, 0o700);
  context.after(async () => rm(root, { recursive: true, force: true }));
  return root;
}

function installPairingEnvironment(stateDirectory: string): () => void {
  const previousURL = process.env.PI_MESSAGING_RELAY_URL;
  const previousState = process.env.PI_MESSAGING_RELAY_STATE_DIR;
  process.env.PI_MESSAGING_RELAY_URL = "http://127.0.0.1:31415";
  process.env.PI_MESSAGING_RELAY_STATE_DIR = stateDirectory;
  return () => {
    if (previousURL === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = previousURL;
    if (previousState === undefined) delete process.env.PI_MESSAGING_RELAY_STATE_DIR;
    else process.env.PI_MESSAGING_RELAY_STATE_DIR = previousState;
  };
}

for (const testCase of [
  { name: "malformed fixed-format code", input: "A".repeat(31) },
  { name: "over-limit UTF-8 argument", input: "é".repeat(2049) },
]) {
  test(`pair command rejects ${testCase.name} before key or request work`, { concurrency: false }, async (context) => {
    const root = await createTestRoot(context);
    const stateDirectory = join(root, "state");
    const restoreEnvironment = installPairingEnvironment(stateDirectory);
    const originalFetch = globalThis.fetch;
    let fetchCalls = 0;
    globalThis.fetch = async () => {
      fetchCalls += 1;
      throw new Error("fetch must not run for a locally invalid pairing code");
    };
    const logs = captureStructuredErrors();

    try {
      const host = new FakePiHost();
      const relayExtension = await loadRelayExtension();
      relayExtension(host.api);
      await host.executeCommand("relay-pair", testCase.input);

      assert.equal(fetchCalls, 0);
      await assert.rejects(stat(stateDirectory), { code: "ENOENT" });
      assert.deepEqual(host.notifications, [
        {
          message: "Pairing failed: code must contain exactly 32 URL-safe characters.",
          level: "error",
        },
      ]);
      assert.deepEqual(host.sendMessageAttempts, []);
      assert.deepEqual(host.sendUserMessageAttempts, []);
      assert.deepEqual(host.liveAccessAttempts, []);
      assert.equal(logs.lines.length, 1);
      assert.equal(JSON.parse(logs.lines[0]).reason, "pairing_code_invalid_format");
      assert.equal(logs.lines[0].includes(testCase.input), false);
    } finally {
      logs.restore();
      globalThis.fetch = originalFetch;
      restoreEnvironment();
    }
  });
}

test("pair command submits only after recursive state and key publication are directory-synced", { concurrency: false }, async (context) => {
  const root = await createTestRoot(context);
  const stateDirectory = join(root, "installation", "state");
  const restoreEnvironment = installPairingEnvironment(stateDirectory);
  const originalFetch = globalThis.fetch;
  const operations: string[] = [];
  globalThis.fetch = async (_input, init) => {
    operations.push("fetch");
    assert.equal(typeof init?.body, "string");
    assert.equal(Buffer.byteLength(String(init?.body), "utf8"), 126);
    const keyInfo = await stat(join(stateDirectory, "installation-ed25519.pem"));
    assert.equal(keyInfo.mode & 0o777, 0o600);
    return new Response('{"client_id":"cli_0123456789abcdef"}', {
      status: 201,
      headers: { "Content-Type": "application/json" },
    });
  };
  const logs = captureStructuredErrors();

  try {
    const host = new FakePiHost();
    const relayExtension = await loadRelayExtension();
    relayExtension(host.api);
    await withDirectorySyncObserverForTest(
      { afterDirectorySync: (path) => operations.push(`sync:${path}`) },
      () => host.executeCommand("relay-pair", VALID_PAIRING_CODE),
    );

    assert.deepEqual(operations, [
      `sync:${root}`,
      `sync:${join(root, "installation")}`,
      `sync:${resolve(stateDirectory)}`,
      "fetch",
    ]);
    assert.deepEqual(host.notifications, [
      { message: "Relay pairing accepted client identity cli_0123456789abcdef.", level: "success" },
    ]);
    assert.deepEqual(host.sendMessageAttempts, []);
    assert.deepEqual(host.sendUserMessageAttempts, []);
    assert.deepEqual(host.liveAccessAttempts, []);
    assert.equal(logs.lines.some((line) => line.includes(VALID_PAIRING_CODE)), false);
  } finally {
    logs.restore();
    globalThis.fetch = originalFetch;
    restoreEnvironment();
  }
});

test("directory-sync failure after key publication prevents HTTP submission", { concurrency: false }, async (context) => {
  const root = await createTestRoot(context);
  const stateDirectory = join(root, "installation", "state");
  const restoreEnvironment = installPairingEnvironment(stateDirectory);
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error("fetch must not run before durable key publication");
  };
  const logs = captureStructuredErrors();

  try {
    const host = new FakePiHost();
    const relayExtension = await loadRelayExtension();
    relayExtension(host.api);
    await withDirectorySyncObserverForTest(
      {
        afterDirectorySync: (path) => {
          if (path === resolve(stateDirectory)) throw new Error("injected directory sync failure");
        },
      },
      () => host.executeCommand("relay-pair", VALID_PAIRING_CODE),
    );

    assert.equal(fetchCalls, 0);
    assert.equal((await stat(join(stateDirectory, "installation-ed25519.pem"))).mode & 0o777, 0o600);
    assert.deepEqual(host.notifications, [
      {
        message: "Pairing failed: installation private key could not be persisted atomically.",
        level: "error",
      },
    ]);
    assert.deepEqual(host.sendMessageAttempts, []);
    assert.deepEqual(host.sendUserMessageAttempts, []);
    assert.deepEqual(host.liveAccessAttempts, []);
    assert.equal(logs.lines.length, 1);
    assert.equal(JSON.parse(logs.lines[0]).reason, "installation_key_persistence_failed");
    assert.equal(logs.lines[0].includes(VALID_PAIRING_CODE), false);
  } finally {
    logs.restore();
    globalThis.fetch = originalFetch;
    restoreEnvironment();
  }
});

for (const testCase of [
  {
    name: "duplicate client_id response fields",
    contentType: "application/json",
    body: '{"client_id":"cli_0123456789abcdef","client_\\u0069d":"cli_fedcba9876543210"}',
  },
  {
    name: "malformed JSON media type prefix",
    contentType: "application/json-evil",
    body: '{"client_id":"cli_0123456789abcdef"}',
  },
  {
    name: "client identity outside server token format",
    contentType: "application/json",
    body: '{"client_id":"attacker-selected"}',
  },
]) {
  test(`pair command rejects ${testCase.name}`, { concurrency: false }, async (context) => {
    const root = await createTestRoot(context);
    const stateDirectory = join(root, "state");
    const restoreEnvironment = installPairingEnvironment(stateDirectory);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response(testCase.body, {
        status: 201,
        headers: { "Content-Type": testCase.contentType },
      });
    const logs = captureStructuredErrors();

    try {
      const host = new FakePiHost();
      const relayExtension = await loadRelayExtension();
      relayExtension(host.api);
      await host.executeCommand("relay-pair", VALID_PAIRING_CODE);

      assert.deepEqual(host.notifications, [
        {
          message: testCase.contentType === "application/json-evil"
            ? "Pairing failed: relay returned a non-JSON response."
            : testCase.name === "client identity outside server token format"
              ? "Pairing failed: relay response did not contain one valid client_id."
              : "Pairing failed: relay returned an invalid or non-canonical response object.",
          level: "error",
        },
      ]);
      assert.deepEqual(host.sendMessageAttempts, []);
      assert.deepEqual(host.sendUserMessageAttempts, []);
      assert.deepEqual(host.liveAccessAttempts, []);
      assert.equal(logs.lines.length, 1);
      assert.equal(JSON.parse(logs.lines[0]).reason, "invalid_response");
      assert.equal(logs.lines[0].includes(VALID_PAIRING_CODE), false);
      assert.equal(logs.lines[0].includes("attacker-selected"), false);
    } finally {
      logs.restore();
      globalThis.fetch = originalFetch;
      restoreEnvironment();
    }
  });
}
