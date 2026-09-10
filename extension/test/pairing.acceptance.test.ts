import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { chmod, mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import test from "node:test";

import { FakePiHost } from "./fake-pi-host.ts";

const TEST_TIMEOUT_MS = 15_000;

function captureStructuredErrors(): { lines: string[]; restore: () => void } {
  const lines: string[] = [];
  const original = console.error;
  console.error = (...values: unknown[]) => lines.push(values.map(String).join(" "));
  return { lines, restore: () => (console.error = original) };
}

async function waitForExit(exited: Promise<void>, timeoutMS: number): Promise<boolean> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), timeoutMS);
    exited.then(() => {
      clearTimeout(timer);
      resolve(true);
    });
  });
}

async function terminateAndReap(
  child: ChildProcessWithoutNullStreams,
  diagnostics: () => string = () => "no captured process output",
): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  const termSent = child.kill("SIGTERM");
  if (await waitForExit(exited, 3_000)) return;

  const killSent = child.kill("SIGKILL");
  if (await waitForExit(exited, 3_000)) return;

  child.stdout.destroy();
  child.stderr.destroy();
  child.unref();
  throw new Error(
    `relay child did not exit after bounded SIGTERM and SIGKILL waits: pid=${child.pid ?? "unknown"} ` +
      `term_sent=${termSent} kill_sent=${killSent} exit_code=${child.exitCode ?? "null"} ` +
      `signal_code=${child.signalCode ?? "null"}; ${diagnostics()}`,
  );
}

async function nextEvent(
  iterator: AsyncIterator<string>,
  stdoutLines: string[],
): Promise<Record<string, unknown>> {
  const result = await new Promise<IteratorResult<string>>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("timed out waiting for relay process event")),
      TEST_TIMEOUT_MS,
    );
    iterator.next().then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
  if (result.done) throw new Error("relay stdout closed before expected event");
  stdoutLines.push(result.value);
  return JSON.parse(result.value) as Record<string, unknown>;
}

function encodedPublicKey(privatePEM: string): string {
  const privateKey = createPrivateKey(privatePEM);
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  assert.equal(typeof jwk.x, "string");
  return `ed25519:${Buffer.from(jwk.x as string, "base64url").toString("base64")}`;
}

test("real relay-pair command establishes one persisted installation identity", { timeout: 60_000 }, async (context) => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const testRoot = await mkdtemp(join(tmpdir(), "pi-relay-pairing-"));
  context.after(async () => rm(testRoot, { recursive: true, force: true }));
  await chmod(testRoot, 0o700);
  const binary = join(testRoot, "pi-messaging-relay-server");
  const serverState = join(testRoot, "server-state");
  const extensionState = join(testRoot, "extension-state");
  const codeFile = join(testRoot, "operator-pairing-code");

  execFileSync("go", ["build", "-o", binary, "./cmd/pi-messaging-relay-server"], {
    cwd: repositoryRoot,
    stdio: "pipe",
  });
  const child = spawn(
    binary,
    ["--listen", "127.0.0.1:0", "--state-dir", serverState, "--pairing-code-file", codeFile],
    { cwd: repositoryRoot, stdio: ["ignore", "pipe", "pipe"] },
  );
  const stderrChunks: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderrChunks.push(chunk));
  const stdout = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const iterator = stdout[Symbol.asyncIterator]();
  const stdoutLines: string[] = [];
  const childDiagnostics = () => {
    const stdoutTail = stdoutLines.join("\n").slice(-2_048);
    const stderrTail = Buffer.concat(stderrChunks).toString("utf8").slice(-2_048);
    return `stdout_tail=${JSON.stringify(stdoutTail)} stderr_tail=${JSON.stringify(stderrTail)}`;
  };
  context.after(async () => terminateAndReap(child, childDiagnostics));

  const previousURL = process.env.PI_MESSAGING_RELAY_URL;
  const previousState = process.env.PI_MESSAGING_RELAY_STATE_DIR;
  let extensionLogs: string[] = [];
  let rawCode = "";
  let privatePEM = "";
  try {
    const ready = await nextEvent(iterator, stdoutLines);
    assert.equal(ready.event, "server_ready");
    assert.match(String(ready.address), /^127\.0\.0\.1:\d+$/);
    assert.equal(ready.state_dir, serverState);

    const created = await nextEvent(iterator, stdoutLines);
    assert.deepEqual(
      { event: created.event, pairing_code: created.pairing_code, private_key: created.private_key },
      { event: "pairing_code_created", pairing_code: "<redacted>", private_key: "<redacted>" },
    );
    rawCode = (await readFile(codeFile, "utf8")).trim();
    assert.match(rawCode, /^[A-Za-z0-9_-]{32}$/);
    assert.equal((await stat(codeFile)).mode & 0o777, 0o600);

    process.env.PI_MESSAGING_RELAY_URL = `http://${String(ready.address)}`;
    process.env.PI_MESSAGING_RELAY_STATE_DIR = extensionState;
    const host = new FakePiHost();
    const extensionLogsCapture = captureStructuredErrors();
    try {
      const relayExtension = (await import(`../index.ts?acceptance=${Date.now()}`)).default;
      relayExtension(host.api as never);
      await host.executeCommand("relay-pair", rawCode);
    } finally {
      extensionLogsCapture.restore();
      extensionLogs = extensionLogsCapture.lines;
    }

    assert.deepEqual(host.registrations, [
      { kind: "command", name: "relay-pair" },
      { kind: "tool", name: "list_peers" },
      { kind: "tool", name: "agent_send" },
    ]);
    assert.equal(host.notifications.length, 1);
    assert.equal(host.notifications[0].level, "success");
    assert.match(host.notifications[0].message, /^Relay pairing accepted client identity cli_[A-Za-z0-9_-]{16}\.$/);
    assert.equal(host.notifications[0].message.includes(rawCode), false);
    const clientID = host.notifications[0].message.slice(
      "Relay pairing accepted client identity ".length,
      -1,
    );
    assert.deepEqual(host.sendMessageAttempts, []);
    assert.deepEqual(host.sendUserMessageAttempts, []);
    assert.deepEqual(host.liveAccessAttempts, []);

    const pairAccepted = await nextEvent(iterator, stdoutLines);
    assert.deepEqual(
      {
        event: pairAccepted.event,
        result: pairAccepted.result,
        pairing_code: pairAccepted.pairing_code,
        private_key: pairAccepted.private_key,
        client_id: pairAccepted.client_id,
      },
      {
        event: "pair_accepted",
        result: "accepted",
        pairing_code: "<redacted>",
        private_key: "<redacted>",
        client_id: clientID,
      },
    );

    const keyFiles = await readdir(extensionState);
    assert.deepEqual(keyFiles, ["installation-ed25519.pem"]);
    const keyPath = join(extensionState, keyFiles[0]);
    privatePEM = await readFile(keyPath, "utf8");
    assert.equal(host.notifications[0].message.includes(privatePEM.trim()), false);
    assert.equal((await stat(extensionState)).mode & 0o777, 0o700);
    assert.equal((await stat(keyPath)).mode & 0o777, 0o600);
    const publicKey = encodedPublicKey(privatePEM);
    assert.equal(pairAccepted.client_public_key, publicKey);

    const persistedFiles = await readdir(serverState);
    assert.deepEqual(persistedFiles, ["allowlist.json"]);
    const allowlistPath = join(serverState, persistedFiles[0]);
    const persistedText = await readFile(allowlistPath, "utf8");
    assert.equal((await stat(serverState)).mode & 0o777, 0o700);
    assert.equal((await stat(allowlistPath)).mode & 0o777, 0o600);
    const persisted = JSON.parse(persistedText) as {
      clients?: Array<{ client_id?: unknown; client_public_key?: unknown; paired_at?: unknown }>;
    };
    assert.equal(persisted.clients?.length, 1);
    assert.deepEqual(
      {
        client_id: persisted.clients?.[0]?.client_id,
        client_public_key: persisted.clients?.[0]?.client_public_key,
      },
      { client_id: clientID, client_public_key: publicKey },
    );
    assert.equal(Number.isNaN(Date.parse(String(persisted.clients?.[0]?.paired_at))), false);
    assert.equal(persistedText.includes(rawCode), false);
    assert.equal(persistedText.includes("PRIVATE KEY"), false);
    assert.equal(persistedText.includes("message"), false);
    await assert.rejects(stat(codeFile), { code: "ENOENT" });

    const allLogs = [...stdoutLines, ...extensionLogs, Buffer.concat(stderrChunks).toString("utf8")].join("\n");
    assert.equal(allLogs.includes(rawCode), false);
    assert.equal(allLogs.includes(privatePEM.trim()), false);
    for (const line of [...stdoutLines, ...extensionLogs]) {
      const event = JSON.parse(line) as Record<string, unknown>;
      if ("pairing_code" in event) assert.equal(event.pairing_code, "<redacted>");
      if ("private_key" in event) assert.equal(event.private_key, "<redacted>");
    }
  } finally {
    if (previousURL === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = previousURL;
    if (previousState === undefined) delete process.env.PI_MESSAGING_RELAY_STATE_DIR;
    else process.env.PI_MESSAGING_RELAY_STATE_DIR = previousState;
    try {
      await terminateAndReap(child, childDiagnostics);
    } finally {
      stdout.close();
      await rm(testRoot, { recursive: true, force: true });
    }
  }
});
