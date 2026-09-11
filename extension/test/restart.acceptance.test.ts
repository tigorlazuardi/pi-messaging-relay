import assert from "node:assert/strict";
import { spawn, execFileSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import test from "node:test";

import {
  installReconnectDependenciesForTest,
  type ReconnectDeadline,
} from "../internal/reconnect.ts";
import { FakePiHost } from "./fake-pi-host.ts";

const TEST_TIMEOUT_MS = 15_000;
const SECRET_BODY = "restart-secret-body-must-never-reach-disk";

type ProcessOutput = {
  iterator: AsyncIterator<string>;
  lines: string[];
};

type RelayProcess = {
  child: ChildProcessWithoutNullStreams;
  output: ProcessOutput;
  stderr: Buffer[];
  closeOutput(): void;
};

type RosterPage = { details: { peers: Array<{ address: string }> } };

type DurableAllowlist = {
  version: number;
  clients: Array<{
    client_id: string;
    client_public_key: string;
    paired_at: string;
  }>;
};

class RestartClock {
  nowMS = 1_800_000_000_000;
  readonly scheduledDelays: number[] = [];
  private nextID = 0;
  private readonly tasks = new Map<number, { at: number; callback(): void }>();

  readonly dependencies = {
    now: () => this.nowMS,
    randomUnit: () => 0.5,
    schedule: (callback: () => void, delayMS: number): ReconnectDeadline => {
      this.scheduledDelays.push(delayMS);
      const id = this.nextID++;
      this.tasks.set(id, { at: this.nowMS + delayMS, callback });
      return { cancel: () => { this.tasks.delete(id); } };
    },
  };

  get pendingCount(): number {
    return this.tasks.size;
  }

  async advanceBy(durationMS: number): Promise<void> {
    const target = this.nowMS + durationMS;
    while (true) {
      const next = [...this.tasks.entries()]
        .filter(([, task]) => task.at <= target)
        .sort((left, right) => left[1].at - right[1].at || left[0] - right[0])[0];
      if (!next) break;
      const [id, task] = next;
      this.tasks.delete(id);
      this.nowMS = task.at;
      task.callback();
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    this.nowMS = target;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}

async function within<T>(promise: Promise<T>, action: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`timed out ${action}`)), TEST_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function waitUntil(predicate: () => boolean, action: string): Promise<void> {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started >= TEST_TIMEOUT_MS) throw new Error(`timed out ${action}`);
    await new Promise<void>((resolve) => setTimeout(resolve, 1));
  }
}

async function nextEvent(
  output: ProcessOutput,
  name: string,
  matches: (event: Record<string, unknown>) => boolean = () => true,
): Promise<Record<string, unknown>> {
  while (true) {
    const next = await within(output.iterator.next(), `waiting for ${name}`);
    if (next.done) throw new Error(`relay output ended before ${name}`);
    output.lines.push(next.value);
    const event = JSON.parse(next.value) as Record<string, unknown>;
    if (event.event === name && matches(event)) return event;
  }
}

async function startRelay(
  binary: string,
  repositoryRoot: string,
  stateDirectory: string,
  codeFile: string | undefined,
  listen: string,
): Promise<{ relay: RelayProcess; ready: Record<string, unknown> }> {
  const args = ["--listen", listen, "--state-dir", stateDirectory];
  if (codeFile !== undefined) args.push("--pairing-code-file", codeFile);
  const child = spawn(binary, args, { cwd: repositoryRoot, stdio: ["ignore", "pipe", "pipe"] });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const relay: RelayProcess = {
    child: child as ChildProcessWithoutNullStreams,
    output: { iterator: lines[Symbol.asyncIterator](), lines: [] },
    stderr,
    closeOutput: () => lines.close(),
  };
  const ready = await nextEvent(relay.output, "server_ready");
  await nextEvent(relay.output, "pairing_code_created");
  return { relay, ready };
}

async function stopRelay(relay: RelayProcess): Promise<void> {
  if (relay.child.exitCode !== null || relay.child.signalCode !== null) return;
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    relay.child.once("exit", (code, signal) => resolve({ code, signal }));
  });
  assert.equal(relay.child.kill("SIGTERM"), true);
  const stopped = await nextEvent(relay.output, "server_stopped");
  assert.equal(stopped.result, "graceful");
  const result = await within(exited, "waiting for graceful relay exit");
  assert.deepEqual(result, { code: 0, signal: null });
}

async function killRelay(relay: RelayProcess): Promise<void> {
  if (relay.child.exitCode !== null || relay.child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => relay.child.once("exit", () => resolve()));
  relay.child.kill("SIGKILL");
  await within(exited, "killing relay during cleanup");
}

async function reserveLoopbackAddress(): Promise<string> {
  const listener = createServer();
  await new Promise<void>((resolve, reject) => {
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", resolve);
  });
  const address = listener.address();
  assert.ok(address && typeof address === "object");
  await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
  return `127.0.0.1:${address.port}`;
}

async function writeInstallationKey(stateDirectory: string): Promise<string> {
  await mkdir(stateDirectory, { mode: 0o700 });
  await chmod(stateDirectory, 0o700);
  const privateKey = generateKeyPairSync("ed25519").privateKey;
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  await writeFile(join(stateDirectory, "installation-ed25519.pem"), pem, { mode: 0o600 });
  return pem;
}

function assertClosedAllowlist(text: string, forbiddenValues: string[]): DurableAllowlist {
  const parsed = JSON.parse(text) as DurableAllowlist;
  assert.deepEqual(Object.keys(parsed).sort(), ["clients", "version"]);
  assert.equal(parsed.version, 1);
  assert.equal(parsed.clients.length, 1);
  assert.deepEqual(Object.keys(parsed.clients[0]).sort(), [
    "client_id",
    "client_public_key",
    "paired_at",
  ]);
  assert.match(parsed.clients[0].client_id, /^cli_[A-Za-z0-9_-]{16}$/);
  assert.match(parsed.clients[0].client_public_key, /^ed25519:[A-Za-z0-9+/]{43}=$/);
  assert.match(parsed.clients[0].paired_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/);

  const forbiddenKeys = new Set([
    "body",
    "pending",
    "pending_sends",
    "dedupe",
    "offline_inbox",
    "inbox",
    "request_id",
    "message_id",
    "delivery_id",
    "route_id",
  ]);
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (value === null || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      assert.equal(forbiddenKeys.has(key), false, `durable allowlist contains forbidden key ${key}`);
      visit(child);
    }
  };
  visit(parsed);
  for (const value of forbiddenValues) assert.equal(text.includes(value), false);
  return parsed;
}

async function listedAddresses(host: FakePiHost): Promise<string[]> {
  const result = await host.executeTool("list_peers", {}) as RosterPage;
  return result.details.peers.map((peer) => peer.address);
}

test("durable allowlist restores real extension authorization across one child-process restart", {
  timeout: 60_000,
  concurrency: false,
}, async () => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const root = await mkdtemp(join(tmpdir(), "pi-relay-restart-"));
  await chmod(root, 0o700);
  const binary = join(root, "relay-server");
  const serverState = join(root, "server-state");
  const pairedExtensionState = join(root, "paired-extension-state");
  const unknownExtensionState = join(root, "unknown-extension-state");
  const codeFile = join(serverState, "pairing-code");
  execFileSync("go", ["build", "-o", binary, "./cmd/pi-messaging-relay-server"], {
    cwd: repositoryRoot,
    stdio: "pipe",
  });

  const listen = await reserveLoopbackAddress();
  const clock = new RestartClock();
  const restoreReconnect = installReconnectDependenciesForTest(clock.dependencies);
  const previousURL = process.env.PI_MESSAGING_RELAY_URL;
  const previousState = process.env.PI_MESSAGING_RELAY_STATE_DIR;
  const originalError = console.error;
  const extensionLogs: string[] = [];
  const hosts: FakePiHost[] = [];
  const relays: RelayProcess[] = [];
  let primaryError: unknown;

  try {
    console.error = (...values: unknown[]) => extensionLogs.push(values.map(String).join(" "));
    const first = await startRelay(binary, repositoryRoot, serverState, codeFile, listen);
    relays.push(first.relay);
    assert.equal(first.ready.address, listen);
    assert.equal(first.ready.state_dir, serverState);
    process.env.PI_MESSAGING_RELAY_URL = `http://${listen}`;
    process.env.PI_MESSAGING_RELAY_STATE_DIR = pairedExtensionState;

    const relayExtension = (await import(`../index.ts?restart=${Date.now()}`)).default;
    const subject = new FakePiHost();
    subject.cwd = "/srv/restart-subject";
    relayExtension(subject.api as never);
    hosts.push(subject);
    await subject.emit("session_start", { type: "session_start", reason: "startup" });
    const pairingCode = (await readFile(codeFile, "utf8")).trim();
    await subject.executeCommand("relay-pair", pairingCode);
    const acceptedPair = await nextEvent(first.relay.output, "pair_accepted");
    const initialAuth = await nextEvent(
      first.relay.output,
      "auth_accepted",
      (event) => event.cwd === subject.cwd,
    );
    assert.equal(acceptedPair.client_public_key, initialAuth.client_public_key);
    const originalAddress = String(initialAuth.address);
    const originalRouteID = String(initialAuth.route_id);

    const offlineResult = await subject.executeTool("agent_send", {
      to: "/offline@host#01993ca2-2222-7bbb-9bbb-222222222222",
      body: SECRET_BODY,
    }) as { details: { status: string; reason: string } };
    assert.deepEqual(
      { status: offlineResult.details.status, reason: offlineResult.details.reason },
      { status: "timeout", reason: "offline" },
    );

    assert.deepEqual(await readdir(serverState), ["allowlist.json"]);
    const allowlistPath = join(serverState, "allowlist.json");
    assert.equal((await stat(serverState)).mode & 0o777, 0o700);
    assert.equal((await stat(allowlistPath)).mode & 0o777, 0o600);
    const privatePEM = await readFile(join(pairedExtensionState, "installation-ed25519.pem"), "utf8");
    const beforeStop = await readFile(allowlistPath, "utf8");
    const storedBeforeStop = assertClosedAllowlist(beforeStop, [SECRET_BODY, privatePEM.trim(), pairingCode]);
    assert.equal(storedBeforeStop.clients[0].client_id, acceptedPair.client_id);
    assert.equal(storedBeforeStop.clients[0].client_public_key, acceptedPair.client_public_key);

    await stopRelay(first.relay);
    await waitUntil(() => clock.pendingCount === 1, "restart reconnect deadline");
    const afterStop = await readFile(allowlistPath, "utf8");
    assert.equal(afterStop, beforeStop);
    assertClosedAllowlist(afterStop, [SECRET_BODY, privatePEM.trim(), pairingCode]);

    const second = await startRelay(binary, repositoryRoot, serverState, undefined, listen);
    relays.push(second.relay);
    assert.equal(second.ready.address, listen);
    assert.equal(await readFile(allowlistPath, "utf8"), beforeStop);
    await clock.advanceBy(500);
    const restoredAuth = await nextEvent(
      second.relay.output,
      "auth_accepted",
      (event) => event.cwd === subject.cwd,
    );
    assert.equal(restoredAuth.client_id, acceptedPair.client_id);
    assert.equal(restoredAuth.client_public_key, acceptedPair.client_public_key);
    assert.equal(restoredAuth.route_id, originalRouteID);
    assert.equal(restoredAuth.address, originalAddress);

    process.env.PI_MESSAGING_RELAY_STATE_DIR = pairedExtensionState;
    const observer = new FakePiHost();
    observer.cwd = "/srv/restart-observer";
    relayExtension(observer.api as never);
    hosts.push(observer);
    await observer.emit("session_start", { type: "session_start", reason: "startup" });
    await nextEvent(second.relay.output, "auth_accepted", (event) => event.cwd === observer.cwd);
    assert.deepEqual(await listedAddresses(observer), [originalAddress]);

    const unknownPEM = await writeInstallationKey(unknownExtensionState);
    process.env.PI_MESSAGING_RELAY_STATE_DIR = unknownExtensionState;
    const unknown = new FakePiHost();
    unknown.cwd = "/srv/restart-unknown";
    relayExtension(unknown.api as never);
    hosts.push(unknown);
    await unknown.emit("session_start", { type: "session_start", reason: "startup" });
    const rejected = await nextEvent(
      second.relay.output,
      "auth_rejected",
      (event) => event.reason === "not_authorized",
    );
    assert.equal(rejected.reason, "not_authorized");
    await waitUntil(
      () => extensionLogs.some((line) => {
        const event = JSON.parse(line) as Record<string, unknown>;
        return event.event === "relay_auth_rejected" && event.reason === "not_authorized";
      }),
      "unknown extension rejection",
    );
    await assert.rejects(unknown.executeTool("list_peers", {}), /Relay is disconnected/);

    const afterRestart = await readFile(allowlistPath, "utf8");
    assert.equal(afterRestart, beforeStop);
    assertClosedAllowlist(afterRestart, [SECRET_BODY, privatePEM.trim(), unknownPEM.trim(), pairingCode]);
    assert.deepEqual(await readdir(serverState), ["allowlist.json"]);
    assert.equal(second.relay.stderr.length, 0);
    assert.equal(first.relay.stderr.length, 0);
  } catch (error: unknown) {
    primaryError = error;
    throw error;
  } finally {
    let cleanupError: unknown;
    for (const host of hosts) {
      try {
        await host.emit("session_shutdown");
      } catch (error: unknown) {
        cleanupError ??= error;
      }
    }
    for (const relay of relays) {
      try {
        await stopRelay(relay);
      } catch (error: unknown) {
        try {
          await killRelay(relay);
        } catch (killError: unknown) {
          cleanupError ??= killError;
        }
        cleanupError ??= error;
      } finally {
        relay.closeOutput();
      }
    }
    restoreReconnect();
    console.error = originalError;
    if (previousURL === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = previousURL;
    if (previousState === undefined) delete process.env.PI_MESSAGING_RELAY_STATE_DIR;
    else process.env.PI_MESSAGING_RELAY_STATE_DIR = previousState;
    try {
      await rm(root, { recursive: true, force: true });
    } catch (error: unknown) {
      cleanupError ??= error;
    }
    if (primaryError === undefined && cleanupError !== undefined) throw cleanupError;
  }
});
