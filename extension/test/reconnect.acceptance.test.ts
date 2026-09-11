import assert from "node:assert/strict";
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import test from "node:test";

import WebSocket, { WebSocketServer } from "ws";

import {
  installReconnectDependenciesForTest,
  type ReconnectDeadline,
} from "../internal/reconnect.ts";
import { FakePiHost } from "./fake-pi-host.ts";

const TEST_TIMEOUT_MS = 15_000;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

type Output = { iterator: AsyncIterator<string>; lines: string[] };
type HelloAttempt = { at: number; routeID: string; cwd: string; socket: WebSocket };
type ToolPage = { details: { peers: Array<{ address: string }> } };

class FakeReconnectClock {
  nowMS = 1_800_000_000_000;
  readonly scheduledDelays: number[] = [];
  private nextID = 0;
  private readonly tasks = new Map<number, { at: number; callback(): void }>();
  private readonly randomSamples: number[];

  readonly dependencies = {
    now: () => this.nowMS,
    randomUnit: () => this.randomSamples.shift() ?? 0.5,
    schedule: (callback: () => void, delayMS: number): ReconnectDeadline => {
      this.scheduledDelays.push(delayMS);
      const id = this.nextID++;
      this.tasks.set(id, { at: this.nowMS + delayMS, callback });
      return { cancel: () => { this.tasks.delete(id); } };
    },
  };

  constructor(randomSamples: number[]) {
    this.randomSamples = randomSamples;
  }

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

async function waitUntil(
  predicate: () => boolean,
  action: string,
  timeoutMS = TEST_TIMEOUT_MS,
): Promise<void> {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started >= timeoutMS) throw new Error(`timed out ${action}`);
    await new Promise<void>((resolve) => setTimeout(resolve, 1));
  }
}

async function nextEvent(
  output: Output,
  name: string,
  matches: (event: Record<string, unknown>) => boolean = () => true,
): Promise<Record<string, unknown>> {
  while (true) {
    const next = await within(output.iterator.next(), `waiting for ${name}`);
    if (next.done) throw new Error(`server output ended before ${name}`);
    output.lines.push(next.value);
    const event = JSON.parse(next.value) as Record<string, unknown>;
    if (event.event === name && matches(event)) return event;
  }
}

async function stop(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  child.kill("SIGTERM");
  try {
    await within(exited, "stopping relay");
  } catch {
    child.kill("SIGKILL");
    await within(exited, "killing relay");
  }
}

function installSubjectSocketControl(
  subjectCWD: string,
  now: () => number,
): { attempts: HelloAttempt[]; holdNextAttempt(): void; restore(): void } {
  type SendMethod = (data: unknown, ...rest: unknown[]) => unknown;
  const prototype = WebSocket.prototype as unknown as { send: SendMethod };
  const originalSend = prototype.send;
  const attempts: HelloAttempt[] = [];
  let holdNext = false;

  prototype.send = function controlledSend(this: WebSocket, data: unknown, ...rest: unknown[]): unknown {
    if (typeof data === "string") {
      try {
        const frame = JSON.parse(data) as Record<string, unknown>;
        const payload = frame.payload as Record<string, unknown> | undefined;
        if (frame.type === "hello" && payload?.cwd === subjectCWD) {
          attempts.push({
            at: now(),
            routeID: String(payload.route_id),
            cwd: String(payload.cwd),
            socket: this,
          });
          if (attempts.length === 2 || attempts.length === 3) {
            this.terminate();
            return undefined;
          }
          if (holdNext) {
            holdNext = false;
            return undefined;
          }
        }
      } catch {
        // Non-JSON writes remain owned by the real WebSocket implementation.
      }
    }
    return Reflect.apply(originalSend, this, [data, ...rest]);
  };

  return {
    attempts,
    holdNextAttempt: () => { holdNext = true; },
    restore: () => { prototype.send = originalSend; },
  };
}

async function listedAddresses(host: FakePiHost): Promise<string[]> {
  const result = await host.executeTool("list_peers", {}) as ToolPage;
  return result.details.peers.map((peer) => peer.address);
}

async function startControllableAuthEndpoint(
  rejectAttempt: (attempt: number) => boolean,
): Promise<{
  origin: string;
  hellos: Array<Record<string, unknown>>;
  close(): Promise<void>;
}> {
  const listener = new WebSocketServer({ host: "127.0.0.1", port: 0, perMessageDeflate: false });
  const sockets = new Set<WebSocket>();
  const hellos: Array<Record<string, unknown>> = [];
  listener.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    socket.send(JSON.stringify({
      v: 1,
      type: "challenge",
      payload: { nonce: "A".repeat(43) },
    }));
    socket.once("message", (data) => {
      const hello = JSON.parse(data.toString("utf8")) as Record<string, unknown>;
      hellos.push(hello);
      if (rejectAttempt(hellos.length)) {
        socket.terminate();
        return;
      }
      const payload = hello.payload as Record<string, unknown>;
      socket.send(JSON.stringify({
        v: 1,
        type: "welcome",
        request_id: hello.request_id,
        payload: {
          self_address: `${String(payload.cwd)}@${String(payload.hostname)}#${String(payload.route_id)}`,
          heartbeat_ms: 30_000,
          max_body_bytes: 262_144,
        },
      }));
    });
  });
  await new Promise<void>((resolve, reject) => {
    listener.once("listening", resolve);
    listener.once("error", reject);
  });
  const address = listener.address();
  assert.ok(address && typeof address === "object");
  return {
    origin: `http://127.0.0.1:${address.port}`,
    hellos,
    close: async () => {
      for (const socket of sockets) socket.terminate();
      await new Promise<void>((resolve) => listener.close(() => resolve()));
    },
  };
}

async function writeInstallationKey(stateDirectory: string): Promise<void> {
  await mkdir(stateDirectory, { mode: 0o700 });
  await chmod(stateDirectory, 0o700);
  const privateKey = generateKeyPairSync("ed25519").privateKey;
  await writeFile(
    join(stateDirectory, "installation-ed25519.pem"),
    privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    { mode: 0o600 },
  );
}

test("inline reconnect deadline preserves one failed-authentication retry intent", { concurrency: false }, async (context) => {
  const root = await mkdtemp(join(tmpdir(), "pi-relay-inline-reconnect-"));
  const stateDirectory = join(root, "state");
  const endpoint = await startControllableAuthEndpoint((attempt) => attempt === 1);
  const previousURL = process.env.PI_MESSAGING_RELAY_URL;
  const previousState = process.env.PI_MESSAGING_RELAY_STATE_DIR;
  const originalError = console.error;
  const logs: string[] = [];
  let scheduleCalls = 0;
  const restoreDependencies = installReconnectDependenciesForTest({
    now: () => 1_800_000_000_000,
    randomUnit: () => 0.5,
    schedule: (callback) => {
      scheduleCalls += 1;
      callback();
      return { cancel: () => undefined };
    },
  });
  const host = new FakePiHost();
  context.after(async () => rm(root, { recursive: true, force: true }));

  try {
    await writeInstallationKey(stateDirectory);
    process.env.PI_MESSAGING_RELAY_URL = endpoint.origin;
    process.env.PI_MESSAGING_RELAY_STATE_DIR = stateDirectory;
    console.error = (...values: unknown[]) => logs.push(values.map(String).join(" "));
    const relayExtension = (await import(`../index.ts?inline-reconnect=${Date.now()}`)).default;
    relayExtension(host.api as never);

    await host.emit("session_start", { type: "session_start", reason: "startup" });
    await waitUntil(() => endpoint.hellos.length === 2, "inline successor attempt", 1_000);
    await waitUntil(
      () => logs.some((line) => JSON.parse(line).event === "relay_auth_accepted"),
      "inline successor authentication",
      1_000,
    );
    assert.equal(scheduleCalls, 1);
    assert.equal(endpoint.hellos.length, 2);
    assert.equal(
      new Set(endpoint.hellos.map((hello) =>
        String((hello.payload as Record<string, unknown>).route_id))).size,
      1,
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(endpoint.hellos.length, 2, "inline retry intent launched a duplicate attempt");
  } finally {
    await host.emit("session_shutdown");
    restoreDependencies();
    console.error = originalError;
    if (previousURL === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = previousURL;
    if (previousState === undefined) delete process.env.PI_MESSAGING_RELAY_STATE_DIR;
    else process.env.PI_MESSAGING_RELAY_STATE_DIR = previousState;
    await endpoint.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("inline reconnect intent is discarded when session shutdown invalidates its generation", { concurrency: false }, async (context) => {
  const root = await mkdtemp(join(tmpdir(), "pi-relay-inline-cancel-"));
  const stateDirectory = join(root, "state");
  const endpoint = await startControllableAuthEndpoint(() => true);
  const previousURL = process.env.PI_MESSAGING_RELAY_URL;
  const previousState = process.env.PI_MESSAGING_RELAY_STATE_DIR;
  const originalError = console.error;
  let scheduleCalls = 0;
  let shutdown: Promise<void> | undefined;
  const host = new FakePiHost();
  const restoreDependencies = installReconnectDependenciesForTest({
    now: () => 1_800_000_000_000,
    randomUnit: () => 0.5,
    schedule: (callback) => {
      scheduleCalls += 1;
      callback();
      shutdown = host.emit("session_shutdown");
      return { cancel: () => undefined };
    },
  });
  context.after(async () => rm(root, { recursive: true, force: true }));

  try {
    await writeInstallationKey(stateDirectory);
    process.env.PI_MESSAGING_RELAY_URL = endpoint.origin;
    process.env.PI_MESSAGING_RELAY_STATE_DIR = stateDirectory;
    console.error = () => undefined;
    const relayExtension = (await import(`../index.ts?inline-cancel=${Date.now()}`)).default;
    relayExtension(host.api as never);

    await host.emit("session_start", { type: "session_start", reason: "startup" });
    assert.ok(shutdown);
    await shutdown;
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(scheduleCalls, 1);
    assert.equal(endpoint.hellos.length, 1);
  } finally {
    await host.emit("session_shutdown");
    restoreDependencies();
    console.error = originalError;
    if (previousURL === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = previousURL;
    if (previousState === undefined) delete process.env.PI_MESSAGING_RELAY_STATE_DIR;
    else process.env.PI_MESSAGING_RELAY_STATE_DIR = previousState;
    await endpoint.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("inline reconnect deadlines consume exactly the finite retry budget", { concurrency: false }, async (context) => {
  const root = await mkdtemp(join(tmpdir(), "pi-relay-inline-bound-"));
  const stateDirectory = join(root, "state");
  const endpoint = await startControllableAuthEndpoint(() => true);
  const previousURL = process.env.PI_MESSAGING_RELAY_URL;
  const previousState = process.env.PI_MESSAGING_RELAY_STATE_DIR;
  const originalError = console.error;
  let scheduleCalls = 0;
  const restoreDependencies = installReconnectDependenciesForTest({
    now: () => 1_800_000_000_000,
    randomUnit: () => 0.5,
    schedule: (callback) => {
      scheduleCalls += 1;
      callback();
      return { cancel: () => undefined };
    },
  });
  const host = new FakePiHost();
  context.after(async () => rm(root, { recursive: true, force: true }));

  try {
    await writeInstallationKey(stateDirectory);
    process.env.PI_MESSAGING_RELAY_URL = endpoint.origin;
    process.env.PI_MESSAGING_RELAY_STATE_DIR = stateDirectory;
    console.error = () => undefined;
    const relayExtension = (await import(`../index.ts?inline-bound=${Date.now()}`)).default;
    relayExtension(host.api as never);

    await host.emit("session_start", { type: "session_start", reason: "startup" });
    await waitUntil(() => endpoint.hellos.length === 11, "finite inline retry sequence", 2_000);
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
    assert.equal(scheduleCalls, 10);
    assert.equal(endpoint.hellos.length, 11, "retry sequence exceeded its ten-retry budget");
  } finally {
    await host.emit("session_shutdown");
    restoreDependencies();
    console.error = originalError;
    if (previousURL === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = previousURL;
    if (previousState === undefined) delete process.env.PI_MESSAGING_RELAY_STATE_DIR;
    else process.env.PI_MESSAGING_RELAY_STATE_DIR = previousState;
    await endpoint.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("fake-clock extension lifecycle restores exact live route with capped jittered retries", { timeout: 60_000, concurrency: false }, async () => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const root = await mkdtemp(join(tmpdir(), "pi-relay-reconnect-"));
  await chmod(root, 0o700);
  const binary = join(root, "relay-server");
  const serverState = join(root, "server-state");
  const extensionState = join(root, "extension-state");
  const codeFile = join(serverState, "pairing-code");
  execFileSync("go", ["build", "-o", binary, "./cmd/pi-messaging-relay-server"], {
    cwd: repositoryRoot,
    stdio: "pipe",
  });

  const child = spawn(binary, [
    "--listen", "127.0.0.1:0",
    "--state-dir", serverState,
    "--pairing-code-file", codeFile,
  ], { cwd: repositoryRoot, stdio: ["ignore", "pipe", "pipe"] });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const output: Output = { iterator: lines[Symbol.asyncIterator](), lines: [] };
  const previousURL = process.env.PI_MESSAGING_RELAY_URL;
  const previousState = process.env.PI_MESSAGING_RELAY_STATE_DIR;
  const originalError = console.error;
  const extensionLogs: string[] = [];
  const clock = new FakeReconnectClock([0, 0.5, 0.75, 0.5]);
  const restoreDependencies = installReconnectDependenciesForTest(clock.dependencies);
  const subjectCWD = "/srv/reconnect-subject";
  const socketControl = installSubjectSocketControl(subjectCWD, () => clock.nowMS);
  const hosts: FakePiHost[] = [];
  let primaryError: unknown;

  try {
    const ready = await nextEvent(output, "server_ready");
    await nextEvent(output, "pairing_code_created");
    process.env.PI_MESSAGING_RELAY_URL = `http://${String(ready.address)}`;
    process.env.PI_MESSAGING_RELAY_STATE_DIR = extensionState;
    console.error = (...values: unknown[]) => extensionLogs.push(values.map(String).join(" "));
    const pairingCode = (await readFile(codeFile, "utf8")).trim();
    const relayExtension = (await import(`../index.ts?reconnect=${Date.now()}`)).default;

    const subject = new FakePiHost();
    subject.cwd = subjectCWD;
    relayExtension(subject.api as never);
    hosts.push(subject);
    await subject.emit("session_start", { type: "session_start", reason: "startup" });
    await subject.executeCommand("relay-pair", pairingCode);
    await nextEvent(output, "pair_accepted");
    const initialAuth = await nextEvent(output, "auth_accepted", (event) => event.cwd === subjectCWD);
    const originalRouteID = String(initialAuth.route_id);
    const originalAddress = String(initialAuth.address);
    assert.match(originalRouteID, UUID_V7);
    assert.equal(originalAddress.endsWith(`#${originalRouteID}`), true);
    assert.equal(socketControl.attempts.length, 1);

    const observer = new FakePiHost();
    observer.cwd = "/srv/reconnect-observer";
    relayExtension(observer.api as never);
    hosts.push(observer);
    await observer.emit("session_start", { type: "session_start", reason: "startup" });
    await nextEvent(output, "auth_accepted", (event) => event.cwd === observer.cwd);
    assert.deepEqual(await listedAddresses(observer), [originalAddress]);

    socketControl.attempts[0].socket.terminate();
    await nextEvent(output, "session_disconnected", (event) => event.address === originalAddress);
    await waitUntil(() => clock.scheduledDelays.length === 1, "first reconnect schedule");
    assert.deepEqual(clock.scheduledDelays, [375]);
    assert.deepEqual(await listedAddresses(observer), []);

    await clock.advanceBy(374);
    assert.equal(socketControl.attempts.length, 1);
    assert.deepEqual(await listedAddresses(observer), []);
    await clock.advanceBy(1);
    await waitUntil(() => socketControl.attempts.length === 2, "first reconnect attempt");
    await waitUntil(() => clock.scheduledDelays.length === 2, "second reconnect schedule");
    assert.deepEqual(clock.scheduledDelays, [375, 1_000]);
    assert.deepEqual(await listedAddresses(observer), []);

    await clock.advanceBy(999);
    assert.equal(socketControl.attempts.length, 2);
    await clock.advanceBy(1);
    await waitUntil(() => socketControl.attempts.length === 3, "second reconnect attempt");
    await waitUntil(() => clock.scheduledDelays.length === 3, "third reconnect schedule");
    assert.deepEqual(clock.scheduledDelays, [375, 1_000, 2_250]);
    assert.deepEqual(await listedAddresses(observer), []);

    await clock.advanceBy(2_249);
    assert.equal(socketControl.attempts.length, 3);
    await clock.advanceBy(1);
    await waitUntil(() => socketControl.attempts.length === 4, "successful reconnect attempt");
    const restoredAuth = await nextEvent(output, "auth_accepted", (event) => event.cwd === subjectCWD);
    assert.equal(restoredAuth.route_id, originalRouteID);
    assert.equal(restoredAuth.address, originalAddress);
    assert.deepEqual(
      socketControl.attempts.slice(0, 4).map((attempt) => ({ at: attempt.at, routeID: attempt.routeID })),
      [
        { at: 1_800_000_000_000, routeID: originalRouteID },
        { at: 1_800_000_000_375, routeID: originalRouteID },
        { at: 1_800_000_001_375, routeID: originalRouteID },
        { at: 1_800_000_003_625, routeID: originalRouteID },
      ],
    );
    assert.deepEqual(await listedAddresses(observer), [originalAddress]);

    await subject.emit("session_start", { type: "session_start", reason: "reload" });
    const reloadAuth = await nextEvent(output, "auth_accepted", (event) => event.cwd === subjectCWD);
    assert.equal(reloadAuth.route_id, originalRouteID);
    assert.equal(reloadAuth.address, originalAddress);

    await subject.emit("session_start", { type: "session_start", reason: "new" });
    const newAuth = await nextEvent(output, "auth_accepted", (event) => event.cwd === subjectCWD);
    assert.match(String(newAuth.route_id), UUID_V7);
    assert.notEqual(newAuth.route_id, originalRouteID);
    assert.notEqual(newAuth.address, originalAddress);

    await subject.emit("session_start", { type: "session_start", reason: "fork" });
    const forkAuth = await nextEvent(output, "auth_accepted", (event) => event.cwd === subjectCWD);
    assert.match(String(forkAuth.route_id), UUID_V7);
    assert.notEqual(forkAuth.route_id, newAuth.route_id);
    assert.notEqual(forkAuth.address, newAuth.address);
    assert.deepEqual(await listedAddresses(observer), [String(forkAuth.address)]);

    const finalSocket = socketControl.attempts.at(-1)?.socket;
    assert.ok(finalSocket);
    finalSocket.terminate();
    await nextEvent(output, "session_disconnected", (event) => event.address === forkAuth.address);
    await waitUntil(() => clock.pendingCount === 1, "shutdown reconnect schedule");
    const attemptCountAtShutdown = socketControl.attempts.length;
    await subject.emit("session_shutdown");
    assert.equal(clock.pendingCount, 0);
    await clock.advanceBy(120_000);
    assert.equal(socketControl.attempts.length, attemptCountAtShutdown);
    assert.deepEqual(await listedAddresses(observer), []);

    await subject.emit("session_start", { type: "session_start", reason: "resume" });
    const resumedAuth = await nextEvent(output, "auth_accepted", (event) => event.cwd === subjectCWD);
    assert.equal(resumedAuth.route_id, forkAuth.route_id);
    assert.equal(resumedAuth.address, forkAuth.address);
    const resumedSocket = socketControl.attempts.at(-1)?.socket;
    assert.ok(resumedSocket);
    resumedSocket.terminate();
    await nextEvent(output, "session_disconnected", (event) => event.address === forkAuth.address);
    await waitUntil(() => clock.pendingCount === 1, "in-flight shutdown reconnect schedule");
    const attemptCountBeforeJoin = socketControl.attempts.length;
    socketControl.holdNextAttempt();
    await clock.advanceBy(clock.scheduledDelays.at(-1) as number);
    await waitUntil(
      () => socketControl.attempts.length === attemptCountBeforeJoin + 1,
      "held reconnect attempt",
    );
    const heldSocket = socketControl.attempts.at(-1)?.socket;
    assert.ok(heldSocket);
    await subject.emit("session_shutdown");
    assert.equal(heldSocket.readyState, heldSocket.CLOSED);
    assert.equal(clock.pendingCount, 0);
    const joinedAttemptCount = socketControl.attempts.length;
    await clock.advanceBy(120_000);
    assert.equal(socketControl.attempts.length, joinedAttemptCount);

    const routeEntries = subject.appendEntryAttempts.filter((entry) =>
      entry.customType === "pi-messaging-relay-route-v1");
    assert.equal(routeEntries.length, 3, "startup, new, and fork each publish one route entry");
    assert.equal(stderr.length, 0);
    const eventNames = new Set(extensionLogs.map((line) => String(JSON.parse(line).event)));
    assert.deepEqual(
      [...eventNames].sort(),
      ["relay_auth_accepted", "relay_auth_rejected", "relay_pair_accepted", "relay_session_disconnected"],
    );
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
    socketControl.restore();
    restoreDependencies();
    console.error = originalError;
    if (previousURL === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = previousURL;
    if (previousState === undefined) delete process.env.PI_MESSAGING_RELAY_STATE_DIR;
    else process.env.PI_MESSAGING_RELAY_STATE_DIR = previousState;
    try {
      await stop(child);
    } catch (error: unknown) {
      cleanupError ??= error;
    }
    lines.close();
    try {
      await rm(root, { recursive: true, force: true });
    } catch (error: unknown) {
      cleanupError ??= error;
    }
    if (primaryError === undefined && cleanupError !== undefined) throw cleanupError;
  }
});
