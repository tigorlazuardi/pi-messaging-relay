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
type HelloAttempt = {
  at: number;
  routeID: string;
  cwd: string;
  socket: WebSocket;
};
type AuthenticationFixture = {
  nonce: string;
  signature: string;
  routeID: string;
  cwd: string;
};
type ToolPage = { details: { peers: Array<{ address: string }> } };
type ToolSendResult = { details: { message_id: string; status: string; reason?: string } };

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

async function drainOutput(output: Output): Promise<void> {
  while (true) {
    const next = await within(output.iterator.next(), "draining server stdout to EOF");
    if (next.done) break;
    output.lines.push(next.value);
  }
  const afterEOF = await within(output.iterator.next(), "confirming server stdout EOF");
  assert.equal(afterEOF.done, true);
}

function capturePhysicalStderr(): {
  chunks: Buffer[];
  restore(): void;
  lines(): string[];
} {
  type WriteCallback = (error?: Error | null) => void;
  type StderrWrite = typeof process.stderr.write;
  const stderr = process.stderr as NodeJS.WriteStream & { write: StderrWrite };
  const originalWrite = stderr.write;
  const chunks: Buffer[] = [];
  let restored = false;

  stderr.write = ((
    chunk: string | Uint8Array,
    encodingOrCallback?: BufferEncoding | WriteCallback,
    callback?: WriteCallback,
  ): boolean => {
    const encoding = typeof encodingOrCallback === "string" ? encodingOrCallback : "utf8";
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk, encoding) : Buffer.from(chunk));
    const settled = typeof encodingOrCallback === "function" ? encodingOrCallback : callback;
    if (settled) queueMicrotask(() => settled(null));
    return true;
  }) as StderrWrite;

  return {
    chunks,
    restore: () => {
      if (restored) return;
      stderr.write = originalWrite;
      restored = true;
    },
    lines: () => {
      const data = Buffer.concat(chunks);
      const result: string[] = [];
      let start = 0;
      for (let index = 0; index < data.length; index += 1) {
        if (data[index] !== 0x0a) continue;
        let end = index;
        if (end > start && data[end - 1] === 0x0d) end -= 1;
        result.push(new TextDecoder("utf-8", { fatal: true }).decode(data.subarray(start, end)));
        start = index + 1;
      }
      assert.equal(start, data.length, "extension stderr ended with an unterminated physical line");
      return result;
    },
  };
}

function installSubjectSocketControl(
  subjectCWD: string,
  now: () => number,
): {
  attempts: HelloAttempt[];
  authenticationFixtures: AuthenticationFixture[];
  challengeNonces: string[];
  holdNextAttempt(): void;
  restore(): void;
} {
  type SendMethod = (data: unknown, ...rest: unknown[]) => unknown;
  type EmitMethod = (event: string | symbol, ...args: unknown[]) => boolean;
  const prototype = WebSocket.prototype as unknown as { send: SendMethod; emit: EmitMethod };
  const originalSend = prototype.send;
  const originalEmit = prototype.emit;
  const attempts: HelloAttempt[] = [];
  const authenticationFixtures: AuthenticationFixture[] = [];
  const challengeNonces: string[] = [];
  const challengeBySocket = new Map<WebSocket, string>();
  let holdNext = false;

  prototype.emit = function controlledEmit(
    this: WebSocket,
    event: string | symbol,
    ...args: unknown[]
  ): boolean {
    if (event === "message" && Buffer.isBuffer(args[0])) {
      try {
        const frame = JSON.parse(args[0].toString("utf8")) as Record<string, unknown>;
        const payload = frame.payload as Record<string, unknown> | undefined;
        if (frame.type === "challenge" && typeof payload?.nonce === "string") {
          challengeNonces.push(payload.nonce);
          challengeBySocket.set(this, payload.nonce);
        }
      } catch {
        // Non-JSON transport events remain owned by the real WebSocket implementation.
      }
    }
    return Reflect.apply(originalEmit, this, [event, ...args]);
  };

  prototype.send = function controlledSend(this: WebSocket, data: unknown, ...rest: unknown[]): unknown {
    if (typeof data === "string") {
      try {
        const frame = JSON.parse(data) as Record<string, unknown>;
        const payload = frame.payload as Record<string, unknown> | undefined;
        if (frame.type === "hello" && typeof payload?.cwd === "string" &&
            typeof payload.route_id === "string" && typeof payload.signature === "string") {
          authenticationFixtures.push({
            nonce: challengeBySocket.get(this) ?? "",
            signature: payload.signature,
            routeID: payload.route_id,
            cwd: payload.cwd,
          });
          if (payload.cwd === subjectCWD) {
            attempts.push({
              at: now(),
              routeID: payload.route_id,
              cwd: payload.cwd,
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
        }
      } catch {
        // Non-JSON writes remain owned by the real WebSocket implementation.
      }
    }
    return Reflect.apply(originalSend, this, [data, ...rest]);
  };

  return {
    attempts,
    authenticationFixtures,
    challengeNonces,
    holdNextAttempt: () => { holdNext = true; },
    restore: () => {
      prototype.send = originalSend;
      prototype.emit = originalEmit;
    },
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
      () => logs.some((line) => JSON.parse(line).event === "relay_reconnect_succeeded"),
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
    const relayExtension = (await import(`../index.ts?inline-bound=${Date.now()}`)).default;
    relayExtension(host.api as never);

    await host.emit("session_start", { type: "session_start", reason: "startup" });
    await waitUntil(() => endpoint.hellos.length === 11, "finite inline retry sequence", 2_000);
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
    assert.equal(scheduleCalls, 10);
    assert.equal(endpoint.hellos.length, 11, "retry sequence exceeded its ten-retry budget");
    const exhausted = logs.map((line) => JSON.parse(line) as Record<string, unknown>)
      .filter((event) => event.event === "relay_reconnect_exhausted");
    assert.deepEqual(exhausted, [{
      level: "warn",
      event: "relay_reconnect_exhausted",
      result: "exhausted",
      reason: "connection_closed",
      retry_index: 10,
      route_id: (endpoint.hellos[0].payload as Record<string, unknown>).route_id,
      client_public_key: (endpoint.hellos[0].payload as Record<string, unknown>).client_public_key,
    }]);
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

test("captured relay diagnostics cover lifecycle, reconnect, settlement, and redaction", { timeout: 60_000, concurrency: false }, async () => {
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
  const extensionStderr = capturePhysicalStderr();
  const clock = new FakeReconnectClock([0, 0.5, 0.75, 0.5]);
  const restoreDependencies = installReconnectDependenciesForTest(clock.dependencies);
  const subjectCWD = "/srv/reconnect-subject";
  const socketControl = installSubjectSocketControl(subjectCWD, () => clock.nowMS);
  const hosts: FakePiHost[] = [];
  let primaryError: unknown;

  try {
    const ready = await nextEvent(output, "server_ready");
    assert.equal(ready.result, "ready");
    const pairingCreated = await nextEvent(output, "pairing_code_created");
    assert.equal(pairingCreated.result, "created");
    assert.equal(pairingCreated.pairing_code, "<redacted>");
    assert.equal(pairingCreated.private_key, "<redacted>");
    process.env.PI_MESSAGING_RELAY_URL = `http://${String(ready.address)}`;
    process.env.PI_MESSAGING_RELAY_STATE_DIR = extensionState;
    const pairingCode = (await readFile(codeFile, "utf8")).trim();
    const relayExtension = (await import(`../index.ts?reconnect=${Date.now()}`)).default;

    const subject = new FakePiHost();
    subject.cwd = subjectCWD;
    relayExtension(subject.api as never);
    hosts.push(subject);
    await subject.emit("session_start", { type: "session_start", reason: "startup" });
    await subject.executeCommand("relay-pair", pairingCode);
    const pairAccepted = await nextEvent(output, "pair_accepted");
    const privatePEM = await readFile(join(extensionState, "installation-ed25519.pem"), "utf8");
    const initialAuth = await nextEvent(output, "auth_accepted", (event) => event.cwd === subjectCWD);
    const originalRouteID = String(initialAuth.route_id);
    const originalAddress = String(initialAuth.address);
    assert.match(originalRouteID, UUID_V7);
    assert.equal(originalAddress.endsWith(`#${originalRouteID}`), true);
    assert.equal(socketControl.attempts.length, 1);
    const heartbeatSocket = socketControl.attempts[0].socket;
    const pong = new Promise<void>((resolve) => heartbeatSocket.once("pong", () => resolve()));
    heartbeatSocket.ping("diagnostic-heartbeat-control");
    await within(pong, "observing heartbeat control pong");

    const observer = new FakePiHost();
    observer.cwd = "/srv/reconnect-observer";
    relayExtension(observer.api as never);
    hosts.push(observer);
    await observer.emit("session_start", { type: "session_start", reason: "startup" });
    const observerAuth = await nextEvent(output, "auth_accepted", (event) => event.cwd === observer.cwd);
    const observerAddress = String(observerAuth.address);
    assert.deepEqual(await listedAddresses(observer), [originalAddress]);

    const privateStringBody = "diagnostic-private-string-body-marker";
    const privateObjectMarker = "diagnostic-private-object-body-marker";
    const stringSend = await subject.executeTool("agent_send", {
      to: observerAddress,
      body: privateStringBody,
    }) as ToolSendResult;
    assert.equal(stringSend.details.status, "received");
    const stringSettlement = await nextEvent(output, "send_settled", (event) =>
      event.message_id === stringSend.details.message_id);
    const objectSend = await subject.executeTool("agent_send", {
      to: observerAddress,
      body: { private: privateObjectMarker, nested: { safe: false } },
    }) as ToolSendResult;
    assert.equal(objectSend.details.status, "received");
    const objectSettlement = await nextEvent(output, "send_settled", (event) =>
      event.message_id === objectSend.details.message_id);
    const privateOfflineBody = "diagnostic-private-offline-body-marker";
    const offlineAddress = "/srv/offline@diagnostic#01993ca3-3333-7aaa-8aaa-333333333333";
    const offlineSend = await subject.executeTool("agent_send", {
      to: offlineAddress,
      body: privateOfflineBody,
    }) as ToolSendResult;
    assert.deepEqual(offlineSend.details, {
      message_id: offlineSend.details.message_id,
      status: "timeout",
      reason: "offline",
    });
    const offlineSettlement = await nextEvent(output, "send_settled", (event) =>
      event.message_id === offlineSend.details.message_id);

    const hostileDestinationSecret = "diagnostic-hostile-destination-trap-secret";
    const hostileBodySecret = "diagnostic-hostile-malformed-body-secret";
    let hostileToJSONCalls = 0;
    const hostileDestination = {
      toJSON: () => {
        hostileToJSONCalls += 1;
        return hostileDestinationSecret;
      },
    };
    await assert.rejects(
      subject.executeTool("agent_send", {
        to: hostileDestination,
        body: hostileBodySecret,
      }),
      (error: unknown) => error instanceof Error && error.name === "RosterRequestError" &&
        (error as Error & { reason?: string }).reason === "invalid_arguments",
    );
    assert.equal(hostileToJSONCalls, 0, "diagnostics invoked hostile destination toJSON");

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

    await observer.emit("session_shutdown");
    await stop(child);
    const serverStopped = await nextEvent(output, "server_stopped");
    assert.equal(serverStopped.result, "graceful");
    assert.equal(child.exitCode, 0);
    await drainOutput(output);
    assert.equal(stderr.length, 0);
    await new Promise<void>((resolve) => setImmediate(resolve));
    const extensionLogs = extensionStderr.lines();
    extensionStderr.restore();

    const parseNormalLines = (stream: string, captured: string[]): Array<Record<string, unknown>> =>
      captured.filter((line) => line.length > 0).map((line) => {
        assert.equal(line.includes("\n") || line.includes("\r"), false, `${stream} emitted a multi-line event`);
        const parsed: unknown = JSON.parse(line);
        assert.ok(parsed !== null && typeof parsed === "object" && !Array.isArray(parsed));
        return parsed as Record<string, unknown>;
      });
    const serverEvents = parseNormalLines("server stdout", output.lines);
    const extensionEvents = parseNormalLines("extension stderr", extensionLogs);

    assert.deepEqual(Object.keys(ready).sort(), ["address", "event", "level", "result", "state_dir"]);
    assert.deepEqual(
      Object.keys(pairingCreated).sort(),
      ["event", "expires_at", "level", "pairing_code", "private_key", "result"],
    );
    assert.equal(pairAccepted.client_public_key, initialAuth.client_public_key);
    assert.equal(pairAccepted.pairing_code, "<redacted>");
    assert.equal(pairAccepted.private_key, "<redacted>");
    assert.match(String(initialAuth.request_id), UUID_V7);
    assert.equal(initialAuth.nonce, "<redacted>");
    assert.equal(initialAuth.signature, "<redacted>");
    assert.equal(initialAuth.private_key, "<redacted>");
    for (const settlement of [stringSettlement, objectSettlement]) {
      assert.equal(settlement.level, "info");
      assert.equal(settlement.result, "settled");
      assert.equal(settlement.reason, "received");
      assert.equal(settlement.body, "<redacted>");
      assert.match(String(settlement.request_id), UUID_V7);
      assert.match(String(settlement.message_id), UUID_V7);
      assert.match(String(settlement.delivery_id), UUID_V7);
      assert.equal(settlement.sender_route, originalAddress);
      assert.equal(settlement.recipient_route, observerAddress);
    }
    assert.equal(offlineSettlement.level, "info");
    assert.equal(offlineSettlement.result, "settled");
    assert.equal(offlineSettlement.reason, "offline");
    assert.equal(offlineSettlement.status, "timeout");
    assert.equal(offlineSettlement.delivery_id, undefined);
    assert.equal(offlineSettlement.recipient_route, offlineAddress);
    assert.equal(offlineSettlement.body, "<redacted>");

    const extensionPair = extensionEvents.find((event) => event.event === "relay_pair_accepted");
    assert.ok(extensionPair);
    assert.equal(extensionPair.client_public_key, initialAuth.client_public_key);
    assert.equal(extensionPair.pairing_code, "<redacted>");
    assert.equal(extensionPair.private_key, "<redacted>");
    const initialExtensionAuth = extensionEvents.find((event) =>
      event.event === "relay_auth_accepted" && event.address === originalAddress);
    assert.ok(initialExtensionAuth);
    assert.equal(initialExtensionAuth.nonce, "<redacted>");
    assert.equal(initialExtensionAuth.signature, "<redacted>");
    assert.equal(initialExtensionAuth.private_key, "<redacted>");

    const sendEvents = extensionEvents.filter((event) => event.event === "relay_send_settled");
    assert.deepEqual(
      sendEvents.map((event) => ({
        level: event.level,
        result: event.result,
        reason: event.reason,
        messageID: event.message_id,
        sender: event.sender_route,
        recipient: event.recipient_route,
        status: event.status,
        body: event.body,
      })),
      [
        {
          level: "info",
          result: "settled",
          reason: "received",
          messageID: stringSend.details.message_id,
          sender: originalAddress,
          recipient: observerAddress,
          status: "received",
          body: "<redacted>",
        },
        {
          level: "info",
          result: "settled",
          reason: "received",
          messageID: objectSend.details.message_id,
          sender: originalAddress,
          recipient: observerAddress,
          status: "received",
          body: "<redacted>",
        },
        {
          level: "warn",
          result: "settled",
          reason: "offline",
          messageID: offlineSend.details.message_id,
          sender: originalAddress,
          recipient: offlineAddress,
          status: "timeout",
          body: "<redacted>",
        },
      ],
    );
    for (const event of sendEvents) {
      assert.deepEqual(
        Object.keys(event).sort(),
        ["body", "event", "latency_ms", "level", "message_id", "operation", "reason", "recipient_route", "result", "sender_route", "status"],
      );
      assert.equal(event.operation, "agent_send");
      assert.equal(typeof event.latency_ms, "number");
    }
    const hostileFailure = extensionEvents.find((event) =>
      event.event === "relay_operation_failed" && event.operation === "agent_send" &&
      event.reason === "invalid_arguments");
    assert.ok(hostileFailure);
    assert.deepEqual(Object.keys(hostileFailure).sort(), [
      "body", "event", "latency_ms", "level", "operation", "reason", "result",
    ]);
    assert.equal(hostileFailure.body, "<redacted>");

    const reconnectEvents = extensionEvents.filter((event) =>
      event.route_id === originalRouteID &&
      ["relay_session_disconnected", "relay_reconnect_scheduled", "relay_reconnect_attempted",
        "relay_auth_rejected", "relay_reconnect_succeeded"].includes(String(event.event)));
    assert.deepEqual(
      reconnectEvents.slice(0, 10).map((event) => ({
        event: event.event,
        result: event.result,
        reason: event.reason,
        retryIndex: event.retry_index,
        delayMS: event.delay_ms,
      })),
      [
        { event: "relay_session_disconnected", result: "disconnected", reason: undefined, retryIndex: undefined, delayMS: undefined },
        { event: "relay_reconnect_scheduled", result: "scheduled", reason: "session_disconnected", retryIndex: 1, delayMS: 375 },
        { event: "relay_reconnect_attempted", result: "attempted", reason: undefined, retryIndex: 1, delayMS: undefined },
        { event: "relay_auth_rejected", result: "rejected", reason: "connection_closed", retryIndex: undefined, delayMS: undefined },
        { event: "relay_reconnect_scheduled", result: "scheduled", reason: "connection_closed", retryIndex: 2, delayMS: 1_000 },
        { event: "relay_reconnect_attempted", result: "attempted", reason: undefined, retryIndex: 2, delayMS: undefined },
        { event: "relay_auth_rejected", result: "rejected", reason: "connection_closed", retryIndex: undefined, delayMS: undefined },
        { event: "relay_reconnect_scheduled", result: "scheduled", reason: "connection_closed", retryIndex: 3, delayMS: 2_250 },
        { event: "relay_reconnect_attempted", result: "attempted", reason: undefined, retryIndex: 3, delayMS: undefined },
        { event: "relay_reconnect_succeeded", result: "connected", reason: undefined, retryIndex: 3, delayMS: undefined },
      ],
    );
    const started = extensionEvents.find((event) =>
      event.event === "relay_session_started" && event.reason === "startup" && event.route_id === originalRouteID);
    assert.ok(started);
    assert.equal(started.level, "info");
    assert.equal(started.result, "started");
    assert.ok(extensionEvents.some((event) =>
      event.event === "relay_session_stopped" && event.result === "graceful"));

    for (const event of [...serverEvents, ...extensionEvents]) {
      for (const field of ["pairing_code", "nonce", "signature", "private_key", "body"]) {
        if (field in event) assert.equal(event[field], "<redacted>", `${String(event.event)}.${field}`);
      }
    }
    const sensitiveFixtures = [
      pairingCode,
      privatePEM.trim(),
      ...privatePEM.split(/\r?\n/).filter((line) => line.length > 40),
      ...socketControl.authenticationFixtures.flatMap((fixture) => [fixture.nonce, fixture.signature]),
      privateStringBody,
      privateObjectMarker,
      privateOfflineBody,
      hostileDestinationSecret,
      hostileBodySecret,
    ];
    assert.equal(socketControl.authenticationFixtures.length, socketControl.challengeNonces.length);
    assert.deepEqual(
      socketControl.authenticationFixtures.map((fixture) => fixture.nonce).sort(),
      [...socketControl.challengeNonces].sort(),
    );
    assert.equal(
      socketControl.authenticationFixtures.filter((fixture) => fixture.cwd === subjectCWD).length,
      socketControl.attempts.length,
    );
    assert.ok(socketControl.authenticationFixtures.some((fixture) => fixture.cwd === observer.cwd));
    assert.equal(
      new Set(socketControl.authenticationFixtures.map((fixture) => fixture.signature)).size,
      socketControl.authenticationFixtures.length,
    );
    assert.ok(sensitiveFixtures.every((fixture) => fixture.length > 0));
    for (const fixture of sensitiveFixtures) {
      assert.equal(serverEvents.some((_event, index) => output.lines[index]?.includes(fixture)), false);
      assert.equal(extensionLogs.some((line) => line.includes(fixture)), false);
    }
    assert.ok(serverEvents.some((event) => event.client_public_key === pairAccepted.client_public_key));
    assert.ok(extensionEvents.some((event) => event.client_public_key === pairAccepted.client_public_key));
    assert.ok(serverEvents.some((event) => event.message_id === stringSend.details.message_id));
    assert.ok(extensionEvents.some((event) => event.message_id === stringSend.details.message_id));
    assert.equal([...serverEvents, ...extensionEvents].some((event) =>
      event.level === "info" && /heartbeat|ping|pong/.test(String(event.event))), false);
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
    extensionStderr.restore();
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
