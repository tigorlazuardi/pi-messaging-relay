import assert from "node:assert/strict";
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import test from "node:test";

import WebSocket, { WebSocketServer } from "ws";

import { installReconnectDependenciesForTest } from "../internal/reconnect.ts";
import { generateUUIDv7 } from "../internal/uuid.ts";
import { FakePiHost } from "./fake-pi-host.ts";
import {
  installIsolatedHome,
  SHARED_RELAY_SECRET,
  writeClientConfig,
  writeServerSecretFile,
} from "./secret-relay.ts";

const TEST_TIMEOUT_MS = 15_000;

type Output = { iterator: AsyncIterator<string>; lines: string[] };

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
  if (child.exitCode !== null && child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  child.kill("SIGTERM");
  try {
    await within(exited, "stopping relay");
  } catch {
    child.kill("SIGKILL");
    await within(exited, "killing relay");
  }
}

/** One raw protocol client used to drive the relay without the extension. */
type RawClient = {
  socket: WebSocket;
  frames: Record<string, unknown>[];
  send(frame: Record<string, unknown>): void;
  waitFor(predicate: (frame: Record<string, unknown>) => boolean, action: string): Promise<Record<string, unknown>>;
  close(): Promise<void>;
};

async function openRawClient(
  endpoint: string,
  options: { capabilities?: string[]; secret?: string } = {},
): Promise<RawClient> {
  const headers: Record<string, string> = {};
  if (options.secret !== undefined) headers.Authorization = `Bearer ${options.secret}`;
  if (options.capabilities !== undefined) headers["X-Relay-Capabilities"] = options.capabilities.join(", ");
  const socket = new WebSocket(endpoint, { headers, perMessageDeflate: false });
  await within(new Promise<void>((resolve, reject) => {
    socket.once("open", () => resolve());
    socket.once("error", reject);
  }), "opening raw client");
  const frames: Record<string, unknown>[] = [];
  socket.on("message", (data) => {
    frames.push(JSON.parse(data.toString("utf8")) as Record<string, unknown>);
  });
  return {
    socket,
    frames,
    send: (frame) => socket.send(JSON.stringify(frame)),
    waitFor: async (predicate, action) => {
      const deadline = Date.now() + TEST_TIMEOUT_MS;
      while (Date.now() < deadline) {
        const found = frames.find((frame) => predicate(frame));
        if (found) return found;
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      throw new Error(`timed out ${action}`);
    },
    close: async () => {
      if (socket.readyState === WebSocket.CLOSED) return;
      const closed = new Promise<void>((resolve) => socket.once("close", () => resolve()));
      socket.terminate();
      await closed;
    },
  };
}

async function openSession(
  client: RawClient,
  routeID: string,
  cwd: string,
): Promise<void> {
  const requestID = generateUUIDv7();
  client.send({
    v: 1,
    type: "hello",
    request_id: requestID,
    payload: { route_id: routeID, hostname: "host", cwd },
  });
  await client.waitFor((frame) => frame.type === "welcome", "welcome");
}

async function listPeers(client: RawClient): Promise<Record<string, unknown>> {
  const requestID = generateUUIDv7();
  client.send({ v: 1, type: "list", request_id: requestID, payload: {} });
  const response = await client.waitFor(
    (frame) => frame.type === "roster" && frame.request_id === requestID,
    "roster response",
  );
  return response.payload as Record<string, unknown>;
}

test("a new client keeps working against a legacy relay and never sends annotations", { timeout: 60_000, concurrency: false }, async (context) => {
  const root = await mkdtemp(join(tmpdir(), "pi-relay-legacy-server-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const listener = new WebSocketServer({ host: "127.0.0.1", port: 0, perMessageDeflate: false });
  const sockets = new Set<WebSocket>();
  const received: Record<string, unknown>[] = [];
  const upgradeHeaders: Array<Record<string, string | string[] | undefined>> = [];
  listener.on("connection", (socket, request) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    upgradeHeaders.push(request.headers);
    socket.on("message", (data) => {
      const frame = JSON.parse(data.toString("utf8")) as Record<string, unknown>;
      received.push(frame);
      if (frame.type === "hello") {
        const payload = frame.payload as Record<string, unknown>;
        // A legacy relay answers with the exact three-field welcome.
        socket.send(JSON.stringify({
          v: 1,
          type: "welcome",
          request_id: frame.request_id,
          payload: {
            self_address: `${String(payload.cwd)}@${String(payload.hostname)}#${String(payload.route_id)}`,
            heartbeat_ms: 30_000,
            max_body_bytes: 262_144,
          },
        }));
        return;
      }
      if (frame.type === "list") {
        socket.send(JSON.stringify({
          v: 1,
          type: "roster",
          request_id: frame.request_id,
          payload: { peers: [{ address: "/srv/legacy@host#route" }] },
        }));
        return;
      }
      // A legacy relay treats every unknown operation as terminal.
      socket.close(1002, "unsupported operation");
    });
  });
  await new Promise<void>((resolve, reject) => {
    listener.once("listening", resolve);
    listener.once("error", reject);
  });
  const address = listener.address();
  assert.ok(address && typeof address === "object");
  context.after(async () => {
    for (const socket of sockets) socket.terminate();
    await new Promise<void>((resolve) => listener.close(() => resolve()));
  });

  const originalError = console.error;
  const logs: string[] = [];
  const host = new FakePiHost();
  host.cwd = "/srv/new-client";
  const environment = installIsolatedHome(join(root, "home"));
  context.after(() => environment.restore());
  try {
    process.env.PI_MESSAGING_RELAY_URL = `http://127.0.0.1:${address.port}`;
    console.error = (...values: unknown[]) => logs.push(values.map(String).join(" "));
    const relayExtension = (await import(`../index.ts?legacy-server=${Date.now()}`)).default;
    relayExtension(host.api as never);
    await host.emit("session_start");

    const deadline = Date.now() + TEST_TIMEOUT_MS;
    let page: { peers: Array<{ address: string; annotations?: Record<string, string> }> } | undefined;
    while (Date.now() < deadline) {
      try {
        const result = await host.executeTool("relay_list_peers", {}) as {
          details: { peers: Array<{ address: string; annotations?: Record<string, string> }> };
        };
        if (result.details.peers.length > 0) {
          page = result.details;
          break;
        }
      } catch {
        // The connection may not have landed yet.
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.ok(page, "the new client never listed the legacy relay roster");
    assert.deepEqual(page.peers, [{ address: "/srv/legacy@host#route" }]);

    // The legacy relay never advertised the capability, so the client sends no
    // annotate operation at all.
    assert.equal(received.some((frame) => frame.type === "annotate"), false);
    // The upgrade still offers the capability; a legacy relay ignores it.
    assert.equal(String(upgradeHeaders[0]?.["x-relay-capabilities"]), "annotations");
  } finally {
    console.error = originalError;
    await host.emit("session_shutdown").catch(() => undefined);
  }
});

test("a capable session publishes its annotations again after a reconnect", { timeout: 60_000, concurrency: false }, async (context) => {
  const root = await mkdtemp(join(tmpdir(), "pi-relay-annotation-reconnect-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const listener = new WebSocketServer({ host: "127.0.0.1", port: 0, perMessageDeflate: false });
  const sockets = new Set<WebSocket>();
  const annotateFrames: Array<Record<string, unknown>> = [];
  let connections = 0;
  listener.on("connection", (socket) => {
    sockets.add(socket);
    connections += 1;
    socket.once("close", () => sockets.delete(socket));
    socket.on("message", (data) => {
      const frame = JSON.parse(data.toString("utf8")) as Record<string, unknown>;
      if (frame.type === "hello") {
        const payload = frame.payload as Record<string, unknown>;
        socket.send(JSON.stringify({
          v: 1,
          type: "welcome",
          request_id: frame.request_id,
          payload: {
            self_address: `${String(payload.cwd)}@${String(payload.hostname)}#${String(payload.route_id)}`,
            heartbeat_ms: 30_000,
            max_body_bytes: 262_144,
            capabilities: ["annotations"],
          },
        }));
        return;
      }
      if (frame.type === "annotate") {
        annotateFrames.push(frame);
        // The first connection dies right after the first annotation, so the
        // session must publish again on the next connection.
        if (connections === 1) socket.terminate();
        return;
      }
      if (frame.type === "list") {
        socket.send(JSON.stringify({
          v: 1,
          type: "roster",
          request_id: frame.request_id,
          payload: { peers: [] },
        }));
      }
    });
  });
  await new Promise<void>((resolve, reject) => {
    listener.once("listening", resolve);
    listener.once("error", reject);
  });
  const address = listener.address();
  assert.ok(address && typeof address === "object");
  context.after(async () => {
    for (const socket of sockets) socket.terminate();
    await new Promise<void>((resolve) => listener.close(() => resolve()));
  });

  const restoreDependencies = installReconnectDependenciesForTest({
    now: () => 1_800_000_000_000,
    randomUnit: () => 0.5,
    schedule: (callback) => {
      callback();
      return { cancel: () => undefined };
    },
  });
  context.after(() => restoreDependencies());

  const originalError = console.error;
  const host = new FakePiHost();
  host.cwd = "/srv/reconnect";
  host.sessionID = "session-reconnect";
  const environment = installIsolatedHome(join(root, "home"));
  context.after(() => environment.restore());
  try {
    process.env.PI_MESSAGING_RELAY_URL = `http://127.0.0.1:${address.port}`;
    console.error = () => undefined;
    const relayExtension = (await import(`../index.ts?annotation-reconnect=${Date.now()}`)).default;
    relayExtension(host.api as never);
    await host.emit("session_start");

    const deadline = Date.now() + TEST_TIMEOUT_MS;
    while (Date.now() < deadline && annotateFrames.length < 2) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(annotateFrames.length >= 2, true, "the reconnect did not publish the annotations again");
    const payload = annotateFrames[0].payload as { annotations: Record<string, string> };
    assert.equal(payload.annotations.session, "session-reconnect");
    assert.equal(payload.annotations.state, "idle");
    assert.deepEqual(
      (annotateFrames[1].payload as { annotations: Record<string, string> }).annotations,
      payload.annotations,
    );
  } finally {
    console.error = originalError;
    await host.emit("session_shutdown").catch(() => undefined);
  }
});

test("a legacy client keeps working against the new relay and sees no annotations", { timeout: 60_000, concurrency: false }, async (context) => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const root = await mkdtemp(join(tmpdir(), "pi-relay-legacy-client-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const binary = join(root, "relay-server");
  const state = join(root, "server-state");
  const secretFile = await writeServerSecretFile(state);
  execFileSync("go", ["build", "-o", binary, "./cmd/pi-messaging-relay-server"], {
    cwd: repositoryRoot,
    stdio: "pipe",
  });
  const child = spawn(binary, [
    "--listen", "127.0.0.1:0",
    "--state-dir", state,
    "--secret-file", secretFile,
  ], { cwd: repositoryRoot, stdio: ["ignore", "pipe", "pipe"] });
  context.after(async () => stop(child));
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const output: Output = { iterator: lines[Symbol.asyncIterator](), lines: [] };
  const ready = await nextEvent(output, "server_ready");
  const address = String(ready.address);
  const endpoint = `ws://${address}/v1/connect`;

  // A capable publisher.
  const publisher = await openRawClient(endpoint, {
    capabilities: ["annotations"],
    secret: SHARED_RELAY_SECRET,
  });
  context.after(() => publisher.close());
  await openSession(publisher, generateUUIDv7(), "/srv/publisher");
  const annotateRequestID = generateUUIDv7();
  publisher.send({
    v: 1,
    type: "annotate",
    request_id: annotateRequestID,
    payload: { annotations: { name: "publisher", state: "busy" } },
  });

  // A legacy requester without the capability header.
  const legacy = await openRawClient(endpoint, { secret: SHARED_RELAY_SECRET });
  context.after(() => legacy.close());
  await openSession(legacy, generateUUIDv7(), "/srv/legacy");

  const legacyPage = await listPeers(legacy);
  const peers = legacyPage.peers as Array<{ address: string; annotations?: unknown }>;
  assert.equal(peers.length, 1);
  assert.match(peers[0].address, /^\/srv\/publisher@host#/);
  assert.equal(peers[0].annotations, undefined, "a legacy requester must not receive annotations");

  // A capable requester sees them.
  const capable = await openRawClient(endpoint, {
    capabilities: ["annotations"],
    secret: SHARED_RELAY_SECRET,
  });
  context.after(() => capable.close());
  await openSession(capable, generateUUIDv7(), "/srv/capable");
  const capablePage = await listPeers(capable);
  const capablePeers = capablePage.peers as Array<{ address: string; annotations?: Record<string, string> }>;
  const published = capablePeers.find((peer) => peer.address.startsWith("/srv/publisher@"));
  assert.ok(published, "the capable requester must see the publisher");
  assert.deepEqual(published.annotations, { name: "publisher", state: "busy" });

  // A legacy hello carrying annotations stays an unknown-field rejection.
  const strict = await openRawClient(endpoint, { secret: SHARED_RELAY_SECRET });
  context.after(() => strict.close());
  strict.send({
    v: 1,
    type: "hello",
    request_id: generateUUIDv7(),
    payload: {
      route_id: generateUUIDv7(),
      hostname: "host",
      cwd: "/srv/strict",
      annotations: { name: "legacy" },
    },
  });
  const closed = await new Promise<boolean>((resolve) => {
    strict.socket.once("close", () => resolve(true));
    setTimeout(() => resolve(false), 5_000).unref?.();
  });
  assert.equal(closed, true, "a legacy hello with annotations must be rejected");
  assert.equal(strict.frames.some((frame) => frame.type === "welcome"), false);

  // No annotation value reached the relay log.
  assert.equal(output.lines.some((line) => line.includes("publisher")), false);
});
