import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { homedir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { SessionSocketAttempt } from "../internal/session-auth.ts";
import { clientConfigurationPath } from "../internal/client-config.ts";
import { FakePiHost } from "./fake-pi-host.ts";

const WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const ROUTE_ID = "01993ca1-1111-7aaa-8aaa-111111111111";
const SECRET = "transport-shared-secret";

type RawFrame = { opcode: number; payload: Buffer };

class RawPeer {
  private buffered = Buffer.alloc(0);
  private waiter: ((frame: RawFrame) => void) | undefined;
  readonly socket: Socket;
  readonly closed: Promise<void>;

  constructor(socket: Socket, initial: Buffer) {
    this.socket = socket;
    this.buffered = initial;
    this.closed = new Promise((resolve) => socket.once("close", () => resolve()));
    socket.on("data", (data) => {
      this.buffered = Buffer.concat([this.buffered, data]);
      this.flush();
    });
  }

  readFrame(): Promise<RawFrame> {
    const frame = this.parseFrame();
    if (frame) return Promise.resolve(frame);
    return new Promise((resolve) => {
      this.waiter = resolve;
    });
  }

  sendText(payload: string, options: { fin?: boolean; opcode?: number } = {}): void {
    this.socket.write(serverFrame(Buffer.from(payload), options.fin ?? true, options.opcode ?? 0x1));
  }

  private flush(): void {
    if (!this.waiter) return;
    const frame = this.parseFrame();
    if (!frame) return;
    const waiter = this.waiter;
    this.waiter = undefined;
    waiter(frame);
  }

  private parseFrame(): RawFrame | undefined {
    if (this.buffered.length < 2) return undefined;
    const opcode = this.buffered[0] & 0x0f;
    const masked = (this.buffered[1] & 0x80) !== 0;
    let length = this.buffered[1] & 0x7f;
    let offset = 2;
    if (length === 126) {
      if (this.buffered.length < 4) return undefined;
      length = this.buffered.readUInt16BE(2);
      offset = 4;
    } else if (length === 127) {
      throw new Error("test endpoint does not accept 64-bit client frame lengths");
    }
    const maskBytes = masked ? 4 : 0;
    if (this.buffered.length < offset + maskBytes + length) return undefined;
    const mask = masked ? this.buffered.subarray(offset, offset + 4) : undefined;
    offset += maskBytes;
    const payload = Buffer.from(this.buffered.subarray(offset, offset + length));
    this.buffered = this.buffered.subarray(offset + length);
    if (mask) {
      for (let index = 0; index < payload.length; index += 1) {
        payload[index] ^= mask[index % 4];
      }
    }
    return { opcode, payload };
  }
}

function serverFrame(payload: Buffer, fin: boolean, opcode: number): Buffer {
  const header = payload.length < 126
    ? Buffer.alloc(2)
    : payload.length <= 0xffff
      ? Buffer.alloc(4)
      : Buffer.alloc(10);
  header[0] = (fin ? 0x80 : 0) | opcode;
  if (payload.length < 126) {
    header[1] = payload.length;
  } else if (payload.length <= 0xffff) {
    header[1] = 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  return Buffer.concat([header, payload]);
}

type RawUpgrade = { peer: RawPeer; authorization: string | undefined };

async function startRawEndpoint(
  onUpgrade: (upgrade: RawUpgrade) => void,
  options: { respond?: "unauthorized" } = {},
): Promise<{
  endpoint: URL;
  server: Server;
}> {
  const server = createServer((socket) => {
    let request = Buffer.alloc(0);
    const onData = (data: Buffer) => {
      request = Buffer.concat([request, data]);
      const boundary = request.indexOf("\r\n\r\n");
      if (boundary < 0) return;
      socket.off("data", onData);
      const headers = request.subarray(0, boundary).toString("ascii");
      const key = /^Sec-WebSocket-Key:\s*(.+)$/im.exec(headers)?.[1]?.trim();
      if (!key) {
        socket.destroy();
        return;
      }
      if (options.respond === "unauthorized") {
        socket.write(
          "HTTP/1.1 401 Unauthorized\r\n" +
          "Content-Type: application/json\r\n" +
          "WWW-Authenticate: Bearer\r\n" +
          'Content-Length: 51\r\n' +
          "\r\n" +
          '{"error":"not_authorized","message":"Authentication is required"}',
        );
        return;
      }
      const accept = createHash("sha1").update(key + WEBSOCKET_GUID).digest("base64");
      socket.write(
        "HTTP/1.1 101 Switching Protocols\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
      );
      onUpgrade({
        peer: new RawPeer(socket, request.subarray(boundary + 4)),
        authorization: /^Authorization:\s*(.+)$/im.exec(headers)?.[1]?.trim(),
      });
    };
    socket.on("data", onData);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return { endpoint: new URL(`ws://127.0.0.1:${address.port}`), server };
}

function attemptOptions(
  endpoint: URL,
  overrides: Partial<ConstructorParameters<typeof SessionSocketAttempt>[0]> = {},
): ConstructorParameters<typeof SessionSocketAttempt>[0] {
  return {
    endpoint,
    secret: undefined,
    routeID: ROUTE_ID,
    cwd: "/srv/transport",
    hostname: "transport-host",
    deliverUserMessage: () => {},
    onDisconnected: () => {},
    ...overrides,
  };
}

async function within<T>(promise: Promise<T>, timeoutMS = 3_000): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("test resource did not settle within deadline")), timeoutMS);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

async function readHello(peer: RawPeer): Promise<Record<string, unknown>> {
  const frame = await peer.readFrame();
  assert.equal(frame.opcode, 0x1);
  return JSON.parse(frame.payload.toString("utf8")) as Record<string, unknown>;
}

function sendWelcome(peer: RawPeer, hello: Record<string, unknown>): void {
  const payload = hello.payload as Record<string, unknown>;
  peer.sendText(JSON.stringify({
    v: 1,
    type: "welcome",
    request_id: hello.request_id,
    payload: {
      self_address: `${String(payload.cwd)}@${String(payload.hostname)}#${String(payload.route_id)}`,
      heartbeat_ms: 30_000,
      max_body_bytes: 262_144,
    },
  }));
}

test("upgrade sends the Bearer header exactly when a secret is configured", async (context) => {
  const seen: Array<string | undefined> = [];
  const endpoint = await startRawEndpoint(({ authorization, peer }) => {
    seen.push(authorization);
    void peer.readFrame().then((frame) => {
      const parsed = JSON.parse(frame.payload.toString("utf8")) as Record<string, unknown>;
      sendWelcome(peer, parsed);
    });
  });
  context.after(async () => closeServer(endpoint.server));

  const withSecret = new SessionSocketAttempt(attemptOptions(endpoint.endpoint, { secret: SECRET }));
  const authorized = await within(withSecret.result);
  context.after(() => authorized.closeAndWait());
  assert.equal(authorized.address, `/srv/transport@transport-host#${ROUTE_ID}`);
  await authorized.closeAndWait();

  const withoutSecret = new SessionSocketAttempt(attemptOptions(endpoint.endpoint));
  const anonymous = await within(withoutSecret.result);
  context.after(() => anonymous.closeAndWait());
  await anonymous.closeAndWait();

  assert.deepEqual(seen, [`Bearer ${SECRET}`, undefined]);
});

test("post-upgrade hello is unsigned establishment with exactly route, hostname, and cwd", async (context) => {
  let peerClosed: Promise<void> | undefined;
  const endpoint = await startRawEndpoint(({ peer }) => {
    peerClosed = peer.closed;
    void peer.readFrame().then((frame) => {
      assert.equal(frame.opcode, 0x1);
      const hello = JSON.parse(frame.payload.toString("utf8")) as Record<string, unknown>;
      assert.deepEqual(Object.keys(hello).sort(), ["payload", "request_id", "type", "v"]);
      assert.equal(hello.v, 1);
      assert.equal(hello.type, "hello");
      assert.match(String(hello.request_id), /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      const payload = hello.payload as Record<string, unknown>;
      assert.deepEqual(
        { keys: Object.keys(payload).sort(), route: payload.route_id, hostname: payload.hostname, cwd: payload.cwd },
        { keys: ["cwd", "hostname", "route_id"], route: ROUTE_ID, hostname: "transport-host", cwd: "/srv/transport" },
      );
      sendWelcome(peer, hello);
    });
  });
  context.after(async () => closeServer(endpoint.server));

  const attempt = new SessionSocketAttempt(attemptOptions(endpoint.endpoint, { secret: SECRET }));
  const connection = await within(attempt.result);
  context.after(() => connection.closeAndWait());
  assert.equal(connection.address, `/srv/transport@transport-host#${ROUTE_ID}`);
  await connection.closeAndWait();
  assert.ok(peerClosed);
});

test("a v1 challenge frame before welcome fails the v2 establishment closed", async (context) => {
  let peerClosed: Promise<void> | undefined;
  const endpoint = await startRawEndpoint(({ peer }) => {
    peerClosed = peer.closed;
    peer.sendText(JSON.stringify({
      v: 1,
      type: "challenge",
      payload: { nonce: "A".repeat(43) },
    }));
  });
  context.after(async () => closeServer(endpoint.server));

  const attempt = new SessionSocketAttempt(attemptOptions(endpoint.endpoint));
  await assert.rejects(within(attempt.result), (error: unknown) =>
    error !== null && typeof error === "object" &&
    "reason" in error && error.reason === "invalid_welcome");
  assert.ok(peerClosed);
  await within(peerClosed);
});

async function expectRejectedAttempt(
  endpoint: URL,
  expectedMessage: string,
): Promise<void> {
  const attempt = new SessionSocketAttempt(attemptOptions(endpoint, { cwd: "/oversized" }));
  await assert.rejects(within(attempt.result), (error: unknown) =>
    error !== null && typeof error === "object" &&
    "reason" in error && error.reason === "invalid_frame" &&
    "message" in error && error.message === expectedMessage);
}

test("complete valid JSON establishment payload over 16 KiB is semantically rejected and force-settled", async (context) => {
  let peerClosed: Promise<void> | undefined;
  const endpoint = await startRawEndpoint(({ peer }) => {
    peerClosed = peer.closed;
    peer.sendText(JSON.stringify({
      v: 1,
      type: "welcome",
      request_id: "01993c79-8ad7-79fa-83e3-9789dcaca168",
      payload: { self_address: "unused", heartbeat_ms: 30_000, max_body_bytes: 262_144 },
      padding: "x".repeat(16 * 1_024),
    }));
    // Deliberately ignore the client's close frame.
  });
  context.after(async () => closeServer(endpoint.server));

  await expectRejectedAttempt(endpoint.endpoint, "Relay session establishment frame exceeds 16 KiB.");
  assert.ok(peerClosed);
  await within(peerClosed);
});

test("fragmented valid JSON establishment payload over 16 KiB is semantically rejected and force-settled", async (context) => {
  let peerClosed: Promise<void> | undefined;
  const endpoint = await startRawEndpoint(({ peer }) => {
    peerClosed = peer.closed;
    const payload = JSON.stringify({
      v: 1,
      type: "welcome",
      request_id: "01993c79-8ad7-79fa-83e3-9789dcaca168",
      payload: { self_address: "unused", heartbeat_ms: 30_000, max_body_bytes: 262_144 },
      padding: "x".repeat(16 * 1_024),
    });
    const boundaries = [0, 4_096, 8_192, 12_288, 16_384, payload.length];
    for (let index = 0; index < boundaries.length - 1; index += 1) {
      peer.sendText(payload.slice(boundaries[index], boundaries[index + 1]), {
        fin: index === boundaries.length - 2,
        opcode: index === 0 ? 0x1 : 0x0,
      });
    }
    // Deliberately ignore the client's close frame.
  });
  context.after(async () => closeServer(endpoint.server));

  await expectRejectedAttempt(endpoint.endpoint, "Relay session establishment frame exceeds 16 KiB.");
  assert.ok(peerClosed);
  await within(peerClosed);
});

test("establishment payload over 512 KiB is transport-rejected and force-settled before use", async (context) => {
  let peerClosed: Promise<void> | undefined;
  const endpoint = await startRawEndpoint(({ peer }) => {
    peerClosed = peer.closed;
    peer.sendText("x".repeat(512 * 1_024 + 1));
    // Deliberately ignore the client's close frame.
  });
  context.after(async () => closeServer(endpoint.server));

  await expectRejectedAttempt(
    endpoint.endpoint,
    "Relay session establishment transport payload exceeds 512 KiB.",
  );
  assert.ok(peerClosed);
  await within(peerClosed);
});

test("closed HTTP 401 upgrade settles as one not_authorized failure", async (context) => {
  const endpoint = await startRawEndpoint(() => {}, { respond: "unauthorized" });
  context.after(async () => closeServer(endpoint.server));

  const attempt = new SessionSocketAttempt(attemptOptions(endpoint.endpoint, { secret: "wrong-secret" }));
  await assert.rejects(within(attempt.result), (error: unknown) =>
    error !== null && typeof error === "object" &&
    "reason" in error && error.reason === "not_authorized" &&
    "message" in error && error.message === "Relay rejected the upgrade credentials.");
});

test("production session_shutdown force-settles retained socket when peer ignores close", async (context) => {
  let peerClosed: Promise<void> | undefined;
  const endpoint = await startRawEndpoint(({ peer }) => {
    peerClosed = peer.closed;
    void peer.readFrame().then((frame) => {
      assert.equal(frame.opcode, 0x1);
      const hello = JSON.parse(frame.payload.toString("utf8")) as Record<string, unknown>;
      const payload = hello.payload as Record<string, unknown>;
      peer.sendText(JSON.stringify({
        v: 1,
        type: "welcome",
        request_id: hello.request_id,
        payload: {
          self_address: `${String(payload.cwd)}@${String(payload.hostname)}#${String(payload.route_id)}`,
          heartbeat_ms: 30_000,
          max_body_bytes: 262_144,
        },
      }));
      // Deliberately leave the later close frame unread and unanswered.
    });
  });
  context.after(async () => closeServer(endpoint.server));

  const root = await mkdtemp(join(tmpdir(), "pi-relay-hostile-shutdown-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, ".config", "pi"), { recursive: true, mode: 0o700 });
  await writeFile(
    clientConfigurationPath(root),
    JSON.stringify({
      url: endpoint.endpoint.href.replace(/^ws:/, "http:"),
      secret: SECRET,
    }),
    { mode: 0o600 },
  );

  const previousURL = process.env.PI_MESSAGING_RELAY_URL;
  const previousHome = process.env.HOME;
  const originalConsoleError = console.error;
  const logs: string[] = [];
  process.env.PI_MESSAGING_RELAY_URL = "";
  process.env.HOME = root;
  console.error = (...values: unknown[]) => logs.push(values.map(String).join(" "));
  try {
    const host = new FakePiHost();
    const relayExtension = (await import(`../index.ts?hostile-shutdown=${Date.now()}`)).default;
    relayExtension(host.api as never);
    await within(host.emit("session_start"));
    // Connect is fire-and-forget; wait until the accepted event lands.
    const acceptedCount = () =>
      logs.filter((line) => {
        try {
          return JSON.parse(line).event === "relay_auth_accepted";
        } catch {
          return false;
        }
      }).length;
    const acceptDeadline = Date.now() + 3_000;
    while (acceptedCount() < 1 && Date.now() < acceptDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(acceptedCount(), 1);

    await within(host.emit("session_shutdown"));
    assert.ok(peerClosed);
    await within(peerClosed);
    assert.equal(logs.filter((line) => JSON.parse(line).event === "relay_session_disconnected").length, 1);
    assert.equal(logs.some((line) => line.includes(SECRET)), false);
  } finally {
    console.error = originalConsoleError;
    if (previousURL === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = previousURL;
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
  }
});
