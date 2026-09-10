import assert from "node:assert/strict";
import { createHash, createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { SessionSocketAttempt } from "../internal/session-auth.ts";
import { FakePiHost } from "./fake-pi-host.ts";

const WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const ROUTE_ID = "01993ca1-1111-7aaa-8aaa-111111111111";

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
  const header = payload.length < 126 ? Buffer.alloc(2) : Buffer.alloc(4);
  header[0] = (fin ? 0x80 : 0) | opcode;
  if (payload.length < 126) {
    header[1] = payload.length;
  } else {
    header[1] = 126;
    header.writeUInt16BE(payload.length, 2);
  }
  return Buffer.concat([header, payload]);
}

async function startRawEndpoint(onUpgrade: (peer: RawPeer) => void): Promise<{
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
      const accept = createHash("sha1").update(key + WEBSOCKET_GUID).digest("base64");
      socket.write(
        "HTTP/1.1 101 Switching Protocols\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
      );
      onUpgrade(new RawPeer(socket, request.subarray(boundary + 4)));
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

function installationFixture(): { privateKey: KeyObject; publicKey: string } {
  const privateKey = generateKeyPairSync("ed25519").privateKey;
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  assert.equal(typeof jwk.x, "string");
  return {
    privateKey,
    publicKey: `ed25519:${Buffer.from(jwk.x as string, "base64url").toString("base64")}`,
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

test("fragmented authentication payload over 16 KiB is rejected and force-settled when peer ignores close", async (context) => {
  let peerClosed: Promise<void> | undefined;
  const endpoint = await startRawEndpoint((peer) => {
    peerClosed = peer.closed;
    const fragment = "x".repeat(4_096);
    peer.sendText(fragment, { fin: false, opcode: 0x1 });
    peer.sendText(fragment, { fin: false, opcode: 0x0 });
    peer.sendText(fragment, { fin: false, opcode: 0x0 });
    peer.sendText(fragment, { fin: false, opcode: 0x0 });
    peer.sendText("x", { fin: true, opcode: 0x0 });
    // Deliberately ignore the client's close frame.
  });
  context.after(async () => closeServer(endpoint.server));
  const installation = installationFixture();
  const attempt = new SessionSocketAttempt({
    endpoint: endpoint.endpoint,
    privateKey: installation.privateKey,
    clientPublicKey: installation.publicKey,
    routeID: ROUTE_ID,
    cwd: "/oversized",
    hostname: "malicious-endpoint",
    onDisconnected: () => {},
  });

  await assert.rejects(within(attempt.result), (error: unknown) =>
    error !== null && typeof error === "object" && "reason" in error && error.reason === "invalid_frame");
  assert.ok(peerClosed);
  await within(peerClosed);
});

test("production session_shutdown force-settles retained socket when peer ignores close", async (context) => {
  let peerClosed: Promise<void> | undefined;
  const endpoint = await startRawEndpoint((peer) => {
    peerClosed = peer.closed;
    peer.sendText(JSON.stringify({
      v: 1,
      type: "challenge",
      payload: { nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
    }));
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
  const stateDirectory = join(root, "state");
  await mkdir(stateDirectory, { mode: 0o700 });
  await chmod(stateDirectory, 0o700);
  const installation = installationFixture();
  const privatePEM = installation.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  await writeFile(join(stateDirectory, "installation-ed25519.pem"), privatePEM, { mode: 0o600 });
  context.after(async () => rm(root, { recursive: true, force: true }));

  const previousURL = process.env.PI_MESSAGING_RELAY_URL;
  const previousState = process.env.PI_MESSAGING_RELAY_STATE_DIR;
  const originalConsoleError = console.error;
  const logs: string[] = [];
  process.env.PI_MESSAGING_RELAY_URL = endpoint.endpoint.href.replace(/^ws:/, "http:");
  process.env.PI_MESSAGING_RELAY_STATE_DIR = stateDirectory;
  console.error = (...values: unknown[]) => logs.push(values.map(String).join(" "));
  try {
    const host = new FakePiHost();
    const relayExtension = (await import(`../index.ts?hostile-shutdown=${Date.now()}`)).default;
    relayExtension(host.api as never);
    await within(host.emit("session_start"));
    assert.equal(logs.filter((line) => JSON.parse(line).event === "relay_auth_accepted").length, 1);

    await within(host.emit("session_shutdown"));
    assert.ok(peerClosed);
    await within(peerClosed);
    assert.equal(logs.filter((line) => JSON.parse(line).event === "relay_session_disconnected").length, 1);
    assert.equal(logs.some((line) => line.includes(privatePEM.trim())), false);
  } finally {
    console.error = originalConsoleError;
    if (previousURL === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = previousURL;
    if (previousState === undefined) delete process.env.PI_MESSAGING_RELAY_STATE_DIR;
    else process.env.PI_MESSAGING_RELAY_STATE_DIR = previousState;
  }
});
