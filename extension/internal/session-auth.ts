import { hostname as operatingSystemHostname } from "node:os";
import { sign, type KeyObject } from "node:crypto";

import WebSocket from "ws";

import { RosterClient, type RosterPage, type SendResult } from "./roster-client.ts";
import { generateUUIDv7 } from "./uuid.ts";

export { generateUUIDv7 } from "./uuid.ts";

const AUTH_TIMEOUT_MS = 5_000;
const CLOSE_TIMEOUT_MS = 1_000;
const AUTH_TRANSCRIPT_DOMAIN = "pi-messaging-relay-auth-v1\n";
const MAX_AUTH_FRAME_BYTES = 16 * 1024;
const MAX_SOCKET_PAYLOAD_BYTES = 512 * 1024;
const MAX_CWD_BYTES = 4096;
const MAX_HOSTNAME_BYTES = 255;
const HEARTBEAT_MS = 30_000;
const MAX_BODY_BYTES = 262_144;

type AuthenticatedConnection = {
  socket: WebSocket;
  address: string;
  list(cursor: string | undefined, signal: AbortSignal): Promise<RosterPage>;
  send(
    to: string,
    body: string | Record<string, unknown>,
    re: string | undefined,
    signal: AbortSignal,
  ): Promise<SendResult>;
  closeAndWait(): Promise<void>;
};

type SessionSocketAttemptOptions = {
  endpoint: URL;
  privateKey: KeyObject;
  clientPublicKey: string;
  routeID: string;
  cwd: string;
  hostname?: string;
  deliverUserMessage(body: string): void;
  onDisconnected(): void;
};

class SessionAuthenticationError extends Error {
  readonly reason: string;

  constructor(reason: string, message: string) {
    super(message);
    this.name = "SessionAuthenticationError";
    this.reason = reason;
  }
}

export class SessionSocketAttempt {
  readonly result: Promise<AuthenticatedConnection>;
  private socket: WebSocket | undefined;
  private settled = false;

  constructor(options: SessionSocketAttemptOptions) {
    this.result = this.connect(options);
  }

  close(): void {
    closeSocket(this.socket);
  }

  private async connect(options: SessionSocketAttemptOptions): Promise<AuthenticatedConnection> {
    const hostname = options.hostname ?? operatingSystemHostname();
    validateDisplayMetadata(options.cwd, MAX_CWD_BYTES, "cwd");
    validateDisplayMetadata(hostname, MAX_HOSTNAME_BYTES, "hostname");
    if (!isUUIDv7(options.routeID)) {
      throw new SessionAuthenticationError("invalid_route_id", "Session route ID is not UUIDv7.");
    }

    const requestID = generateUUIDv7();
    const socket = new WebSocket(options.endpoint, {
      handshakeTimeout: AUTH_TIMEOUT_MS,
      maxPayload: MAX_SOCKET_PAYLOAD_BYTES,
      perMessageDeflate: false,
    });
    this.socket = socket;

    return new Promise<AuthenticatedConnection>((resolve, reject) => {
      let phase: "challenge" | "welcome" = "challenge";
      const timer = setTimeout(() => {
        fail(new SessionAuthenticationError("auth_timeout", "Relay authentication exceeded 5 seconds."));
      }, AUTH_TIMEOUT_MS);

      const cleanHandshakeListeners = () => {
        clearTimeout(timer);
        socket.off("message", onMessage);
        socket.off("error", onError);
        socket.off("close", onPrematureClose);
      };
      const fail = (error: SessionAuthenticationError) => {
        if (this.settled) return;
        this.settled = true;
        cleanHandshakeListeners();
        void closeAndWait(socket).then(() => reject(error));
      };
      const onError = (error: Error & { code?: string }) => {
        const oversized = error.code === "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH";
        fail(new SessionAuthenticationError(
          oversized ? "invalid_frame" : "connection_failed",
          oversized
            ? "Relay authentication transport payload exceeds 512 KiB."
            : "Relay WebSocket connection failed.",
        ));
      };
      const onPrematureClose = () => {
        fail(new SessionAuthenticationError("connection_closed", "Relay closed during authentication."));
      };
      const onMessage = (data: unknown, isBinary: boolean) => {
        try {
          if (isBinary || (!Buffer.isBuffer(data) && typeof data !== "string")) {
            throw new SessionAuthenticationError("invalid_frame", "Relay authentication frame is invalid.");
          }
          const encoded = typeof data === "string" ? Buffer.from(data, "utf8") : data;
          if (encoded.byteLength > MAX_AUTH_FRAME_BYTES) {
            throw new SessionAuthenticationError("invalid_frame", "Relay authentication frame exceeds 16 KiB.");
          }
          const text = new TextDecoder("utf-8", { fatal: true }).decode(encoded);
          const frame = parseJSONObject(text);
          if (phase === "challenge") {
            const challenge = parseChallenge(frame);
            const transcript = helloTranscript(challenge, {
              requestID,
              clientPublicKey: options.clientPublicKey,
              routeID: options.routeID,
              hostname,
              cwd: options.cwd,
            });
            const signature = sign(null, transcript, options.privateKey).toString("base64");
            socket.send(JSON.stringify({
              v: 1,
              type: "hello",
              request_id: requestID,
              payload: {
                client_public_key: options.clientPublicKey,
                route_id: options.routeID,
                hostname,
                cwd: options.cwd,
                signature,
              },
            }));
            phase = "welcome";
            return;
          }

          const address = `${options.cwd}@${hostname}#${options.routeID}`;
          parseWelcome(frame, requestID, address);
          this.settled = true;
          cleanHandshakeListeners();
          const onRetainedError = () => {};
          socket.on("error", onRetainedError);
          socket.once("close", () => {
            socket.off("error", onRetainedError);
            options.onDisconnected();
          });
          const roster = new RosterClient(socket, {
            settle: () => closeAndWait(socket),
            selfAddress: address,
            deliverUserMessage: options.deliverUserMessage,
          });
          resolve({
            socket,
            address,
            list: (cursor, signal) => roster.list(cursor, signal),
            send: (to, body, re, signal) => roster.send(to, body, re, signal),
            closeAndWait: () => closeAndWait(socket),
          });
        } catch (error) {
          fail(error instanceof SessionAuthenticationError
            ? error
            : new SessionAuthenticationError("invalid_response", "Relay authentication response is invalid."));
        }
      };

      socket.on("message", onMessage);
      socket.once("error", onError);
      socket.once("close", onPrematureClose);
    });
  }
}

export function isUUIDv7(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
}

export function helloTranscript(
  nonce: string,
  metadata: {
    requestID: string;
    clientPublicKey: string;
    routeID: string;
    hostname: string;
    cwd: string;
  },
): Buffer {
  const fields: ReadonlyArray<readonly [string, string]> = [
    ["nonce", nonce],
    ["request_id", metadata.requestID],
    ["client_public_key", metadata.clientPublicKey],
    ["route_id", metadata.routeID],
    ["hostname", metadata.hostname],
    ["cwd", metadata.cwd],
  ];
  let transcript = AUTH_TRANSCRIPT_DOMAIN;
  for (const [name, value] of fields) {
    transcript += `${name}:${Buffer.byteLength(value, "utf8")}:${value}\n`;
  }
  return Buffer.from(transcript, "utf8");
}

function parseJSONObject(text: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(text);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new SessionAuthenticationError("invalid_response", "Relay authentication response is not an object.");
  }
  return parsed as Record<string, unknown>;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function parseChallenge(frame: Record<string, unknown>): string {
  if (!hasExactKeys(frame, ["v", "type", "payload"]) || frame.v !== 1 || frame.type !== "challenge") {
    throw new SessionAuthenticationError("invalid_challenge", "Relay challenge envelope is invalid.");
  }
  const payload = frame.payload;
  if (payload === null || typeof payload !== "object" || Array.isArray(payload) ||
      !hasExactKeys(payload as Record<string, unknown>, ["nonce"])) {
    throw new SessionAuthenticationError("invalid_challenge", "Relay challenge payload is invalid.");
  }
  const nonce = (payload as Record<string, unknown>).nonce;
  if (typeof nonce !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(nonce)) {
    throw new SessionAuthenticationError("invalid_challenge", "Relay challenge nonce is invalid.");
  }
  return nonce;
}

function parseWelcome(frame: Record<string, unknown>, requestID: string, address: string): void {
  if (frame.type === "error") {
    const payload = frame.payload as Record<string, unknown> | undefined;
    const reason = payload?.code === "not_authorized" ? "not_authorized" : "authentication_rejected";
    throw new SessionAuthenticationError(reason, "Relay rejected session authentication.");
  }
  if (!hasExactKeys(frame, ["v", "type", "request_id", "payload"]) ||
      frame.v !== 1 || frame.type !== "welcome" || frame.request_id !== requestID) {
    throw new SessionAuthenticationError("invalid_welcome", "Relay welcome envelope is invalid.");
  }
  const payload = frame.payload;
  if (payload === null || typeof payload !== "object" || Array.isArray(payload) ||
      !hasExactKeys(payload as Record<string, unknown>, ["self_address", "heartbeat_ms", "max_body_bytes"])) {
    throw new SessionAuthenticationError("invalid_welcome", "Relay welcome payload is invalid.");
  }
  const welcome = payload as Record<string, unknown>;
  if (welcome.self_address !== address || welcome.heartbeat_ms !== HEARTBEAT_MS ||
      welcome.max_body_bytes !== MAX_BODY_BYTES) {
    throw new SessionAuthenticationError("invalid_welcome", "Relay welcome values do not match this session.");
  }
}

function validateDisplayMetadata(value: string, maximumBytes: number, name: string): void {
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes === 0 || bytes > maximumBytes) {
    throw new SessionAuthenticationError(`invalid_${name}`, `Session ${name} is outside its display limit.`);
  }
}

const socketSettlement = new WeakMap<WebSocket, Promise<void>>();

function closeSocket(socket: WebSocket | undefined): void {
  if (!socket) return;
  void closeAndWait(socket);
}

function closeAndWait(socket: WebSocket): Promise<void> {
  const existing = socketSettlement.get(socket);
  if (existing) return existing;
  if (socket.readyState === WebSocket.CLOSED) return Promise.resolve();

  const settlement = new Promise<void>((resolve) => {
    const ignoreError = () => {};
    let forceTimer: NodeJS.Timeout | undefined;
    const settled = () => {
      if (forceTimer) clearTimeout(forceTimer);
      socket.off("error", ignoreError);
      resolve();
    };
    socket.on("error", ignoreError);
    socket.once("close", settled);

    if (socket.readyState === WebSocket.CONNECTING) {
      socket.terminate();
      return;
    }
    if (socket.readyState === WebSocket.OPEN) {
      try {
        socket.close(1000, "session closed");
      } catch {
        socket.terminate();
        return;
      }
    }
    forceTimer = setTimeout(() => socket.terminate(), CLOSE_TIMEOUT_MS);
  });
  socketSettlement.set(socket, settlement);
  return settlement;
}
