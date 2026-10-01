import { hostname as operatingSystemHostname } from "node:os";

import WebSocket from "ws";

import { RosterClient, type RosterPage, type SendResult } from "./roster-client.ts";
import { generateUUIDv7 } from "./uuid.ts";

export { generateUUIDv7 } from "./uuid.ts";

const ESTABLISHMENT_TIMEOUT_MS = 5_000;
const CLOSE_TIMEOUT_MS = 1_000;
const MAX_ESTABLISHMENT_FRAME_BYTES = 16 * 1024;
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
  secret: string | undefined;
  routeID: string;
  cwd: string;
  hostname?: string;
  deliverUserMessage(body: string): void;
  onDisconnected(): void;
};

class SessionEstablishmentError extends Error {
  readonly reason: string;

  constructor(reason: string, message: string) {
    super(message);
    this.name = "SessionEstablishmentError";
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
      throw new SessionEstablishmentError("invalid_route_id", "Session route ID is not UUIDv7.");
    }

    const requestID = generateUUIDv7();
    const socket = new WebSocket(options.endpoint, {
      handshakeTimeout: ESTABLISHMENT_TIMEOUT_MS,
      // The secret is the only credential and is checked at the HTTP upgrade; the
      // post-upgrade hello is unsigned display metadata.
      headers: options.secret === undefined ? {} : { Authorization: `Bearer ${options.secret}` },
      maxPayload: MAX_SOCKET_PAYLOAD_BYTES,
      perMessageDeflate: false,
    });
    this.socket = socket;

    return new Promise<AuthenticatedConnection>((resolve, reject) => {
      const timer = setTimeout(() => {
        fail(new SessionEstablishmentError(
          "auth_timeout",
          "Relay session establishment exceeded 5 seconds.",
        ));
      }, ESTABLISHMENT_TIMEOUT_MS);

      const cleanHandshakeListeners = () => {
        clearTimeout(timer);
        socket.off("open", onOpen);
        socket.off("message", onMessage);
        socket.off("error", onError);
        socket.off("close", onPrematureClose);
      };
      const fail = (error: SessionEstablishmentError) => {
        if (this.settled) return;
        this.settled = true;
        cleanHandshakeListeners();
        void closeAndWait(socket).then(() => reject(error));
      };
      const onError = (error: Error & { code?: string }) => {
        const oversized = error.code === "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH";
        // One closed HTTP 401 spelling covers missing, malformed, and wrong Bearer
        // credentials; reconnect code sees one ordinary failed upgrade.
        const unauthorized = /^Unexpected server response: 401$/.test(error.message);
        fail(new SessionEstablishmentError(
          unauthorized ? "not_authorized" : oversized ? "invalid_frame" : "connection_failed",
          unauthorized
            ? "Relay rejected the upgrade credentials."
            : oversized
              ? "Relay session establishment transport payload exceeds 512 KiB."
              : "Relay WebSocket connection failed.",
        ));
      };
      const onPrematureClose = () => {
        fail(new SessionEstablishmentError(
          "connection_closed",
          "Relay closed during session establishment.",
        ));
      };
      const onOpen = () => {
        try {
          socket.send(JSON.stringify({
            v: 1,
            type: "hello",
            request_id: requestID,
            payload: {
              route_id: options.routeID,
              hostname,
              cwd: options.cwd,
            },
          }));
        } catch (error) {
          fail(error instanceof SessionEstablishmentError
            ? error
            : new SessionEstablishmentError(
              "connection_closed",
              "Relay closed before the hello was written.",
            ));
        }
      };
      const onMessage = (data: unknown, isBinary: boolean) => {
        try {
          if (isBinary || (!Buffer.isBuffer(data) && typeof data !== "string")) {
            throw new SessionEstablishmentError("invalid_frame", "Relay establishment frame is invalid.");
          }
          const encoded = typeof data === "string" ? Buffer.from(data, "utf8") : data;
          if (encoded.byteLength > MAX_ESTABLISHMENT_FRAME_BYTES) {
            throw new SessionEstablishmentError(
              "invalid_frame",
              "Relay session establishment frame exceeds 16 KiB.",
            );
          }
          const text = new TextDecoder("utf-8", { fatal: true }).decode(encoded);
          const frame = parseJSONObject(text);

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
          fail(error instanceof SessionEstablishmentError
            ? error
            : new SessionEstablishmentError(
              "invalid_response",
              "Relay session establishment response is invalid.",
            ));
        }
      };

      socket.once("open", onOpen);
      socket.on("message", onMessage);
      socket.once("error", onError);
      socket.once("close", onPrematureClose);
    });
  }
}

export function isUUIDv7(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
}

function parseJSONObject(text: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(text);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new SessionEstablishmentError(
      "invalid_response",
      "Relay session establishment response is not an object.",
    );
  }
  return parsed as Record<string, unknown>;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function parseWelcome(frame: Record<string, unknown>, requestID: string, address: string): void {
  if (!hasExactKeys(frame, ["v", "type", "request_id", "payload"]) ||
      frame.v !== 1 || frame.type !== "welcome" || frame.request_id !== requestID) {
    throw new SessionEstablishmentError("invalid_welcome", "Relay welcome envelope is invalid.");
  }
  const payload = frame.payload;
  if (payload === null || typeof payload !== "object" || Array.isArray(payload) ||
      !hasExactKeys(payload as Record<string, unknown>, ["self_address", "heartbeat_ms", "max_body_bytes"])) {
    throw new SessionEstablishmentError("invalid_welcome", "Relay welcome payload is invalid.");
  }
  const welcome = payload as Record<string, unknown>;
  if (welcome.self_address !== address || welcome.heartbeat_ms !== HEARTBEAT_MS ||
      welcome.max_body_bytes !== MAX_BODY_BYTES) {
    throw new SessionEstablishmentError("invalid_welcome", "Relay welcome values do not match this session.");
  }
}

function validateDisplayMetadata(value: string, maximumBytes: number, name: string): void {
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes === 0 || bytes > maximumBytes) {
    throw new SessionEstablishmentError(
      `invalid_${name}`,
      `Session ${name} is outside its display limit.`,
    );
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
