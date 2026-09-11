import WebSocket from "ws";

import { generateUUIDv7 } from "./uuid.ts";

const MAX_ROSTER_FRAME_BYTES = 48 * 1024;
const MAX_ADDRESS_BYTES = 4_389;
const MAX_CURSOR_CHARACTERS = 5_856;
const DEFAULT_RESPONSE_TIMEOUT_MS = 5_000;

/** Stable local list failure with a telemetry-safe reason. */
export class RosterRequestError extends Error {
  readonly reason: string;

  constructor(reason: string, message: string) {
    super(message);
    this.name = "RosterRequestError";
    this.reason = reason;
  }
}

/** Closed address-only page returned by one correlated roster response. */
export type RosterPage = {
  peers: Array<{ address: string }>;
  next_cursor?: string;
};

type PendingList = {
  requestID: string;
  resolve(page: RosterPage): void;
  reject(error: Error): void;
  timer: NodeJS.Timeout;
  signal: AbortSignal;
  onAbort(): void;
};

type RosterClientOptions = {
  responseTimeoutMS?: number;
  settle?: () => Promise<void>;
};

/** Single-flight roster request owner for one authenticated retained socket. */
export class RosterClient {
  private readonly socket: WebSocket;
  private readonly responseTimeoutMS: number;
  private readonly settle: () => Promise<void>;
  private pending: PendingList | undefined;
  private terminal = false;

  constructor(socket: WebSocket, options: RosterClientOptions = {}) {
    this.socket = socket;
    this.responseTimeoutMS = options.responseTimeoutMS ?? DEFAULT_RESPONSE_TIMEOUT_MS;
    this.settle = options.settle ?? (() => terminateAndWait(socket));
    socket.on("message", this.onMessage);
    socket.on("error", this.onError);
    socket.once("close", this.onClose);
  }

  list(cursor: string | undefined, signal: AbortSignal): Promise<RosterPage> {
    if (this.terminal || this.socket.readyState !== WebSocket.OPEN) {
      return Promise.reject(new RosterRequestError("disconnected", "Relay disconnected during list_peers."));
    }
    if (this.pending) {
      return Promise.reject(new RosterRequestError(
        "concurrent_request",
        "Relay list_peers already has one request in flight.",
      ));
    }
    if (signal.aborted) {
      return Promise.reject(new RosterRequestError("aborted", "Relay list_peers request was aborted."));
    }

    const requestID = generateUUIDv7();
    return new Promise<RosterPage>((resolve, reject) => {
      const onAbort = () => {
        void this.failTerminal(new RosterRequestError("aborted", "Relay list_peers request was aborted."));
      };
      const timer = setTimeout(() => {
        void this.failTerminal(new RosterRequestError("timeout", "Relay list_peers response timed out."));
      }, this.responseTimeoutMS);
      this.pending = { requestID, resolve, reject, timer, signal, onAbort };
      signal.addEventListener("abort", onAbort, { once: true });

      const frame = JSON.stringify({
        v: 1,
        type: "list",
        request_id: requestID,
        payload: cursor === undefined ? {} : { cursor },
      });
      try {
        this.socket.send(frame, (error) => {
          if (error) void this.failTerminal(new RosterRequestError(
            "disconnected",
            "Relay disconnected during list_peers.",
          ));
        });
      } catch {
        void this.failTerminal(new RosterRequestError("disconnected", "Relay disconnected during list_peers."));
      }
    });
  }

  private readonly onMessage = (data: WebSocket.RawData, isBinary: boolean): void => {
    const pending = this.pending;
    if (!pending) {
      void this.failTerminal();
      return;
    }
    try {
      if (isBinary || !Buffer.isBuffer(data) || data.byteLength > MAX_ROSTER_FRAME_BYTES) {
        throw new Error("invalid roster frame");
      }
      const text = new TextDecoder("utf-8", { fatal: true }).decode(data);
      const page = parseRoster(text, pending.requestID);
      this.clearPending();
      pending.resolve(page);
    } catch {
      void this.failTerminal(new RosterRequestError(
        "invalid_response",
        "Relay returned an invalid list_peers response.",
      ));
    }
  };

  private readonly onError = (error: Error & { code?: string }): void => {
    const invalidFrame = error.code === "WS_ERR_INVALID_UTF8" ||
      error.code === "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH";
    void this.failTerminal(invalidFrame
      ? new RosterRequestError("invalid_response", "Relay returned an invalid list_peers response.")
      : new RosterRequestError("disconnected", "Relay disconnected during list_peers."));
  };

  private readonly onClose = (): void => {
    this.terminal = true;
    this.socket.off("message", this.onMessage);
    this.socket.off("error", this.onError);
    const pending = this.pending;
    if (!pending) return;
    this.clearPending();
    pending.reject(new RosterRequestError("disconnected", "Relay disconnected during list_peers."));
  };

  private clearPending(): void {
    const pending = this.pending;
    if (!pending) return;
    clearTimeout(pending.timer);
    pending.signal.removeEventListener("abort", pending.onAbort);
    this.pending = undefined;
  }

  private async failTerminal(error?: Error): Promise<void> {
    if (this.terminal) return;
    this.terminal = true;
    const pending = this.pending;
    this.clearPending();
    try {
      await this.settle();
    } finally {
      if (pending && error) pending.reject(error);
    }
  }
}

function parseRoster(text: string, requestID: string): RosterPage {
  assertUnambiguousJSON(text);
  const parsed: unknown = JSON.parse(text);
  if (!isObject(parsed) || !hasExactKeys(parsed, ["v", "type", "request_id", "payload"]) ||
      parsed.v !== 1 || parsed.type !== "roster" || parsed.request_id !== requestID) {
    throw new Error("invalid roster envelope");
  }
  const payload = parsed.payload;
  if (!isObject(payload) ||
      (!hasExactKeys(payload, ["peers"]) && !hasExactKeys(payload, ["peers", "next_cursor"])) ||
      !Array.isArray(payload.peers)) {
    throw new Error("invalid roster payload");
  }
  const peers = payload.peers.map((candidate) => {
    if (!isObject(candidate) || !hasExactKeys(candidate, ["address"]) ||
        typeof candidate.address !== "string" || !validOpaqueString(candidate.address, MAX_ADDRESS_BYTES)) {
      throw new Error("invalid roster peer");
    }
    return { address: candidate.address };
  });
  if ("next_cursor" in payload) {
    if (typeof payload.next_cursor !== "string" || !validCursor(payload.next_cursor)) {
      throw new Error("invalid roster cursor");
    }
    return { peers, next_cursor: payload.next_cursor };
  }
  return { peers };
}

function validCursor(cursor: string): boolean {
  if (cursor.length <= 4 || cursor.length > MAX_CURSOR_CHARACTERS || !/^cur_[A-Za-z0-9_-]+$/.test(cursor)) {
    return false;
  }
  const encoded = cursor.slice(4);
  const decoded = Buffer.from(encoded, "base64url");
  return decoded.byteLength > 0 && decoded.byteLength <= MAX_ADDRESS_BYTES &&
    decoded.toString("base64url") === encoded &&
    validUTF8(decoded);
}

function validOpaqueString(value: string, maximumBytes: number): boolean {
  if (value.length === 0) return false;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return Buffer.byteLength(value, "utf8") <= maximumBytes;
}

function validUTF8(value: Buffer): boolean {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(value);
    return true;
  } catch {
    return false;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function assertUnambiguousJSON(text: string): void {
  let cursor = 0;
  const whitespace = () => {
    while (cursor < text.length && /[\t\n\r ]/.test(text[cursor])) cursor += 1;
  };
  const string = (): string => {
    const start = cursor;
    if (text[cursor++] !== '"') throw new Error("string required");
    while (cursor < text.length) {
      const character = text[cursor++];
      if (character === '"') return JSON.parse(text.slice(start, cursor)) as string;
      if (character.charCodeAt(0) < 0x20) throw new Error("invalid control character");
      if (character !== "\\") continue;
      const escape = text[cursor++];
      if ('"\\/bfnrt'.includes(escape)) continue;
      if (escape !== "u" || !/^[0-9a-fA-F]{4}$/.test(text.slice(cursor, cursor + 4))) {
        throw new Error("invalid string escape");
      }
      cursor += 4;
    }
    throw new Error("unterminated string");
  };
  const value = (depth: number): void => {
    whitespace();
    if (depth > 64) throw new Error("JSON nesting exceeds limit");
    if (text[cursor] === "{") {
      cursor += 1;
      whitespace();
      const fields = new Set<string>();
      if (text[cursor] !== "}") {
        while (true) {
          const name = string();
          if (fields.has(name)) throw new Error("duplicate field");
          fields.add(name);
          whitespace();
          if (text[cursor++] !== ":") throw new Error("field separator required");
          value(depth + 1);
          whitespace();
          if (text[cursor] === "}") break;
          if (text[cursor++] !== ",") throw new Error("object separator required");
          whitespace();
        }
      }
      cursor += 1;
      return;
    }
    if (text[cursor] === "[") {
      cursor += 1;
      whitespace();
      if (text[cursor] !== "]") {
        while (true) {
          value(depth + 1);
          whitespace();
          if (text[cursor] === "]") break;
          if (text[cursor++] !== ",") throw new Error("array separator required");
        }
      }
      cursor += 1;
      return;
    }
    if (text[cursor] === '"') {
      string();
      return;
    }
    const scalar = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(cursor));
    if (!scalar) throw new Error("invalid scalar");
    cursor += scalar[0].length;
  };

  whitespace();
  value(1);
  whitespace();
  if (cursor !== text.length) throw new Error("trailing JSON");
}

function terminateAndWait(socket: WebSocket): Promise<void> {
  if (socket.readyState === WebSocket.CLOSED) return Promise.resolve();
  return new Promise((resolve) => {
    socket.once("close", () => resolve());
    socket.terminate();
  });
}
