import WebSocket from "ws";

import {
  canonicalCompactJSON,
  CanonicalJSONError,
  renderRelayMessage,
  type JSONObject,
} from "./message-renderer.ts";
import { generateUUIDv7 } from "./uuid.ts";

const MAX_ROSTER_FRAME_BYTES = 48 * 1024;
const MAX_FRAME_BYTES = 512 * 1024;
const MAX_ADDRESS_BYTES = 4_389;
const MAX_CURSOR_CHARACTERS = 5_856;
const DEFAULT_LIST_RESPONSE_TIMEOUT_MS = 5_000;
// ponytail: fixed to 8s; make configurable when another production deadline profile exists.
const DEFAULT_SEND_RESPONSE_TIMEOUT_MS = 8_000;
// ponytail: fixed to 4s; revisit only when another measured transport deadline profile exists.
const DEFAULT_SEND_RETRY_DELAY_MS = 4_000;

/** Stable local retained-socket failure with a telemetry-safe reason. */
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

/** Closed model-visible result returned by one correlated send response. */
export type SendResult =
  | { message_id: string; status: "received" }
  | { message_id: string; status: "timeout"; reason: "offline" }
  | { message_id: string; status: "timeout"; reason: "ack_timeout" }
  | { message_id: string; status: "timeout"; reason: "recipient_disconnected" }
  | { message_id: string; status: "denied"; reason: "message_id_conflict" };

type ResponseDeadline = {
  cancel(): void;
};

type ResponseDeadlineFactory = (expire: () => void, durationMS: number) => ResponseDeadline;

type PendingOperation = {
  kind: "list" | "send";
  requestID: string;
  retryRequestID?: string;
  messageID?: string;
  retryFrame?: (requestID: string) => string;
  firstWriteCompleted: boolean;
  resolve(value: RosterPage | SendResult): void;
  reject(error: Error): void;
  deadline: ResponseDeadline;
  retryDeadline?: ResponseDeadline;
  signal: AbortSignal;
  onAbort(): void;
};

type LateSendResponse = {
  requestID: string;
  messageID: string;
  result: SendResult;
};

type RosterClientOptions = {
  responseTimeoutMS?: number;
  responseDeadlineFactory?: ResponseDeadlineFactory;
  retryDeadlineFactory?: ResponseDeadlineFactory;
  settle?: () => Promise<void>;
  selfAddress?: string;
  deliverUserMessage?: (body: string) => void;
};

/** Single-flight operation and inbound-delivery owner for one authenticated socket. */
export class RosterClient {
  private readonly socket: WebSocket;
  private readonly responseTimeoutMS: number | undefined;
  private readonly responseDeadlineFactory: ResponseDeadlineFactory;
  private readonly retryDeadlineFactory: ResponseDeadlineFactory;
  private readonly settle: () => Promise<void>;
  private readonly selfAddress: string | undefined;
  private readonly deliverUserMessage: ((body: string) => void) | undefined;
  private pending: PendingOperation | undefined;
  private terminal = false;
  private inboundProcessing = false;
  private writeInFlight: Promise<void> | undefined;
  private lateSendResponse: LateSendResponse | undefined;

  constructor(socket: WebSocket, options: RosterClientOptions = {}) {
    this.socket = socket;
    this.responseTimeoutMS = options.responseTimeoutMS;
    this.responseDeadlineFactory = options.responseDeadlineFactory ?? startResponseDeadline;
    this.retryDeadlineFactory = options.retryDeadlineFactory ?? startResponseDeadline;
    this.settle = options.settle ?? (() => terminateAndWait(socket));
    this.selfAddress = options.selfAddress;
    this.deliverUserMessage = options.deliverUserMessage;
    socket.on("message", this.onMessage);
    socket.on("error", this.onError);
    socket.once("close", this.onClose);
  }

  list(cursor: string | undefined, signal: AbortSignal): Promise<RosterPage> {
    const requestID = generateUUIDv7();
    const frame = JSON.stringify({
      v: 1,
      type: "list",
      request_id: requestID,
      payload: cursor === undefined ? {} : { cursor },
    });
    return this.beginOperation("list", requestID, undefined, frame, signal) as Promise<RosterPage>;
  }

  send(
    to: string,
    body: string | Record<string, unknown>,
    re: string | undefined,
    signal: AbortSignal,
  ): Promise<SendResult> {
    if (!validOpaqueString(to, MAX_ADDRESS_BYTES) ||
        (typeof body !== "string" && !isObject(body)) ||
        (typeof body === "string" && !validText(body)) ||
        (re !== undefined && !isUUIDv7(re))) {
      return Promise.reject(new RosterRequestError("invalid_arguments", "Relay agent_send arguments are invalid."));
    }
    let encodedBody: string;
    try {
      encodedBody = canonicalCompactJSON(body, maximumSendBodyBytes(to, re));
    } catch (error) {
      if (error instanceof CanonicalJSONError && error.failure === "maximum_bytes") {
        return Promise.reject(new RosterRequestError(
          "invalid_arguments",
          "Relay agent_send frame exceeds 512 KiB.",
        ));
      }
      return Promise.reject(new RosterRequestError(
        "invalid_arguments",
        "Relay agent_send body is not safe JSON.",
      ));
    }
    const requestID = generateUUIDv7();
    const messageID = generateUUIDv7();
    const encodedRe = re === undefined ? "" : `,"re":${JSON.stringify(re)}`;
    const immutablePayload = `{"message_id":${JSON.stringify(messageID)},"to":${JSON.stringify(to)},` +
      `"body":${encodedBody}${encodedRe}}`;
    const makeFrame = (frameRequestID: string) =>
      `{"v":1,"type":"send","request_id":${JSON.stringify(frameRequestID)},"payload":${immutablePayload}}`;
    const frame = makeFrame(requestID);
    if (Buffer.byteLength(frame, "utf8") > MAX_FRAME_BYTES) {
      return Promise.reject(new RosterRequestError("invalid_arguments", "Relay agent_send frame exceeds 512 KiB."));
    }
    return this.beginOperation("send", requestID, messageID, frame, signal, makeFrame) as Promise<SendResult>;
  }

  private beginOperation(
    kind: "list" | "send",
    requestID: string,
    messageID: string | undefined,
    frame: string,
    signal: AbortSignal,
    retryFrame?: (requestID: string) => string,
  ): Promise<RosterPage | SendResult> {
    if (this.terminal || this.socket.readyState !== WebSocket.OPEN) {
      return Promise.reject(this.operationError(kind, "disconnected"));
    }
    if (this.pending || this.writeInFlight) {
      const operation = kind === "list" ? "list_peers" : "agent_send";
      return Promise.reject(new RosterRequestError(
        "concurrent_request",
        `Relay ${operation} already has one request in flight.`,
      ));
    }
    if (signal.aborted) {
      return Promise.reject(this.operationError(kind, "aborted"));
    }

    return new Promise<RosterPage | SendResult>((resolve, reject) => {
      const onAbort = () => void this.failTerminal(this.operationError(kind, "aborted"));
      const pending: PendingOperation = {
        kind,
        requestID,
        messageID,
        retryFrame,
        firstWriteCompleted: false,
        resolve,
        reject,
        deadline: { cancel: () => undefined },
        signal,
        onAbort,
      };
      this.pending = pending;
      signal.addEventListener("abort", onAbort, { once: true });

      const timeoutMS = this.responseTimeoutMS ?? (kind === "list"
        ? DEFAULT_LIST_RESPONSE_TIMEOUT_MS
        : DEFAULT_SEND_RESPONSE_TIMEOUT_MS);
      let deadline: ResponseDeadline;
      try {
        deadline = this.responseDeadlineFactory(() => {
          void this.failTerminal(this.operationError(kind, "timeout"));
        }, timeoutMS);
        if (!deadline || typeof deadline.cancel !== "function") throw new Error("invalid response deadline");
      } catch {
        void this.failTerminal(this.operationError(kind, "disconnected"));
        return;
      }
      if (this.pending !== pending) {
        cancelResponseDeadline(deadline);
        return;
      }
      pending.deadline = deadline;
      if (kind === "send") {
        try {
          pending.retryDeadline = this.retryDeadlineFactory(
            () => this.retrySend(pending),
            DEFAULT_SEND_RETRY_DELAY_MS,
          );
          if (!pending.retryDeadline || typeof pending.retryDeadline.cancel !== "function") {
            throw new Error("invalid retry deadline");
          }
        } catch {
          void this.failTerminal(this.operationError(kind, "disconnected"));
          return;
        }
      }
      void this.write(frame).then(() => {
        pending.firstWriteCompleted = true;
      }).catch(() => {
        void this.failTerminal(this.operationError(kind, "disconnected"));
      });
    });
  }

  private readonly onMessage = (data: WebSocket.RawData, isBinary: boolean): void => {
    try {
      if (isBinary || !Buffer.isBuffer(data) || data.byteLength > MAX_FRAME_BYTES) {
        throw new Error("invalid relay frame");
      }
      const text = new TextDecoder("utf-8", { fatal: true }).decode(data);
      assertUnambiguousJSON(text);
      const parsed: unknown = JSON.parse(text);
      if (!isObject(parsed) || parsed.v !== 1 || typeof parsed.type !== "string") {
        throw new Error("invalid relay envelope");
      }
      if (parsed.type === "message") {
        if (this.inboundProcessing) throw new Error("concurrent inbound delivery");
        const delivery = parseMessage(parsed, this.selfAddress, this.deliverUserMessage);
        const renderedBody = renderRelayMessage(delivery);
        this.inboundProcessing = true;
        void this.acceptDelivery(delivery, renderedBody);
        return;
      }

      const late = this.lateSendResponse;
      if (late && parsed.request_id === late.requestID) {
        const result = parseSendResult(parsed, late.requestID, late.messageID);
        if (JSON.stringify(result) !== JSON.stringify(late.result)) {
          throw new Error("conflicting paired send result");
        }
        this.lateSendResponse = undefined;
        return;
      }

      const pending = this.pending;
      if (!pending) throw new Error("unsolicited relay response");
      let result: RosterPage | SendResult;
      if (pending.kind === "list") {
        if (data.byteLength > MAX_ROSTER_FRAME_BYTES) throw new Error("oversized roster frame");
        result = parseRoster(parsed, pending.requestID);
      } else {
        const responseRequestID = typeof parsed.request_id === "string" ? parsed.request_id : "";
        if (responseRequestID !== pending.requestID && responseRequestID !== pending.retryRequestID) {
          throw new Error("invalid send result correlation");
        }
        result = parseSendResult(parsed, responseRequestID, pending.messageID as string);
        const pairedRequestID = responseRequestID === pending.requestID
          ? pending.retryRequestID
          : pending.requestID;
        if (pairedRequestID) {
          if (this.lateSendResponse) throw new Error("paired response drain capacity reached");
          this.lateSendResponse = {
            requestID: pairedRequestID,
            messageID: pending.messageID as string,
            result,
          };
        }
      }
      this.clearPending();
      pending.resolve(result);
    } catch {
      const pending = this.pending;
      void this.failTerminal(pending
        ? this.operationError(pending.kind, "invalid_response")
        : undefined);
    }
  };

  private retrySend(pending: PendingOperation): void {
    if (this.pending !== pending || pending.kind !== "send" || !pending.firstWriteCompleted ||
        this.writeInFlight || this.terminal || this.socket.readyState !== WebSocket.OPEN || !pending.retryFrame) {
      return;
    }
    const requestID = generateUUIDv7();
    pending.retryRequestID = requestID;
    void this.write(pending.retryFrame(requestID)).catch(() => {
      void this.failTerminal(this.operationError("send", "disconnected"));
    });
  }

  private async acceptDelivery(delivery: InboundDelivery, renderedBody: string): Promise<void> {
    try {
      try {
        this.deliverUserMessage?.(renderedBody);
      } catch {
        // received is attempt-at-extension-boundary only; Pi exposes no stronger receipt.
      }
      await this.write(JSON.stringify({
        v: 1,
        type: "received",
        request_id: generateUUIDv7(),
        payload: {
          delivery_id: delivery.deliveryID,
          message_id: delivery.messageID,
        },
      }));
      this.inboundProcessing = false;
    } catch {
      await this.failTerminal();
    }
  }

  private write(frame: string): Promise<void> {
    const waitFor = this.writeInFlight ?? Promise.resolve();
    const write = waitFor.then(() => new Promise<void>((resolve, reject) => {
      if (this.terminal || this.socket.readyState !== WebSocket.OPEN) {
        reject(new Error("socket closed"));
        return;
      }
      try {
        this.socket.send(frame, (error) => error ? reject(error) : resolve());
      } catch (error) {
        reject(error);
      }
    }));
    const tracked = write.finally(() => {
      if (this.writeInFlight === tracked) this.writeInFlight = undefined;
    });
    this.writeInFlight = tracked;
    return tracked;
  }

  private readonly onError = (error: Error & { code?: string }): void => {
    const invalidFrame = error.code === "WS_ERR_INVALID_UTF8" ||
      error.code === "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH";
    const pending = this.pending;
    void this.failTerminal(pending
      ? this.operationError(pending.kind, invalidFrame ? "invalid_response" : "disconnected")
      : undefined);
  };

  private readonly onClose = (): void => {
    this.terminal = true;
    this.socket.off("message", this.onMessage);
    this.socket.off("error", this.onError);
    const pending = this.pending;
    if (!pending) return;
    this.clearPending();
    pending.reject(this.operationError(pending.kind, "disconnected"));
  };

  private clearPending(): void {
    const pending = this.pending;
    if (!pending) return;
    cancelResponseDeadline(pending.deadline);
    if (pending.retryDeadline) cancelResponseDeadline(pending.retryDeadline);
    pending.signal.removeEventListener("abort", pending.onAbort);
    this.pending = undefined;
  }

  private operationError(kind: "list" | "send", reason: string): RosterRequestError {
    const operation = kind === "list" ? "list_peers" : "agent_send";
    const messages: Record<string, string> = {
      aborted: `Relay ${operation} request was aborted.`,
      timeout: `Relay ${operation} response timed out.`,
      invalid_response: `Relay returned an invalid ${operation} response.`,
      disconnected: `Relay disconnected during ${operation}.`,
    };
    return new RosterRequestError(reason, messages[reason] ?? `Relay ${operation} failed.`);
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

type InboundDelivery = {
  deliveryID: string;
  messageID: string;
  from: string;
  re?: string;
  body: string | JSONObject;
};

function parseMessage(
  frame: Record<string, unknown>,
  selfAddress: string | undefined,
  deliver: ((body: string) => void) | undefined,
): InboundDelivery {
  if (!hasExactKeys(frame, ["v", "type", "payload"]) || !selfAddress || !deliver) {
    throw new Error("unsolicited message envelope");
  }
  const payload = frame.payload;
  if (!isObject(payload) ||
      (!hasExactKeys(payload, ["delivery_id", "message_id", "from", "to", "body"]) &&
       !hasExactKeys(payload, ["delivery_id", "message_id", "from", "to", "body", "re"]))) {
    throw new Error("invalid message payload");
  }
  if (typeof payload.delivery_id !== "string" || !isUUIDv7(payload.delivery_id) ||
      typeof payload.message_id !== "string" || !isUUIDv7(payload.message_id) ||
      typeof payload.from !== "string" || !validOpaqueString(payload.from, MAX_ADDRESS_BYTES) ||
      typeof payload.to !== "string" || !validOpaqueString(payload.to, MAX_ADDRESS_BYTES) ||
      payload.to !== selfAddress ||
      ("re" in payload && (typeof payload.re !== "string" || !isUUIDv7(payload.re)))) {
    throw new Error("invalid message correlation");
  }
  if ((typeof payload.body !== "string" && !isObject(payload.body)) ||
      (typeof payload.body === "string" && !validText(payload.body))) {
    throw new Error("invalid message body");
  }
  return {
    deliveryID: payload.delivery_id,
    messageID: payload.message_id,
    from: payload.from,
    ...("re" in payload ? { re: payload.re as string } : {}),
    body: payload.body as string | JSONObject,
  };
}

function parseRoster(frame: Record<string, unknown>, requestID: string): RosterPage {
  if (!hasExactKeys(frame, ["v", "type", "request_id", "payload"]) ||
      frame.type !== "roster" || frame.request_id !== requestID) {
    throw new Error("invalid roster envelope");
  }
  const payload = frame.payload;
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

function parseSendResult(frame: Record<string, unknown>, requestID: string, messageID: string): SendResult {
  if (!hasExactKeys(frame, ["v", "type", "request_id", "payload"]) ||
      frame.type !== "send_result" || frame.request_id !== requestID) {
    throw new Error("invalid send result envelope");
  }
  const payload = frame.payload;
  if (!isObject(payload) || payload.message_id !== messageID) {
    throw new Error("invalid send result payload");
  }
  if (hasExactKeys(payload, ["message_id", "status"]) && payload.status === "received") {
    return { message_id: messageID, status: "received" };
  }
  if (hasExactKeys(payload, ["message_id", "status", "reason"]) &&
      payload.status === "timeout" &&
      (payload.reason === "offline" ||
       payload.reason === "ack_timeout" ||
       payload.reason === "recipient_disconnected")) {
    return { message_id: messageID, status: "timeout", reason: payload.reason };
  }
  if (hasExactKeys(payload, ["message_id", "status", "reason"]) &&
      payload.status === "denied" && payload.reason === "message_id_conflict") {
    return { message_id: messageID, status: "denied", reason: "message_id_conflict" };
  }
  throw new Error("invalid send result payload");
}

function maximumSendBodyBytes(to: string, re: string | undefined): number {
  const uuidPlaceholder = "00000000-0000-7000-8000-000000000000";
  const encodedRe = re === undefined ? "" : `,"re":${JSON.stringify(re)}`;
  const frameWithoutBody = `{"v":1,"type":"send","request_id":${JSON.stringify(uuidPlaceholder)},` +
    `"payload":{"message_id":${JSON.stringify(uuidPlaceholder)},"to":${JSON.stringify(to)},` +
    `"body":${encodedRe}}}`;
  return MAX_FRAME_BYTES - Buffer.byteLength(frameWithoutBody, "utf8");
}

function validCursor(cursor: string): boolean {
  if (cursor.length <= 4 || cursor.length > MAX_CURSOR_CHARACTERS || !/^cur_[A-Za-z0-9_-]+$/.test(cursor)) {
    return false;
  }
  const encoded = cursor.slice(4);
  const decoded = Buffer.from(encoded, "base64url");
  return decoded.byteLength > 0 && decoded.byteLength <= MAX_ADDRESS_BYTES &&
    decoded.toString("base64url") === encoded && validUTF8(decoded);
}

function validOpaqueString(value: string, maximumBytes: number): boolean {
  return value.length > 0 && validText(value) && Buffer.byteLength(value, "utf8") <= maximumBytes;
}

function validText(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function validUTF8(value: Buffer): boolean {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(value);
    return true;
  } catch {
    return false;
  }
}

function isUUIDv7(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
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
    if ((text[cursor] === "{" || text[cursor] === "[") && depth > 64) {
      throw new Error("JSON nesting exceeds limit");
    }
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

function cancelResponseDeadline(deadline: ResponseDeadline): void {
  try {
    deadline.cancel();
  } catch {
    // Deadline cleanup must not replace the operation's stable terminal result.
  }
}

function startResponseDeadline(expire: () => void, durationMS: number): ResponseDeadline {
  const timer = setTimeout(expire, durationMS);
  return { cancel: () => clearTimeout(timer) };
}

function terminateAndWait(socket: WebSocket): Promise<void> {
  if (socket.readyState === WebSocket.CLOSED) return Promise.resolve();
  return new Promise((resolve) => {
    socket.once("close", () => resolve());
    socket.terminate();
  });
}
