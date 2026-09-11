import { constants } from "node:fs";
import { link, lstat, mkdir, open, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  type KeyObject,
} from "node:crypto";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

import { createRecipientDelivery } from "./internal/delivery-policy.ts";
import { syncDirectory } from "./internal/directory-durability.ts";
import { RosterRequestError } from "./internal/roster-client.ts";
import { generateUUIDv7, SessionSocketAttempt } from "./internal/session-auth.ts";

const DISCONNECTED_ERROR =
  "Relay is disconnected. Pair this installation with /relay-pair CODE, then wait for a relay-enabled connection release.";
const ENDPOINT_ENV = "PI_MESSAGING_RELAY_URL";
const STATE_DIR_ENV = "PI_MESSAGING_RELAY_STATE_DIR";
const PRIVATE_KEY_FILENAME = "installation-ed25519.pem";
const REDACTED = "<redacted>";
const MAX_PAIR_REQUEST_BYTES = 4096;
const MAX_PAIR_RESPONSE_BYTES = 4096;
const MAX_CURSOR_CHARACTERS = 5_856;
const PAIRING_CODE_BYTES = 32;
const PAIR_REQUEST_FIXED_BYTES = 94;
const MAX_PAIRING_CODE_BYTES = Math.min(
  PAIRING_CODE_BYTES,
  MAX_PAIR_REQUEST_BYTES - PAIR_REQUEST_FIXED_BYTES,
);

const listPeersParameters = Type.Object(
  {
    cursor: Type.Optional(Type.String({
      maxLength: MAX_CURSOR_CHARACTERS,
      pattern: "^cur_[A-Za-z0-9_-]+$",
      description: "Opaque next_cursor from the preceding list_peers page; omit for the first page",
    })),
  },
  { additionalProperties: false },
);
const agentSendParameters = Type.Object(
  {
    to: Type.String({
      minLength: 1,
      description: "Opaque address returned by list_peers",
    }),
    body: Type.Union([
      Type.String({ description: "Message text" }),
      Type.Record(Type.String(), Type.Unknown(), {
        description: "JSON object message body",
      }),
    ]),
    re: Type.Optional(
      Type.String({
        minLength: 1,
        description: "Original message ID when sending a reply",
      }),
    ),
  },
  { additionalProperties: false },
);

class PairingError extends Error {
  readonly reason: string;

  constructor(reason: string, message: string) {
    super(message);
    this.name = "PairingError";
    this.reason = reason;
  }
}

function logFailure(operation: string, reason: string): void {
  console.error(
    JSON.stringify({
      level: "warn",
      event: "relay_operation_failed",
      operation,
      reason,
    }),
  );
}

function logPairing(
  level: "info" | "warn",
  result: "accepted" | "rejected",
  fields: { reason?: string; clientPublicKey?: string; clientID?: string; latencyMS: number },
): void {
  console.error(
    JSON.stringify({
      level,
      event: result === "accepted" ? "relay_pair_accepted" : "relay_pair_rejected",
      operation: "relay-pair",
      result,
      ...(fields.reason ? { reason: fields.reason } : {}),
      pairing_code: REDACTED,
      private_key: REDACTED,
      ...(fields.clientPublicKey ? { client_public_key: fields.clientPublicKey } : {}),
      ...(fields.clientID ? { client_id: fields.clientID } : {}),
      latency_ms: fields.latencyMS,
    }),
  );
}

function disconnected(operation: "list_peers" | "agent_send"): never {
  logFailure(operation, "disconnected");
  throw new Error(DISCONNECTED_ERROR);
}

function extensionStateDirectory(): string {
  return process.env[STATE_DIR_ENV] || join(homedir(), ".pi", "agent", "pi-messaging-relay");
}

async function ensurePrivateStateDirectory(path: string): Promise<string> {
  const absolutePath = resolve(path);
  const firstCreated = await mkdir(absolutePath, { recursive: true, mode: 0o700 });
  if (typeof firstCreated === "string") {
    let createdPath = resolve(firstCreated);
    while (true) {
      await syncDirectory(dirname(createdPath));
      if (createdPath === absolutePath) break;
      const nextComponent = relative(createdPath, absolutePath).split(sep)[0];
      if (!nextComponent) throw new Error("created state path is outside configured directory");
      createdPath = join(createdPath, nextComponent);
    }
  }
  const info = await lstat(absolutePath);
  if (!info.isDirectory() || (info.mode & 0o777) !== 0o700) {
    throw new PairingError(
      "unsafe_state_permissions",
      `Pairing failed: ${STATE_DIR_ENV} must name a directory with permissions 0700.`,
    );
  }
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new PairingError(
      "unsafe_state_owner",
      `Pairing failed: ${STATE_DIR_ENV} must be owned by the current user.`,
    );
  }
  return absolutePath;
}

async function readInstallationKey(path: string): Promise<KeyObject> {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) {
      throw error;
    }
    throw new PairingError(
      "installation_key_unavailable",
      "Pairing failed: installation private key cannot be opened safely.",
    );
  }

  try {
    const info = await handle.stat();
    if (!info.isFile() || (info.mode & 0o777) !== 0o600) {
      throw new PairingError(
        "unsafe_key_permissions",
        "Pairing failed: installation private key must be a regular file with permissions 0600.",
      );
    }
    if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
      throw new PairingError(
        "unsafe_key_owner",
        "Pairing failed: installation private key must be owned by the current user.",
      );
    }
    const pem = await handle.readFile({ encoding: "utf8" });
    const key = createPrivateKey(pem);
    if (key.asymmetricKeyType !== "ed25519") {
      throw new PairingError(
        "invalid_installation_key",
        "Pairing failed: stored installation key is not an Ed25519 private key.",
      );
    }
    return key;
  } catch (error) {
    if (error instanceof PairingError) throw error;
    throw new PairingError(
      "invalid_installation_key",
      "Pairing failed: stored installation private key is invalid.",
    );
  } finally {
    await handle.close();
  }
}

async function persistNewInstallationKey(path: string, pem: string): Promise<boolean> {
  const temporaryPath = `${path}.${randomUUID()}.tmp`;
  let handle;
  let temporaryExists = false;
  try {
    handle = await open(temporaryPath, "wx", 0o600);
    temporaryExists = true;
    await handle.chmod(0o600);
    await handle.writeFile(pem, { encoding: "utf8" });
    await handle.sync();
    await handle.close();
    handle = undefined;
    let published = false;
    try {
      await link(temporaryPath, path);
      published = true;
    } catch (error) {
      if (!hasErrorCode(error, "EEXIST")) throw error;
    }
    await unlink(temporaryPath);
    temporaryExists = false;
    await syncDirectory(dirname(path));
    return published;
  } finally {
    if (handle) await handle.close().catch(() => undefined);
    if (temporaryExists) await unlink(temporaryPath).catch(() => undefined);
  }
}

async function loadOrCreateInstallationKey(): Promise<KeyObject> {
  const stateDirectory = await ensurePrivateStateDirectory(extensionStateDirectory());
  const keyPath = join(stateDirectory, PRIVATE_KEY_FILENAME);
  try {
    const existing = await readInstallationKey(keyPath);
    await syncDirectory(stateDirectory);
    return existing;
  } catch (error) {
    if (!hasErrorCode(error, "ENOENT")) throw error;
  }

  const generated = generateKeyPairSync("ed25519").privateKey;
  const pem = generated.export({ format: "pem", type: "pkcs8" }).toString();
  try {
    if (await persistNewInstallationKey(keyPath, pem)) return generated;
  } catch {
    throw new PairingError(
      "installation_key_persistence_failed",
      "Pairing failed: installation private key could not be persisted atomically.",
    );
  }
  const winner = await readInstallationKey(keyPath);
  await syncDirectory(stateDirectory);
  return winner;
}

function encodedPublicKey(privateKey: KeyObject): string {
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  if (typeof jwk.x !== "string") {
    throw new PairingError(
      "public_key_export_failed",
      "Pairing failed: Ed25519 public key could not be exported.",
    );
  }
  return `ed25519:${Buffer.from(jwk.x, "base64url").toString("base64")}`;
}

function relayOrigin(): URL {
  const configured = process.env[ENDPOINT_ENV];
  if (!configured) {
    throw new PairingError(
      "endpoint_not_configured",
      `Pairing failed: set ${ENDPOINT_ENV} to the relay loopback origin, then retry /relay-pair CODE.`,
    );
  }
  let endpoint: URL;
  try {
    endpoint = new URL(configured);
  } catch {
    throw new PairingError(
      "endpoint_invalid",
      `Pairing failed: ${ENDPOINT_ENV} must be an HTTP loopback origin such as http://127.0.0.1:8080.`,
    );
  }
  const host = endpoint.hostname.replace(/^\[|\]$/g, "");
  const ipv4Parts = host.split(".");
  const isIPv4Loopback =
    ipv4Parts.length === 4 &&
    ipv4Parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255) &&
    Number(ipv4Parts[0]) === 127;
  if (
    endpoint.protocol !== "http:" ||
    endpoint.username !== "" ||
    endpoint.password !== "" ||
    (endpoint.pathname !== "" && endpoint.pathname !== "/") ||
    endpoint.search !== "" ||
    endpoint.hash !== "" ||
    (!isIPv4Loopback && host !== "::1")
  ) {
    throw new PairingError(
      "endpoint_invalid",
      `Pairing failed: ${ENDPOINT_ENV} must be an HTTP loopback origin such as http://127.0.0.1:8080.`,
    );
  }
  return endpoint;
}

function pairEndpoint(): URL {
  return new URL("/v1/pair", relayOrigin());
}

function connectEndpoint(): URL {
  const endpoint = new URL("/v1/connect", relayOrigin());
  endpoint.protocol = "ws:";
  return endpoint;
}

async function loadExistingInstallationKey(): Promise<KeyObject | undefined> {
  const stateDirectory = resolve(extensionStateDirectory());
  try {
    await lstat(stateDirectory);
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) return undefined;
    throw error;
  }
  await ensurePrivateStateDirectory(stateDirectory);
  try {
    return await readInstallationKey(join(stateDirectory, PRIVATE_KEY_FILENAME));
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) return undefined;
    throw error;
  }
}

async function readBoundedText(response: Response): Promise<string> {
  const contentType = response.headers.get("content-type") || "";
  if (!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(contentType.trim())) {
    throw new PairingError("invalid_response", "Pairing failed: relay returned a non-JSON response.");
  }
  if (!response.body) {
    throw new PairingError("invalid_response", "Pairing failed: relay returned an empty response.");
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_PAIR_RESPONSE_BYTES) {
        await reader.cancel();
        throw new PairingError("response_too_large", "Pairing failed: relay response exceeded 4096 bytes.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks, size));
  } catch {
    throw new PairingError("invalid_response", "Pairing failed: relay returned invalid UTF-8.");
  }
}

function skipJSONWhitespace(text: string, start: number): number {
  let cursor = start;
  while (cursor < text.length && /[\t\n\r ]/.test(text[cursor])) cursor += 1;
  return cursor;
}

function parseJSONString(text: string, start: number): { value: string; next: number } {
  if (text[start] !== '"') throw new Error("expected JSON string");
  let value = "";
  for (let cursor = start + 1; cursor < text.length; cursor += 1) {
    const character = text[cursor];
    if (character === '"') return { value, next: cursor + 1 };
    if (character.charCodeAt(0) < 0x20) throw new Error("unescaped JSON control character");
    if (character !== "\\") {
      value += character;
      continue;
    }

    cursor += 1;
    const escape = text[cursor];
    const simpleEscapes: Record<string, string> = {
      '"': '"',
      "\\": "\\",
      "/": "/",
      b: "\b",
      f: "\f",
      n: "\n",
      r: "\r",
      t: "\t",
    };
    if (Object.hasOwn(simpleEscapes, escape)) {
      value += simpleEscapes[escape];
      continue;
    }
    if (escape !== "u") throw new Error("invalid JSON string escape");
    const hexadecimal = text.slice(cursor + 1, cursor + 5);
    if (!/^[0-9a-fA-F]{4}$/.test(hexadecimal)) throw new Error("invalid JSON Unicode escape");
    value += String.fromCharCode(Number.parseInt(hexadecimal, 16));
    cursor += 4;
  }
  throw new Error("unterminated JSON string");
}

function parseExactStringObject(text: string, expectedFields: readonly string[]): Record<string, string> {
  try {
    let cursor = skipJSONWhitespace(text, 0);
    if (text[cursor] !== "{") throw new Error("expected JSON object");
    cursor = skipJSONWhitespace(text, cursor + 1);
    const result: Record<string, string> = {};
    const expected = new Set(expectedFields);
    if (text[cursor] !== "}") {
      while (true) {
        const field = parseJSONString(text, cursor);
        if (!expected.has(field.value)) throw new Error("unknown JSON field");
        if (Object.hasOwn(result, field.value)) throw new Error("duplicate JSON field");
        cursor = skipJSONWhitespace(text, field.next);
        if (text[cursor] !== ":") throw new Error("expected field separator");
        cursor = skipJSONWhitespace(text, cursor + 1);
        const value = parseJSONString(text, cursor);
        result[field.value] = value.value;
        cursor = skipJSONWhitespace(text, value.next);
        if (text[cursor] === "}") break;
        if (text[cursor] !== ",") throw new Error("expected object separator");
        cursor = skipJSONWhitespace(text, cursor + 1);
      }
    }
    cursor = skipJSONWhitespace(text, cursor + 1);
    if (cursor !== text.length) throw new Error("trailing JSON content");
    if (Object.keys(result).length !== expectedFields.length) throw new Error("missing JSON field");
    return result;
  } catch (error) {
    if (error instanceof PairingError) throw error;
    throw new PairingError(
      "invalid_response",
      "Pairing failed: relay returned an invalid or non-canonical response object.",
    );
  }
}

async function pairInstallation(
  code: string,
): Promise<{ clientID: string; clientPublicKey: string; privateKey: KeyObject }> {
  const endpoint = pairEndpoint();
  const privateKey = await loadOrCreateInstallationKey();
  const clientPublicKey = encodedPublicKey(privateKey);
  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pairing_code: code, client_public_key: clientPublicKey }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new PairingError(
      "request_failed",
      "Pairing failed: relay could not be reached within 10 seconds; verify the configured loopback URL.",
    );
  }
  const payloadText = await readBoundedText(response);
  if (response.status !== 201) {
    const payload = parseExactStringObject(payloadText, ["error", "message"]);
    const knownRejections: Record<string, string> = {
      pairing_code_invalid: "Pairing code is invalid or expired.",
      invalid_request: "Relay rejected the pairing request shape.",
      invalid_client_public_key: "Relay rejected the Ed25519 installation public key.",
      pairing_unavailable: "Relay could not persist pairing; check relay state permissions.",
    };
    const knownMessage = knownRejections[payload.error];
    if (knownMessage) {
      throw new PairingError(payload.error, `Pairing failed (${payload.error}): ${knownMessage}`);
    }
    throw new PairingError(
      "request_rejected",
      `Pairing failed: relay returned HTTP ${response.status}.`,
    );
  }
  const payload = parseExactStringObject(payloadText, ["client_id"]);
  if (!/^cli_[A-Za-z0-9_-]{16}$/.test(payload.client_id)) {
    throw new PairingError(
      "invalid_response",
      "Pairing failed: relay response did not contain one valid client_id.",
    );
  }
  return { clientID: payload.client_id, clientPublicKey, privateKey };
}

function hasErrorCode(error: unknown, code: string): boolean {
  return (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    (error as { code?: unknown }).code === code
  );
}

function validatePairingCodeArgument(argument: string): string {
  const byteLength = Buffer.byteLength(argument, "utf8");
  if (byteLength === 0) {
    throw new PairingError(
      "pairing_code_required",
      "Pairing failed: enter a code with /relay-pair CODE.",
    );
  }
  // Fixed ASCII code/public-key syntax makes every accepted closed request exactly 126 UTF-8 bytes.
  if (byteLength > MAX_PAIRING_CODE_BYTES || !/^[A-Za-z0-9_-]{32}$/.test(argument)) {
    throw new PairingError(
      "pairing_code_invalid_format",
      "Pairing failed: code must contain exactly 32 URL-safe characters.",
    );
  }
  return argument;
}

export default function relayExtension(pi: ExtensionAPI): void {
  let sessionStarted = false;
  let sessionRouteID: string | undefined;
  let sessionCWD: string | undefined;
  let startupAttempted = false;
  let pairingAttempted = false;
  let activeSessionIdle: (() => boolean) | undefined;
  let activeAttempt: SessionSocketAttempt | undefined;
  let activeConnection: Awaited<SessionSocketAttempt["result"]> | undefined;

  const logAuthentication = (
    level: "info" | "warn",
    result: "accepted" | "rejected" | "disconnected",
    fields: { reason?: string; address?: string; routeID?: string; clientPublicKey?: string; latencyMS?: number },
  ) => {
    console.error(JSON.stringify({
      level,
      event: result === "accepted"
        ? "relay_auth_accepted"
        : result === "rejected"
          ? "relay_auth_rejected"
          : "relay_session_disconnected",
      result,
      ...(fields.reason ? { reason: fields.reason } : {}),
      ...(fields.address ? { address: fields.address } : {}),
      ...(fields.routeID ? { route_id: fields.routeID } : {}),
      ...(fields.clientPublicKey ? { client_public_key: fields.clientPublicKey } : {}),
      nonce: REDACTED,
      signature: REDACTED,
      private_key: REDACTED,
      ...(fields.latencyMS === undefined ? {} : { latency_ms: fields.latencyMS }),
    }));
  };

  const connectOnce = async (cause: "startup" | "pairing", pairedKey?: KeyObject): Promise<void> => {
    if (!sessionStarted || activeConnection) return;
    if (cause === "startup") {
      if (startupAttempted) return;
    } else if (pairingAttempted) {
      return;
    }
    if (activeAttempt) {
      await activeAttempt.result.catch(() => undefined);
      if (!sessionStarted || activeConnection) return;
    }

    let privateKey: KeyObject | undefined;
    try {
      privateKey = pairedKey ?? await loadExistingInstallationKey();
      if (!privateKey) return;
    } catch {
      logAuthentication("warn", "rejected", {
        reason: "installation_key_unavailable",
        routeID: sessionRouteID,
      });
      return;
    }
    if (cause === "startup") startupAttempted = true;
    else pairingAttempted = true;

    const started = Date.now();
    let clientPublicKey: string;
    let endpoint: URL;
    try {
      clientPublicKey = encodedPublicKey(privateKey);
      endpoint = connectEndpoint();
    } catch (error) {
      const reason = error instanceof PairingError ? error.reason : "configuration_invalid";
      logAuthentication("warn", "rejected", {
        reason,
        routeID: sessionRouteID,
        latencyMS: Date.now() - started,
      });
      return;
    }
    const routeID = sessionRouteID;
    const cwd = sessionCWD;
    const sessionIdle = activeSessionIdle;
    if (!routeID || !cwd || !sessionIdle) return;

    const attempt = new SessionSocketAttempt({
      endpoint,
      privateKey,
      clientPublicKey,
      routeID,
      cwd,
      deliverUserMessage: createRecipientDelivery(
        pi.sendUserMessage,
        sessionIdle,
        () => activeSessionIdle === sessionIdle,
      ),
      onDisconnected: () => {
        if (activeConnection?.socket === connection?.socket) activeConnection = undefined;
        logAuthentication("info", "disconnected", {
          address: connection?.address,
          routeID,
          clientPublicKey,
        });
      },
    });
    activeAttempt = attempt;
    let connection: Awaited<typeof attempt.result> | undefined;
    try {
      connection = await attempt.result;
      if (!sessionStarted || sessionRouteID !== routeID) {
        await connection.closeAndWait();
        return;
      }
      activeConnection = connection;
      logAuthentication("info", "accepted", {
        address: connection.address,
        routeID,
        clientPublicKey,
        latencyMS: Date.now() - started,
      });
    } catch (error) {
      const reason = error !== null && typeof error === "object" && "reason" in error &&
          typeof (error as { reason?: unknown }).reason === "string"
        ? (error as { reason: string }).reason
        : "connection_failed";
      logAuthentication("warn", "rejected", {
        reason,
        routeID,
        clientPublicKey,
        latencyMS: Date.now() - started,
      });
    } finally {
      if (activeAttempt === attempt) activeAttempt = undefined;
    }
  };

  pi.on("session_start", async (_event, ctx) => {
    activeSessionIdle = undefined;
    if (activeConnection) await activeConnection.closeAndWait();
    activeAttempt?.close();
    sessionStarted = true;
    sessionRouteID = generateUUIDv7();
    sessionCWD = ctx.cwd;
    activeSessionIdle = () => ctx.isIdle();
    startupAttempted = false;
    pairingAttempted = false;
    await connectOnce("startup");
  });

  pi.on("session_shutdown", async () => {
    sessionStarted = false;
    sessionRouteID = undefined;
    sessionCWD = undefined;
    activeSessionIdle = undefined;
    const pendingAttempt = activeAttempt?.result;
    activeAttempt?.close();
    if (pendingAttempt) await pendingAttempt.catch(() => undefined);
    const connection = activeConnection;
    activeConnection = undefined;
    if (connection) await connection.closeAndWait();
  });

  pi.registerCommand("relay-pair", {
    description: "Pair this Pi installation with the configured relay server",
    handler: async (args, ctx) => {
      const started = Date.now();
      try {
        const code = validatePairingCodeArgument(args);
        const paired = await pairInstallation(code);
        logPairing("info", "accepted", {
          clientPublicKey: paired.clientPublicKey,
          clientID: paired.clientID,
          latencyMS: Date.now() - started,
        });
        ctx.ui.notify(`Relay pairing accepted client identity ${paired.clientID}.`, "success");
        if (sessionStarted) await connectOnce("pairing", paired.privateKey);
      } catch (error) {
        const pairingError =
          error instanceof PairingError
            ? error
            : new PairingError("unexpected_failure", "Pairing failed unexpectedly; inspect relay logs and retry.");
        logPairing("warn", "rejected", {
          reason: pairingError.reason,
          latencyMS: Date.now() - started,
        });
        ctx.ui.notify(pairingError.message, "error");
      }
    },
  });

  pi.registerTool({
    name: "list_peers",
    label: "List Relay Peers",
    description: "List one address-only page of online Pi relay sessions; the result contains peers and optional next_cursor",
    parameters: listPeersParameters,
    async execute(_toolCallID, params, signal) {
      const connection = activeConnection;
      if (!connection) return disconnected("list_peers");
      try {
        const cursor = (params as { cursor?: string }).cursor;
        const page = await connection.list(cursor, signal as AbortSignal);
        return {
          content: [{ type: "text", text: JSON.stringify(page) }],
          details: page,
        };
      } catch (error) {
        logFailure(
          "list_peers",
          error instanceof RosterRequestError ? error.reason : "unexpected_failure",
        );
        throw error;
      }
    },
  });

  pi.registerTool({
    name: "agent_send",
    label: "Send to Relay Peer",
    description: "Send text to one online Pi relay session; object bodies are reserved for a later release",
    parameters: agentSendParameters,
    async execute(_toolCallID, params, signal) {
      const connection = activeConnection;
      if (!connection) return disconnected("agent_send");
      try {
        const input = params as {
          to: string;
          body: string | Record<string, unknown>;
          re?: string;
        };
        const result = await connection.send(input.to, input.body, input.re, signal as AbortSignal);
        return {
          content: [{ type: "text", text: JSON.stringify(result) }],
          details: result,
        };
      } catch (error) {
        logFailure(
          "agent_send",
          error instanceof RosterRequestError ? error.reason : "unexpected_failure",
        );
        throw error;
      }
    },
  });
}
