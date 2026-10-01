import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

import { Type } from "typebox";
import { Value } from "typebox/value";

// ponytail: fixed ceilings per the accepted online relay auth v2 page; make them
// configurable only when a second deployment profile exists.
export const MAX_CONFIG_FILE_BYTES = 4_096;
export const MAX_SECRET_BYTES = 512;

export const ENDPOINT_ENV = "PI_MESSAGING_RELAY_URL";

/** Fixed home-relative config path; XDG_CONFIG_HOME is deliberately not honored. */
export function clientConfigurationPath(home = homedir()): string {
  return join(home, ".config", "pi", "pi-messaging-relay.json");
}

/** Closed client configuration file shape from the accepted v2 contract. */
export const clientConfigurationSchema = Type.Object(
  {
    url: Type.String({ minLength: 1 }),
    secret: Type.Optional(Type.String()),
  },
  { additionalProperties: false },
);

/** One effective connection configuration after the environment url substitution. */
export type ClientConfiguration = {
  endpoint: URL;
  secret: string | undefined;
};

/** Stable client-side configuration failure with a telemetry-safe reason. */
export class ClientConfigurationError extends Error {
  readonly reason: string;

  constructor(reason: string, message: string) {
    super(message);
    this.name = "ClientConfigurationError";
    this.reason = reason;
  }
}

function configurationError(reason: string, message: string): ClientConfigurationError {
  return new ClientConfigurationError(reason, message);
}

function hasErrorCode(error: unknown, code: string): boolean {
  return (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    (error as { code?: unknown }).code === code
  );
}

/**
 * Load the effective client configuration. Absent file and absent environment url
 * return undefined (relay disconnected, no attempts). An unreadable, unsafe,
 * over-limit, or rejected file fails closed by throwing instead of degrading to an
 * unauthenticated or fallback origin. The secret is taken verbatim from the file
 * only; there is deliberately no secret environment variable.
 */
export async function loadClientConfiguration(home = homedir()): Promise<ClientConfiguration | undefined> {
  const file = await readConfigFile(clientConfigurationPath(home));
  const parsedFile = file === undefined ? undefined : parseClientConfigurationText(file);
  const override = process.env[ENDPOINT_ENV];
  const configuredUrl = override === "" ? undefined : override;
  if (!parsedFile && !configuredUrl) return undefined;
  const source = configuredUrl ?? parsedFile?.url;
  if (source === undefined) return undefined;
  return { endpoint: parseLoopbackOrigin(source), secret: parsedFile?.secret };
}

/** Validate one origin for the client config. Plain HTTP stays loopback-only
 * (same-host deployments, the v1 shape); HTTPS is trusted to any host because
 * TLS is the transport trust boundary — remote ingress behind a TLS-terminating
 * proxy is a supported deployment. Userinfo, non-root paths, query, and hash
 * stay rejected for both schemes. */
export function parseLoopbackOrigin(value: string): URL {
  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    throw configurationError(
      "url_invalid",
      "Relay client url must be an HTTP loopback origin or an HTTPS origin such as http://127.0.0.1:8080 or https://relay.example.net.",
    );
  }
  const httpsOrigin = endpoint.protocol === "https:";
  const host = endpoint.hostname.replace(/^\[|\]$/g, "");
  const ipv4Parts = host.split(".");
  const isIPv4Loopback =
    ipv4Parts.length === 4 &&
    ipv4Parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255) &&
    Number(ipv4Parts[0]) === 127;
  if (
    (endpoint.protocol !== "http:" && !httpsOrigin) ||
    endpoint.username !== "" ||
    endpoint.password !== "" ||
    (endpoint.pathname !== "" && endpoint.pathname !== "/") ||
    endpoint.search !== "" ||
    endpoint.hash !== "" ||
    (!httpsOrigin && !isIPv4Loopback && host !== "::1")
  ) {
    throw configurationError(
      "url_invalid",
      "Relay client url must be an HTTP loopback origin or an HTTPS origin such as http://127.0.0.1:8080 or https://relay.example.net.",
    );
  }
  return endpoint;
}

/** Parse and validate the closed config file text: duplicate keys, unknown keys,
 * wrong types, trailing JSON, and out-of-bounds secrets reject the whole file. */
export function parseClientConfigurationText(text: string): { url: string; secret?: string } {
  let parsed: Record<string, unknown>;
  try {
    parsed = parseClosedStringObject(text, { required: ["url"], optional: ["secret"] });
  } catch {
    throw configurationError(
      "config_invalid",
      "Relay client configuration must be one closed JSON object with url and optional secret.",
    );
  }
  if (!Value.Check(clientConfigurationSchema, parsed)) {
    throw configurationError(
      "config_invalid",
      "Relay client configuration must be one closed JSON object with url and optional secret.",
    );
  }
  const secret = parsed.secret;
  if (secret !== undefined) {
    const bytes = Buffer.byteLength(secret, "utf8");
    if (bytes < 1 || bytes > MAX_SECRET_BYTES) {
      throw configurationError(
        "secret_invalid",
        `Relay client secret must be 1 through ${MAX_SECRET_BYTES} UTF-8 bytes, used verbatim.`,
      );
    }
  }
  return secret === undefined ? { url: parsed.url } : { url: parsed.url, secret };
}

async function readConfigFile(path: string): Promise<string | undefined> {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) return undefined;
    if (hasErrorCode(error, "ELOOP")) {
      throw configurationError(
        "unsafe_config_symlink",
        "Relay client configuration must be a regular file, not a symlink.",
      );
    }
    throw configurationError(
      "config_unreadable",
      "Relay client configuration could not be opened safely.",
    );
  }

  try {
    const info = await handle.stat();
    if (!info.isFile()) {
      throw configurationError(
        "unsafe_config_file",
        "Relay client configuration must be a regular file.",
      );
    }
    if ((info.mode & 0o777) !== 0o600) {
      throw configurationError(
        "unsafe_config_permissions",
        "Relay client configuration must have permissions 0600.",
      );
    }
    if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
      throw configurationError(
        "unsafe_config_owner",
        "Relay client configuration must be owned by the current user.",
      );
    }
    const buffer = Buffer.alloc(MAX_CONFIG_FILE_BYTES + 1);
    let total = 0;
    while (total <= MAX_CONFIG_FILE_BYTES) {
      const { bytesRead } = await handle.read(buffer, total, buffer.length - total, total);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    if (total > MAX_CONFIG_FILE_BYTES) {
      throw configurationError(
        "config_too_large",
        `Relay client configuration exceeds ${MAX_CONFIG_FILE_BYTES} bytes.`,
      );
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, total));
    } catch {
      throw configurationError(
        "config_invalid",
        "Relay client configuration must be valid UTF-8.",
      );
    }
  } finally {
    await handle.close();
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

/** Parse one closed JSON object of string members, rejecting duplicate keys,
 * unknown keys, non-string values, and trailing JSON before TypeBox validation. */
function parseClosedStringObject(
  text: string,
  shape: { required: readonly string[]; optional: readonly string[] },
): Record<string, string> {
  let cursor = skipJSONWhitespace(text, 0);
  if (text[cursor] !== "{") throw new Error("expected JSON object");
  cursor = skipJSONWhitespace(text, cursor + 1);
  const result: Record<string, string> = {};
  const allowed = new Set([...shape.required, ...shape.optional]);
  if (text[cursor] !== "}") {
    while (true) {
      const field = parseJSONString(text, cursor);
      if (!allowed.has(field.value)) throw new Error("unknown JSON field");
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
  for (const field of shape.required) {
    if (!Object.hasOwn(result, field)) throw new Error("missing JSON field");
  }
  return result;
}
