import { types } from "node:util";

const MAX_ADDRESS_BYTES = 4_389;
const MAX_FRAME_BYTES = 512 * 1024;
const MAX_BODY_CONTAINER_DEPTH = 62;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type JSONPrimitive = null | boolean | number | string;
export type JSONValue = JSONPrimitive | JSONValue[] | { [key: string]: JSONValue };
export type JSONObject = { [key: string]: JSONValue };

export type RelayMessage = {
  from: string;
  messageID: string;
  re?: string;
  body: string | JSONObject;
};

type CanonicalJSONFailure = "invalid" | "maximum_bytes";

/** Content-free canonical-encoding failure classified for the owning transport boundary. */
export class CanonicalJSONError extends Error {
  readonly failure: CanonicalJSONFailure;

  constructor(failure: CanonicalJSONFailure) {
    super("Relay message content is not safe JSON.");
    this.name = "CanonicalJSONError";
    this.failure = failure;
  }
}

/** Encodes a safe snapshot compactly within an explicit UTF-8 byte budget. */
export function canonicalCompactJSON(value: unknown, maximumBytes: number): string {
  try {
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0) throw new Error("invalid byte budget");
    const validationBudget = new ByteBudget(maximumBytes);
    validateSafeJSON(value, 0, new Set<object>(), validationBudget);
    const snapshot: unknown = structuredClone(value);
    const encoder = new BoundedEncoder(maximumBytes);
    encoder.encode(snapshot, 0, new Set<object>());
    return encoder.finish();
  } catch (error) {
    throw new CanonicalJSONError(error instanceof EncodingBudgetExceeded ? "maximum_bytes" : "invalid");
  }
}

/** Produces the exact provenance header and unchanged string or canonical object body. */
export function renderRelayMessage(message: RelayMessage): string {
  try {
    if (!validOpaqueString(message.from, MAX_ADDRESS_BYTES) ||
        !UUID_V7.test(message.messageID) ||
        (message.re !== undefined && !UUID_V7.test(message.re)) ||
        (typeof message.body !== "string" &&
         (message.body === null || typeof message.body !== "object" ||
          types.isProxy(message.body) || Array.isArray(message.body)))) {
      throw new Error("invalid relay message");
    }
    const quotedFrom = JSON.stringify(message.from)?.replace(
      /[\u0085\u2028\u2029]/g,
      (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
    );
    if (quotedFrom === undefined) throw new Error("invalid sender address");
    const renderedBody = typeof message.body === "string"
      ? requireValidText(message.body)
      : canonicalCompactJSON(message.body, MAX_FRAME_BYTES);
    const correlation = message.re === undefined ? "" : `, re=${message.re}`;
    return `[pi-messaging-relay] message from ${quotedFrom} (id=${message.messageID}${correlation}):\n${renderedBody}`;
  } catch {
    throw new Error("Relay message cannot be rendered.");
  }
}

class EncodingBudgetExceeded extends Error {}

class ByteBudget {
  remaining: number;

  constructor(maximumBytes: number) {
    this.remaining = maximumBytes;
  }

  consume(bytes: number): void {
    if (bytes > this.remaining) throw new EncodingBudgetExceeded();
    this.remaining -= bytes;
  }
}

class BoundedEncoder {
  private readonly budget: ByteBudget;
  private readonly chunks: string[] = [];

  constructor(maximumBytes: number) {
    this.budget = new ByteBudget(maximumBytes);
  }

  encode(value: unknown, containerDepth: number, ancestors: Set<object>): void {
    if (value === null) {
      this.append("null");
      return;
    }
    switch (typeof value) {
      case "string":
        this.appendJSONString(value);
        return;
      case "boolean":
        this.append(value ? "true" : "false");
        return;
      case "number": {
        if (!Number.isFinite(value)) throw new Error("nonfinite number");
        const encoded = JSON.stringify(value);
        if (encoded === undefined) throw new Error("invalid number");
        this.append(encoded);
        return;
      }
      case "object":
        this.encodeContainer(value, containerDepth + 1, ancestors);
        return;
      default:
        throw new Error("non-JSON value");
    }
  }

  finish(): string {
    return this.chunks.join("");
  }

  private encodeContainer(value: object, depth: number, ancestors: Set<object>): void {
    if (depth > MAX_BODY_CONTAINER_DEPTH || ancestors.has(value)) throw new Error("unsafe object graph");
    ancestors.add(value);
    try {
      if (Array.isArray(value)) {
        this.encodeArray(value, depth, ancestors);
        return;
      }
      if (!isObjectRecord(value)) throw new Error("unsafe object prototype");
      this.encodeObject(value, depth, ancestors);
    } finally {
      ancestors.delete(value);
    }
  }

  private encodeArray(value: unknown[], depth: number, ancestors: Set<object>): void {
    requirePossibleArrayLength(value.length, this.budget.remaining);
    this.append("[");
    for (let index = 0; index < value.length; index += 1) {
      if (index > 0) this.append(",");
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
        throw new Error("unsafe array property");
      }
      this.encode(descriptor.value, depth, ancestors);
    }
    this.append("]");
  }

  private encodeObject(value: Record<string, unknown>, depth: number, ancestors: Set<object>): void {
    const keys = Object.keys(value).sort();
    this.append("{");
    for (let index = 0; index < keys.length; index += 1) {
      if (index > 0) this.append(",");
      const key = keys[index];
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
        throw new Error("unsafe object property");
      }
      this.appendJSONString(key);
      this.append(":");
      this.encode(descriptor.value, depth, ancestors);
    }
    this.append("}");
  }

  private appendJSONString(value: string): void {
    const measuredBytes = measureJSONStringBytes(value, this.budget.remaining);
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error("invalid string");
    this.appendMeasured(encoded, measuredBytes);
  }

  private append(value: string): void {
    this.appendMeasured(value, Buffer.byteLength(value, "utf8"));
  }

  private appendMeasured(value: string, bytes: number): void {
    this.budget.consume(bytes);
    this.chunks.push(value);
  }
}

function validateSafeJSON(
  value: unknown,
  containerDepth: number,
  ancestors: Set<object>,
  budget: ByteBudget,
): void {
  if (value === null) {
    budget.consume(4);
    return;
  }
  switch (typeof value) {
    case "string":
      budget.consume(measureJSONStringBytes(value, budget.remaining));
      return;
    case "boolean":
      budget.consume(value ? 4 : 5);
      return;
    case "number": {
      if (!Number.isFinite(value)) throw new Error("nonfinite number");
      const encoded = JSON.stringify(value);
      if (encoded === undefined) throw new Error("invalid number");
      budget.consume(Buffer.byteLength(encoded, "utf8"));
      return;
    }
    case "object":
      validateSafeContainer(value, containerDepth + 1, ancestors, budget);
      return;
    default:
      throw new Error("non-JSON value");
  }
}

function validateSafeContainer(
  value: object,
  depth: number,
  ancestors: Set<object>,
  budget: ByteBudget,
): void {
  if (types.isProxy(value) || depth > MAX_BODY_CONTAINER_DEPTH || ancestors.has(value)) {
    throw new Error("unsafe object graph");
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      validateSafeArray(value, depth, ancestors, budget);
      return;
    }
    if (!isObjectRecord(value)) throw new Error("unsafe object prototype");
    validateSafeObject(value, depth, ancestors, budget);
  } finally {
    ancestors.delete(value);
  }
}

function validateSafeArray(
  value: unknown[],
  depth: number,
  ancestors: Set<object>,
  budget: ByteBudget,
): void {
  requirePossibleArrayLength(value.length, budget.remaining);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length !== value.length + 1) throw new Error("sparse or extended array");
  budget.consume(1);
  for (let index = 0; index < value.length; index += 1) {
    if (index > 0) budget.consume(1);
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      throw new Error("unsafe array property");
    }
    validateSafeJSON(descriptor.value, depth, ancestors, budget);
  }
  budget.consume(1);
}

function validateSafeObject(
  value: Record<string, unknown>,
  depth: number,
  ancestors: Set<object>,
  budget: ByteBudget,
): void {
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key === "symbol")) throw new Error("symbol object property");
  budget.consume(1);
  for (let index = 0; index < ownKeys.length; index += 1) {
    const key = ownKeys[index] as string;
    if (index > 0) budget.consume(1);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      throw new Error("unsafe object property");
    }
    budget.consume(measureJSONStringBytes(key, budget.remaining));
    budget.consume(1);
    validateSafeJSON(descriptor.value, depth, ancestors, budget);
  }
  budget.consume(1);
}

function requirePossibleArrayLength(length: number, remainingBytes: number): void {
  const minimumBytes = length === 0 ? 2 : (2 * length) + 1;
  if (minimumBytes > remainingBytes) throw new EncodingBudgetExceeded();
}

function measureJSONStringBytes(value: string, remainingBytes: number): number {
  requireValidText(value);
  const rawBytes = Buffer.byteLength(value, "utf8");
  if (rawBytes > remainingBytes) throw new EncodingBudgetExceeded();

  let encodedBytes = 2;
  if (encodedBytes > remainingBytes) throw new EncodingBudgetExceeded();
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit === 0x22 || unit === 0x5c || unit === 0x08 || unit === 0x09 ||
        unit === 0x0a || unit === 0x0c || unit === 0x0d) {
      encodedBytes += 2;
    } else if (unit < 0x20) {
      encodedBytes += 6;
    } else if (unit < 0x80) {
      encodedBytes += 1;
    } else if (unit < 0x800) {
      encodedBytes += 2;
    } else if (unit >= 0xd800 && unit <= 0xdbff) {
      encodedBytes += 4;
      index += 1;
    } else {
      encodedBytes += 3;
    }
    if (encodedBytes > remainingBytes) throw new EncodingBudgetExceeded();
  }
  return encodedBytes;
}

function requireValidText(value: string): string {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) {
        throw new Error("invalid Unicode string");
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error("invalid Unicode string");
    }
  }
  return value;
}

function validOpaqueString(value: string, maximumBytes: number): boolean {
  try {
    return value.length > 0 && Buffer.byteLength(requireValidText(value), "utf8") <= maximumBytes;
  } catch {
    return false;
  }
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
