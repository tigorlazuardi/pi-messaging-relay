import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalCompactJSON,
  renderRelayMessage,
} from "../internal/message-renderer.ts";

const MESSAGE_ID = "01993c84-fc2b-7e1c-af99-61b8118ac6df";
const ORIGINAL_ID = "01993c80-40de-79d7-9b2c-1349f88bb408";
const TEST_BUDGET_BYTES = 512 * 1024;

test("canonical encoder sorts every object by ECMAScript UTF-16 lexical order", () => {
  const body = {
    z: { "2": "two", "10": "ten", a: [{ z: 1, a: 2 }] },
    "\ue000": "private-use",
    "𐀀": "astral",
    "ä": "latin",
    A: "ascii",
  };

  assert.equal(
    canonicalCompactJSON(body, TEST_BUDGET_BYTES),
    '{"A":"ascii","z":{"10":"ten","2":"two","a":[{"a":2,"z":1}]},"ä":"latin","𐀀":"astral","":"private-use"}',
  );
  assert.equal(canonicalCompactJSON({}, TEST_BUDGET_BYTES), "{}");
});

test("canonical encoder preserves arrays and deterministically encodes JSON primitives", () => {
  assert.equal(
    canonicalCompactJSON(
      { values: [null, true, false, 0, -0, 1.25, 1e+21, "quote\" slash\\ line\n"] },
      TEST_BUDGET_BYTES,
    ),
    '{"values":[null,true,false,0,0,1.25,1e+21,"quote\\\" slash\\\\ line\\n"]}',
  );
  assert.equal(canonicalCompactJSON(null, TEST_BUDGET_BYTES), "null");
  assert.equal(canonicalCompactJSON(true, TEST_BUDGET_BYTES), "true");
  assert.equal(canonicalCompactJSON(42, TEST_BUDGET_BYTES), "42");
  assert.equal(canonicalCompactJSON("x\n", TEST_BUDGET_BYTES), '"x\\n"');
});

test("renderer quotes opaque sender on one physical header line and preserves body text", () => {
  const from = 'opaque"\\/\n\u0085\u2028\u2029address';
  const body = "  first line\nsecond line\n";
  const rendered = renderRelayMessage({ from, messageID: MESSAGE_ID, body });
  assert.equal(
    rendered,
    `[pi-messaging-relay] message from "opaque\\\"\\\\/\\n\\u0085\\u2028\\u2029address" (id=${MESSAGE_ID}):\n${body}`,
  );
  assert.equal(rendered.slice(0, rendered.indexOf("\n")).includes("\u0085"), false);
  assert.equal(rendered.slice(0, rendered.indexOf("\n")).includes("\u2028"), false);
  assert.equal(rendered.slice(0, rendered.indexOf("\n")).includes("\u2029"), false);
  assert.equal(
    renderRelayMessage({ from: "ordinary-address", messageID: MESSAGE_ID, re: ORIGINAL_ID, body: { z: 1, a: 2 } }),
    `[pi-messaging-relay] message from "ordinary-address" (id=${MESSAGE_ID}, re=${ORIGINAL_ID}):\n{"a":2,"z":1}`,
  );
});

test("canonical encoder rejects non-JSON, cyclic, nonfinite, accessor, and unsafe values without content", () => {
  const secret = "must-not-appear-in-render-error";
  const cyclic: Record<string, unknown> = { secret };
  cyclic.self = cyclic;
  const accessor = Object.defineProperty({}, "secret", {
    enumerable: true,
    get: () => secret,
  });
  const sparse = new Array(1);
  const accessorArray = ["placeholder"];
  Object.defineProperty(accessorArray, "0", {
    enumerable: true,
    get: () => secret,
  });
  const custom = Object.create({ inherited: secret }) as Record<string, unknown>;
  custom.value = "x";
  const symbolProperty = { value: "x", [Symbol(secret)]: true };
  const invalid: unknown[] = [
    cyclic,
    { value: Number.NaN },
    { value: Number.POSITIVE_INFINITY },
    { value: undefined },
    { value: 1n },
    { value: Symbol(secret) },
    { value: () => secret },
    accessor,
    sparse,
    accessorArray,
    custom,
    symbolProperty,
    Object.defineProperty({ visible: true }, "hidden", { value: secret }),
    "\ud800",
  ];

  for (const value of invalid) {
    assert.throws(
      () => canonicalCompactJSON(value, TEST_BUDGET_BYTES),
      (error: unknown) => error instanceof Error &&
        error.message === "Relay message content is not safe JSON." &&
        !error.message.includes(secret),
    );
  }
});

test("canonical encoder enforces the body depth that fits the 64-container wire envelope", () => {
  const nested = (containers: number): unknown => {
    let value: unknown = null;
    for (let depth = 0; depth < containers; depth += 1) value = { value };
    return value;
  };
  assert.doesNotThrow(() => canonicalCompactJSON(nested(62), TEST_BUDGET_BYTES));
  assert.throws(() => canonicalCompactJSON(nested(63), TEST_BUDGET_BYTES), {
    message: "Relay message content is not safe JSON.",
  });
});

test("canonical encoder enforces exact encoded-byte budget and rejects huge sparse arrays quickly", { timeout: 1_000 }, () => {
  const body = { value: "line\n" };
  const exact = '{"value":"line\\n"}';
  assert.equal(Buffer.byteLength(exact, "utf8"), 18);
  assert.equal(canonicalCompactJSON(body, 18), exact);
  assert.throws(() => canonicalCompactJSON(body, 17), {
    message: "Relay message content is not safe JSON.",
  });

  const hugeSparse: unknown[] = [];
  hugeSparse.length = 0xffffffff;
  assert.throws(() => canonicalCompactJSON(hugeSparse, TEST_BUDGET_BYTES), {
    message: "Relay message content is not safe JSON.",
  });
});

test("canonical encoder rejects transparent and nested mutating proxies without invoking traps or getters", () => {
  const secret = "proxy-and-accessor-secret";
  let trapCalls = 0;
  let getterCalls = 0;
  const transparent = new Proxy({ value: secret }, {});
  const mutatingTarget = { value: secret };
  const mutating = new Proxy(mutatingTarget, {
    ownKeys(target) {
      trapCalls += 1;
      target.value = "mutated-secret";
      return Reflect.ownKeys(target);
    },
  });
  const accessor = Object.defineProperty({}, "value", {
    enumerable: true,
    get: () => {
      getterCalls += 1;
      return secret;
    },
  });

  for (const body of [transparent, { nested: transparent }, { nested: mutating }, accessor]) {
    assert.throws(
      () => canonicalCompactJSON(body, TEST_BUDGET_BYTES),
      (error: unknown) => error instanceof Error &&
        error.message === "Relay message content is not safe JSON." &&
        !error.message.includes(secret),
    );
  }
  assert.equal(trapCalls, 0);
  assert.equal(getterCalls, 0);
  assert.equal(mutatingTarget.value, secret);
});

test("renderer rejects invalid header correlation without exposing supplied content", () => {
  const secret = "invalid-header-secret";
  for (const input of [
    { from: "", messageID: MESSAGE_ID, body: secret },
    { from: secret, messageID: "not-an-id", body: secret },
    { from: secret, messageID: MESSAGE_ID, re: "", body: secret },
    { from: secret, messageID: MESSAGE_ID, body: [] },
  ]) {
    assert.throws(
      () => renderRelayMessage(input as never),
      (error: unknown) => error instanceof Error &&
        error.message === "Relay message cannot be rendered." &&
        !error.message.includes(secret),
    );
  }
});
