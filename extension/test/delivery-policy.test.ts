import assert from "node:assert/strict";
import test from "node:test";

import { createRecipientDelivery } from "../internal/delivery-policy.ts";

function recordingSend(attempts: unknown[][]): (...args: unknown[]) => void {
  return (...args) => { attempts.push(args); };
}

test("missing active recipient identity fails safe to follow-up delivery", () => {
  const attempts: unknown[][] = [];
  const deliver = createRecipientDelivery(
    recordingSend(attempts),
    () => true,
    () => false,
  );

  deliver("missing identity body");

  assert.deepEqual(attempts, [["missing identity body", { deliverAs: "followUp" }]]);
});

test("recipient identity change during idle observation fails safe to follow-up delivery", () => {
  const attempts: unknown[][] = [];
  const capturedSession = Symbol("captured recipient session");
  let activeSession = capturedSession;
  const deliver = createRecipientDelivery(
    recordingSend(attempts),
    () => {
      activeSession = Symbol("replacement recipient session");
      return true;
    },
    () => activeSession === capturedSession,
  );

  deliver("identity changed while checking idle");

  assert.deepEqual(attempts, [[
    "identity changed while checking idle",
    { deliverAs: "followUp" },
  ]]);
});

test("recipient idle predicate exception fails safe to follow-up delivery", () => {
  const attempts: unknown[][] = [];
  const deliver = createRecipientDelivery(
    recordingSend(attempts),
    () => { throw new Error("stale Pi context"); },
    () => true,
  );

  deliver("idle check failed");

  assert.deepEqual(attempts, [["idle check failed", { deliverAs: "followUp" }]]);
});
