import assert from "node:assert/strict";
import test from "node:test";

import {
  RECONNECT_CAP_MS,
  RECONNECT_INITIAL_MS,
  RECONNECT_JITTER_RATIO,
  RECONNECT_MAX_RETRIES,
  RECONNECT_MULTIPLIER,
  reconnectDelayMS,
} from "../internal/reconnect.ts";

test("reconnect delay applies bounded deterministic jitter to capped exponential backoff", () => {
  assert.deepEqual(
    {
      initial: RECONNECT_INITIAL_MS,
      multiplier: RECONNECT_MULTIPLIER,
      jitter: RECONNECT_JITTER_RATIO,
      cap: RECONNECT_CAP_MS,
      maximumRetries: RECONNECT_MAX_RETRIES,
    },
    { initial: 500, multiplier: 2, jitter: 0.25, cap: 30_000, maximumRetries: 10 },
  );

  const samples = [0, 0.5, 0.75];
  assert.deepEqual(
    samples.map((sample, retryIndex) => reconnectDelayMS(retryIndex, () => sample)),
    [375, 1_000, 2_250],
  );
  assert.equal(reconnectDelayMS(6, () => 0), 22_500);
  assert.equal(reconnectDelayMS(6, () => 0.5), 30_000);
  assert.equal(reconnectDelayMS(6, () => 0.999_999), 30_000);
  assert.equal(reconnectDelayMS(RECONNECT_MAX_RETRIES - 1, () => 0.999_999), 30_000);
});

test("reconnect delay rejects invalid retry and randomness inputs without scheduling", () => {
  for (const retryIndex of [-1, 0.5, RECONNECT_MAX_RETRIES, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(() => reconnectDelayMS(retryIndex, () => 0.5), {
      message: "Reconnect retry index is invalid.",
    });
  }
  for (const sample of [-0.001, 1, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(() => reconnectDelayMS(0, () => sample), {
      message: "Reconnect randomness must be in [0, 1).",
    });
  }
});
