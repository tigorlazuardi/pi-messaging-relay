import { randomBytes } from "node:crypto";

// ponytail: fixed v1 reconnect policy; make configurable when another deployment profile exists.
export const RECONNECT_INITIAL_MS = 500;
export const RECONNECT_MULTIPLIER = 2;
export const RECONNECT_JITTER_RATIO = 0.25;
export const RECONNECT_CAP_MS = 30_000;
export const RECONNECT_MAX_RETRIES = 10;

export type ReconnectDeadline = {
  cancel(): void;
};

export type ReconnectDependencies = {
  now(): number;
  randomUnit(): number;
  schedule(callback: () => void, delayMS: number): ReconnectDeadline;
};

const productionDependencies: ReconnectDependencies = Object.freeze({
  now: () => Date.now(),
  randomUnit: () => randomBytes(4).readUInt32BE(0) / 0x1_0000_0000,
  schedule: (callback, delayMS) => {
    const timer = setTimeout(callback, delayMS);
    return { cancel: () => clearTimeout(timer) };
  },
});

let currentDependencies = productionDependencies;

/** Return one dependency snapshot for a newly loaded extension factory. */
export function reconnectDependencies(): ReconnectDependencies {
  return currentDependencies;
}

/** Install deterministic reconnect dependencies around one serial test seam. */
export function installReconnectDependenciesForTest(
  dependencies: ReconnectDependencies,
): () => void {
  if (typeof dependencies.now !== "function" ||
      typeof dependencies.randomUnit !== "function" ||
      typeof dependencies.schedule !== "function") {
    throw new Error("Reconnect dependencies are invalid.");
  }
  const previous = currentDependencies;
  currentDependencies = dependencies;
  return () => {
    currentDependencies = previous;
  };
}

/** Calculate one integer-millisecond reconnect delay from a deterministic random sample. */
export function reconnectDelayMS(retryIndex: number, randomUnit: () => number): number {
  if (!Number.isSafeInteger(retryIndex) || retryIndex < 0 || retryIndex >= RECONNECT_MAX_RETRIES) {
    throw new Error("Reconnect retry index is invalid.");
  }
  const sample = randomUnit();
  if (!Number.isFinite(sample) || sample < 0 || sample >= 1) {
    throw new Error("Reconnect randomness must be in [0, 1).");
  }

  const cappedExponent = Math.min(retryIndex, 32);
  const nominal = Math.min(
    RECONNECT_CAP_MS,
    RECONNECT_INITIAL_MS * (RECONNECT_MULTIPLIER ** cappedExponent),
  );
  const jitterFactor = (1 - RECONNECT_JITTER_RATIO) + (2 * RECONNECT_JITTER_RATIO * sample);
  return Math.min(RECONNECT_CAP_MS, Math.round(nominal * jitterFactor));
}
