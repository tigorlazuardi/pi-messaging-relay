import { execFile } from "node:child_process";

/** Flat string-to-string metadata one session publishes about itself. The relay
 * never routes, authorizes, or dedupes on annotations: they are untrusted,
 * sender-controlled display data. */
export type AnnotationSet = Record<string, string>;

/** Capability token both sides negotiate for the annotation extension. */
export const ANNOTATIONS_CAPABILITY = "annotations";

/** Maximum number of keys in one live annotation set. */
export const MAX_ANNOTATION_KEYS = 8;
/** Maximum size of one annotation value in UTF-8 bytes. */
export const MAX_ANNOTATION_VALUE_BYTES = 256;
/** Maximum size of the compact JSON encoding of one annotation set. */
export const MAX_ANNOTATION_SERIALIZED_BYTES = 1024;
/** Accepted key shape: a lowercase letter followed by lowercase letters, digits,
 * or underscores, at most 32 characters in total. */
export const ANNOTATION_KEY_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;

/** Stable drop reasons mirroring the relay's own reasons. */
export type AnnotationReason =
  | "invalid_payload"
  | "invalid_key"
  | "invalid_value"
  | "too_many_keys"
  | "too_large";

export type AnnotationValidation =
  | { ok: true; annotations: AnnotationSet }
  | { ok: false; reason: AnnotationReason };

/** Validates one annotation set with the relay's own limits. The relay stays
 * authoritative; this mirror only keeps the client from sending a set it knows
 * the relay would drop. */
export function validateAnnotationSet(candidate: unknown): AnnotationValidation {
  if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
    return { ok: false, reason: "invalid_payload" };
  }
  const entries = Object.entries(candidate as Record<string, unknown>);
  if (entries.length > MAX_ANNOTATION_KEYS) {
    return { ok: false, reason: "too_many_keys" };
  }
  const annotations: AnnotationSet = {};
  for (const [key, value] of entries) {
    if (!ANNOTATION_KEY_PATTERN.test(key)) {
      return { ok: false, reason: "invalid_key" };
    }
    if (typeof value !== "string" || !validAnnotationValue(value)) {
      return { ok: false, reason: "invalid_value" };
    }
    annotations[key] = value;
  }
  if (annotationSerializedBytes(annotations) > MAX_ANNOTATION_SERIALIZED_BYTES) {
    return { ok: false, reason: "too_large" };
  }
  return { ok: true, annotations };
}

/** Measures the compact JSON encoding of one annotation set. */
export function annotationSerializedBytes(annotations: AnnotationSet): number {
  return Buffer.byteLength(JSON.stringify(annotations), "utf8");
}

/** Accepts one annotation value: valid UTF-8, no control characters, no line
 * separators, and at most 256 bytes. The empty value is legal. */
export function validAnnotationValue(value: string): boolean {
  if (Buffer.byteLength(value, "utf8") > MAX_ANNOTATION_VALUE_BYTES) return false;
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return false;
    if (code >= 0x80 && code <= 0x9f) return false;
    if (code === 0x2028 || code === 0x2029) return false;
  }
  return true;
}

/** Parses the launcher-supplied annotation object. An invalid value is ignored
 * entirely and never fatal: a launcher typo must not break the session. */
export function parseLauncherAnnotations(raw: string | undefined): {
  annotations: AnnotationSet;
  reason?: AnnotationReason | "invalid_json";
} {
  if (raw === undefined || raw.trim() === "") return { annotations: {} };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { annotations: {}, reason: "invalid_json" };
  }
  const validated = validateAnnotationSet(parsed);
  if (!validated.ok) return { annotations: {}, reason: validated.reason };
  return { annotations: validated.annotations };
}

/** Builds the live annotation set from the extension-derived sources and the
 * launcher-supplied ones. Extension-derived keys win over launcher keys, and
 * an unusable value is omitted instead of invalidating the whole set. A
 * derived set above the serialized ceiling drops its longest values instead
 * of publishing nothing at all. */
export function buildAnnotationSet(sources: {
  session?: string | undefined;
  state?: string | undefined;
  name?: string | undefined;
  branch?: string | undefined;
  launcher?: AnnotationSet | undefined;
}): AnnotationSet {
  const derived: AnnotationSet = {};
  for (const [key, value] of [
    ["session", sources.session],
    ["state", sources.state],
    ["name", sources.name],
    ["branch", sources.branch],
  ] as const) {
    if (typeof value !== "string" || value === "") continue;
    if (!ANNOTATION_KEY_PATTERN.test(key) || !validAnnotationValue(value)) continue;
    derived[key] = value;
  }
  // The derived keys must fit the ceiling on their own: an oversized set is
  // dropped whole by the relay, and the session would publish nothing at all.
  // The longest derived value goes first.
  for (const key of Object.keys(derived).sort(
    (left, right) => derived[right].length - derived[left].length)) {
    if (annotationSerializedBytes(derived) <= MAX_ANNOTATION_SERIALIZED_BYTES) break;
    delete derived[key];
  }
  const annotations: AnnotationSet = { ...derived };
  const launcher = sources.launcher ?? {};
  for (const key of Object.keys(launcher).sort()) {
    if (Object.keys(annotations).length >= MAX_ANNOTATION_KEYS) break;
    if (Object.hasOwn(annotations, key)) continue;
    const value = launcher[key];
    if (!ANNOTATION_KEY_PATTERN.test(key) || !validAnnotationValue(value)) continue;
    if (annotationSerializedBytes({ ...annotations, [key]: value }) > MAX_ANNOTATION_SERIALIZED_BYTES) continue;
    annotations[key] = value;
  }
  return annotations;
}

/** Reads the current git branch of one working directory. Best effort: a
 * missing git, a non-repository, or a slow lookup yields undefined and the
 * branch is simply omitted. */
export function readGitBranch(cwd: string): Promise<string | undefined> {
  return new Promise((resolve) => {
    try {
      execFile(
        "git",
        ["-C", cwd, "rev-parse", "--abbrev-ref", "HEAD"],
        { timeout: 500, maxBuffer: 4096, windowsHide: true },
        (error, stdout) => {
          if (error) {
            resolve(undefined);
            return;
          }
          const branch = stdout.trim();
          resolve(branch === "" || branch === "HEAD" ? undefined : branch);
        },
      );
    } catch {
      resolve(undefined);
    }
  });
}

/** Injectable clock so the annotation cadence is deterministic in tests. */
export type AnnotationClock = {
  now(): number;
  schedule(callback: () => void, delayMS: number): { cancel(): void };
};

export const productionAnnotationClock: AnnotationClock = Object.freeze({
  now: () => Date.now(),
  schedule: (callback, delayMS) => {
    const timer = setTimeout(callback, delayMS);
    return { cancel: () => clearTimeout(timer) };
  },
});

/** Coalescing publisher for one session's live annotation set. At most one
 * annotate operation leaves the client per interval; a burst of updates
 * collapses into the newest set. */
export class AnnotationPublisher {
  private readonly clock: AnnotationClock;
  private readonly send: (annotations: AnnotationSet) => void;
  private readonly minIntervalMS: number;
  private pending: AnnotationSet | undefined;
  private lastSent: AnnotationSet | undefined;
  private lastSentAt: number | undefined;
  private scheduled: { cancel(): void } | undefined;
  private lastReason: AnnotationReason | undefined;

  constructor(options: {
    clock: AnnotationClock;
    send: (annotations: AnnotationSet) => void;
    minIntervalMS?: number;
  }) {
    this.clock = options.clock;
    this.send = options.send;
    this.minIntervalMS = options.minIntervalMS ?? 1_000;
  }

  /** The stable reason of the last dropped set, or undefined when every set
   * was accepted. */
  get reason(): AnnotationReason | undefined {
    return this.lastReason;
  }

  /** Validates and publishes one replacement set. An invalid set is dropped
   * and never reaches the relay. */
  publish(candidate: unknown): void {
    const validated = validateAnnotationSet(candidate);
    if (!validated.ok) {
      this.lastReason = validated.reason;
      return;
    }
    this.lastReason = undefined;
    this.pending = validated.annotations;
    this.flush(false);
  }

  /** Publishes one replacement set immediately, bypassing the coalescing
   * window and the unchanged-set check. A new connection starts with an empty
   * server-side set, so a reconnect must send the set again. */
  forcePublish(candidate: unknown): void {
    const validated = validateAnnotationSet(candidate);
    if (!validated.ok) {
      this.lastReason = validated.reason;
      return;
    }
    this.lastReason = undefined;
    this.pending = validated.annotations;
    this.flush(true);
  }

  /** Drops every pending and scheduled update. */
  stop(): void {
    this.scheduled?.cancel();
    this.scheduled = undefined;
    this.pending = undefined;
  }

  private flush(force: boolean): void {
    const pending = this.pending;
    if (pending === undefined) return;
    if (!force && this.lastSent !== undefined && sameAnnotationSet(pending, this.lastSent)) {
      this.pending = undefined;
      return;
    }
    const now = this.clock.now();
    const elapsed = this.lastSentAt === undefined ? undefined : now - this.lastSentAt;
    if (!force && elapsed !== undefined && elapsed < this.minIntervalMS) {
      if (this.scheduled === undefined) {
        this.scheduled = this.clock.schedule(() => {
          this.scheduled = undefined;
          this.flush(false);
        }, this.minIntervalMS - elapsed);
      }
      return;
    }
    if (this.scheduled) {
      this.scheduled.cancel();
      this.scheduled = undefined;
    }
    this.pending = undefined;
    this.lastSent = { ...pending };
    this.lastSentAt = now;
    this.send(pending);
  }
}

function sameAnnotationSet(left: AnnotationSet, right: AnnotationSet): boolean {
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  if (leftKeys.length !== rightKeys.length) return false;
  return leftKeys.every((key, index) =>
    key === rightKeys[index] && left[key] === right[key]);
}
