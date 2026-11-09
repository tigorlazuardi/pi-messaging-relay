import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  AnnotationPublisher,
  buildAnnotationSet,
  parseLauncherAnnotations,
  readGitBranch,
  validateAnnotationSet,
  type AnnotationClock,
  type AnnotationSet,
} from "../internal/annotations.ts";

/** Deterministic clock: time only moves when the test moves it. */
function fakeClock(): AnnotationClock & { advance(delayMS: number): void } {
  let current = 0;
  const scheduled: Array<{ at: number; callback: () => void; cancelled: boolean }> = [];
  return {
    now: () => current,
    schedule: (callback, delayMS) => {
      const entry = { at: current + delayMS, callback, cancelled: false };
      scheduled.push(entry);
      return {
        cancel: () => {
          entry.cancelled = true;
        },
      };
    },
    advance: (delayMS: number) => {
      current += delayMS;
      for (const entry of [...scheduled]) {
        if (entry.cancelled || entry.at > current) continue;
        entry.cancelled = true;
        entry.callback();
      }
    },
  };
}

test("annotation validation mirrors the relay limits", () => {
  const accepted = validateAnnotationSet({ name: "alice", state: "idle", empty: "" });
  assert.equal(accepted.ok, true);
  if (accepted.ok) assert.deepEqual(accepted.annotations, { name: "alice", state: "idle", empty: "" });

  const rejected: Array<[unknown, string]> = [
    [null, "invalid_payload"],
    [["name"], "invalid_payload"],
    [{ Name: "alice" }, "invalid_key"],
    [{ "na me": "alice" }, "invalid_key"],
    [{ "1name": "alice" }, "invalid_key"],
    [{ name: 42 }, "invalid_value"],
    [{ name: "a\nb" }, "invalid_value"],
    [{ name: "ab" }, "invalid_value"],
    [{ name: "x".repeat(257) }, "invalid_value"],
    [{ a1: "v", a2: "v", a3: "v", a4: "v", a5: "v", a6: "v", a7: "v", a8: "v", a9: "v" }, "too_many_keys"],
    [{ a1: "x".repeat(250), a2: "x".repeat(250), a3: "x".repeat(250), a4: "x".repeat(250), a5: "x".repeat(250) }, "too_large"],
  ];
  for (const [candidate, reason] of rejected) {
    const result = validateAnnotationSet(candidate);
    assert.equal(result.ok, false, `${JSON.stringify(candidate)} was accepted`);
    if (!result.ok) assert.equal(result.reason, reason);
  }
});

test("launcher annotations are ignored entirely when invalid and never fatal", () => {
  assert.deepEqual(parseLauncherAnnotations(undefined).annotations, {});
  assert.deepEqual(parseLauncherAnnotations("").annotations, {});
  const broken = parseLauncherAnnotations("{not json");
  assert.deepEqual(broken.annotations, {});
  assert.equal(broken.reason, "invalid_json");
  const wrongShape = parseLauncherAnnotations("[1,2]");
  assert.deepEqual(wrongShape.annotations, {});
  const valid = parseLauncherAnnotations(JSON.stringify({ role: "implementer", parent: "/srv/x@host#id" }));
  assert.deepEqual(valid.annotations, { role: "implementer", parent: "/srv/x@host#id" });
});

test("extension-derived annotation keys win over launcher keys", () => {
  const annotations = buildAnnotationSet({
    session: "session-a",
    state: "idle",
    name: "reviewer",
    branch: "feature/annotations",
    launcher: { role: "implementer", session: "launcher-session", task: "review the roster" },
  });
  assert.deepEqual(annotations, {
    session: "session-a",
    state: "idle",
    name: "reviewer",
    branch: "feature/annotations",
    role: "implementer",
    task: "review the roster",
  });
});

test("unusable annotation sources are omitted instead of invalidating the set", () => {
  const annotations = buildAnnotationSet({
    session: "",
    state: "idle",
    name: "x".repeat(300),
    branch: "main",
    launcher: { "bad key": "value", role: "reviewer" },
  });
  assert.deepEqual(annotations, { state: "idle", branch: "main", role: "reviewer" });
});

test("the annotation set stays inside the relay key and size ceilings", () => {
  const launcher: AnnotationSet = {};
  for (let index = 0; index < 20; index += 1) launcher[`key${index}`] = "value";
  const annotations = buildAnnotationSet({ state: "idle", launcher });
  assert.equal(Object.keys(annotations).length, 8);
  assert.equal(annotations.state, "idle");
  assert.equal(Buffer.byteLength(JSON.stringify(annotations), "utf8") <= 1024, true);
});

test("annotation updates coalesce into at most one send per second", () => {
  const clock = fakeClock();
  const sent: AnnotationSet[] = [];
  const publisher = new AnnotationPublisher({
    clock,
    send: (annotations) => sent.push(annotations),
  });

  publisher.publish({ state: "idle" });
  assert.deepEqual(sent, [{ state: "idle" }]);

  publisher.publish({ state: "busy" });
  publisher.publish({ state: "busy", name: "worker" });
  assert.deepEqual(sent, [{ state: "idle" }], "bursts inside the window must not send");

  clock.advance(1_000);
  assert.deepEqual(sent, [{ state: "idle" }, { state: "busy", name: "worker" }]);

  // An unchanged set never leaves the client.
  publisher.publish({ state: "busy", name: "worker" });
  clock.advance(2_000);
  assert.equal(sent.length, 2);
});

test("an invalid annotation set is dropped and never reaches the relay", () => {
  const clock = fakeClock();
  const sent: AnnotationSet[] = [];
  const publisher = new AnnotationPublisher({
    clock,
    send: (annotations) => sent.push(annotations),
  });
  publisher.publish({ "bad key": "value" });
  assert.deepEqual(sent, []);
  assert.equal(publisher.reason, "invalid_key");
  publisher.publish({ state: "idle" });
  assert.deepEqual(sent, [{ state: "idle" }]);
  assert.equal(publisher.reason, undefined);
});

test("a forced publish sends the current set immediately for a fresh connection", () => {
  const clock = fakeClock();
  const sent: AnnotationSet[] = [];
  const publisher = new AnnotationPublisher({
    clock,
    send: (annotations) => sent.push(annotations),
  });
  publisher.publish({ state: "idle" });
  assert.equal(sent.length, 1);
  publisher.forcePublish({ state: "busy" });
  assert.deepEqual(sent, [{ state: "idle" }, { state: "busy" }]);
});

test("the git branch is best effort and omitted when it cannot be read", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-relay-branch-"));
  try {
    assert.equal(await readGitBranch(join(root, "missing-directory")), undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
