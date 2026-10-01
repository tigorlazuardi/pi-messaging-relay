import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  appendDiagnosticLine,
  readSessionLogTail,
  resolveSessionLogPath,
} from "../internal/session-log.ts";

describe("resolveSessionLogPath", () => {
  const home = "/home/operator";

  it("names one file after the persisted session under the state dir", () => {
    const path = resolveSessionLogPath({}, home, "/srv/pi/.sessions/abc123.jsonl");
    assert.equal(path, `${home}/.local/state/pi-messaging-relay/sessions/abc123.jsonl.log.jsonl`);
  });

  it("honors XDG_STATE_HOME and the explicit env override", () => {
    assert.equal(
      resolveSessionLogPath({ XDG_STATE_HOME: "/xdg/state" }, home, "/s/one.jsonl"),
      "/xdg/state/pi-messaging-relay/sessions/one.jsonl.log.jsonl",
    );
    assert.equal(
      resolveSessionLogPath({ PI_MESSAGING_RELAY_LOG_DIR: "/var/log/relay" }, home, "/s/one.jsonl"),
      "/var/log/relay/one.jsonl.log.jsonl",
    );
  });

  it("returns undefined for in-memory sessions and unsafe names", () => {
    assert.equal(resolveSessionLogPath({}, home, undefined), undefined);
    assert.equal(resolveSessionLogPath({}, home, ""), undefined);
    // Only the basename is read; traversal cannot escape the log directory.
    assert.equal(
      resolveSessionLogPath({}, home, "/s/../../escape.jsonl"),
      `${home}/.local/state/pi-messaging-relay/sessions/escape.jsonl.log.jsonl`,
    );
    assert.equal(resolveSessionLogPath({}, home, "/s/with space.jsonl"), undefined);
    assert.equal(resolveSessionLogPath({}, home, "/s/not-a-session.txt"), undefined);
  });
});

describe("appendDiagnosticLine", () => {
  it("appends newline-terminated lines fire-and-forget", async (t) => {
    const dir = await mkdtemp(join(tmpdir(), "pi-relay-session-log-"));
    t.after(() => rm(dir, { recursive: true, force: true }));
    const path = join(dir, "one.jsonl.log.jsonl");
    appendDiagnosticLine(path, '{"event":"one"}');
    appendDiagnosticLine(path, '{"event":"two"}');
    // Weak synchronization: no await inside the emit path; poll the file.
    const deadline = Date.now() + 2_000;
    let content = "";
    while (Date.now() < deadline) {
      content = await readFile(path, "utf8").catch(() => "");
      if (content.split("\n").filter((line) => line.length > 0).length >= 2) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(content, '{"event":"one"}\n{"event":"two"}\n');
  });

  it("creates the directory on first write and never throws", async (t) => {
    const dir = await mkdtemp(join(tmpdir(), "pi-relay-session-log-"));
    t.after(() => rm(dir, { recursive: true, force: true }));
    const path = join(dir, "nested", "deeper", "one.jsonl.log.jsonl");
    assert.doesNotThrow(() => appendDiagnosticLine(path, '{"event":"late"}'));
    const deadline = Date.now() + 2_000;
    let content = "";
    while (Date.now() < deadline) {
      content = await readFile(path, "utf8").catch(() => "");
      if (content.length > 0) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(content, '{"event":"late"}\n');
  });
});

describe("readSessionLogTail", () => {
  it("returns newest-last lines capped at the requested maximum", async (t) => {
    const dir = await mkdtemp(join(tmpdir(), "pi-relay-session-log-"));
    t.after(() => rm(dir, { recursive: true, force: true }));
    const path = join(dir, "one.jsonl.log.jsonl");
    await writeFile(path, ["a", "b", "c", "d"].map((line) => `{"n":"${line}"}\n`).join(""));
    assert.deepEqual(await readSessionLogTail(path, 2), ['{"n":"c"}', '{"n":"d"}']);
    assert.deepEqual(await readSessionLogTail(path, 10), [
      '{"n":"a"}',
      '{"n":"b"}',
      '{"n":"c"}',
      '{"n":"d"}',
    ]);
  });

  it("reads missing and empty files as empty", async (t) => {
    assert.deepEqual(await readSessionLogTail(join(tmpdir(), "missing-dir-xyz", "none.jsonl.log.jsonl"), 5), []);
    const dir = await mkdtemp(join(tmpdir(), "pi-relay-session-log-"));
    t.after(() => rm(dir, { recursive: true, force: true }));
    const path = join(dir, "empty.jsonl.log.jsonl");
    await writeFile(path, "");
    assert.deepEqual(await readSessionLogTail(path, 5), []);
  });
});
