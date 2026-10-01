import assert from "node:assert/strict";
import test from "node:test";

import {
  RelayCardComponent,
  Text,
  truncateToWidth,
  visibleWidth,
  wrapText,
} from "../internal/relay-box.ts";

const ADDRESS = "/srv/worker@homeserver";
const DETAILS = {
  from: ADDRESS,
  messageID: "01993c84-fc2b-7e1c-af99-61b8118ac6df",
  bodyText: "first line\nsecond line",
};

test("visibleWidth excludes ANSI SGR sequences and zero-width characters", () => {
  assert.equal(visibleWidth("plain"), 5);
  assert.equal(visibleWidth("\u001B[31mred\u001B[0m"), 3);
  assert.equal(visibleWidth("e\u0301 combining"), "e\u0301 combining".length - 1);
  assert.equal(visibleWidth(""), 0);
});

test("truncateToWidth adds an ellipsis only when characters drop", () => {
  assert.equal(truncateToWidth("short", 10), "short");
  assert.equal(truncateToWidth("longer-text", 5), "long…");
  assert.equal(visibleWidth(truncateToWidth("longer-text", 5)), 5);
  assert.equal(truncateToWidth("anything", 0), "");
});

test("wrapText wraps on spaces, splits long words, and preserves empty lines", () => {
  assert.deepEqual(wrapText("aaa bbb ccc", 7), ["aaa bbb", "ccc"]);
  assert.deepEqual(wrapText("abcdefghij", 4), ["abcd", "efgh", "ij"]);
  assert.deepEqual(wrapText("a\n\nb", 5), ["a", "", "b"]);
  assert.deepEqual(wrapText("", 5), [""]);
  assert.deepEqual(wrapText("tiny", 0), []);
});

test("card renders a consistent box with header, body, and reply hint", () => {
  // Real ANSI wraps (like pi themes produce); width invariants hold per line.
  const theme = {
    fg: (color: string, text: string) => `\u001B[31m${text}\u001B[0m`,
    bold: (text: string) => text,
  };
  const lines = new RelayCardComponent(DETAILS, theme, false).render(80);
  assert.equal(lines.length >= 5, true);
  const plain = (line: string) => line.replace(/\u001B\[[0-9;]*m/g, "");
  for (const line of lines) assert.equal(plain(line).length, 80);
  assert.match(lines[0]!, /^\u001B\[31m╭/);
  assert.match(plain(lines[0]!), /^╭.+╮$/);
  assert.match(lines[0]!, /relay message from/);
  assert.match(plain(lines.at(-1)!), /^╰─+╯$/);
  const flat = lines.join("\n");
  assert.match(flat, /first line/);
  assert.match(flat, /second line/);
  assert.match(flat, /reply via agent_send/);
  assert.match(flat, /ctrl\+o expands/);
});

test("expanded card preserves exact newlines and drops the expand hint", () => {
  const lines = new RelayCardComponent(DETAILS, undefined, true).render(60);
  const flat = lines.join("\n");
  assert.match(flat, /first line/);
  assert.match(flat, /second line/);
  assert.match(flat, /relay message from/);
  assert.equal(flat.includes("ctrl+o expands"), false);
});

test("card wraps long bodies within the frame at narrow widths", () => {
  const details = { ...DETAILS, bodyText: "word ".repeat(40).trim() };
  for (const width of [20, 41, 80]) {
    const lines = new RelayCardComponent(details, undefined, false).render(width);
    for (const line of lines) {
      assert.equal(visibleWidth(line.replace(/\x1b\[[0-9;]*m/g, "")) <= width, true);
    }
  }
});

test("reply hint quotes the full opaque address for agent_send", () => {
  const lines = new RelayCardComponent(DETAILS, undefined, false).render(200);
  assert.match(lines.join("\n"), new RegExp(ADDRESS.replace(/[/.@]/g, "\\$&")));
});

test("re-flagged card renders the reply correlation id", () => {
  const lines = new RelayCardComponent(
    { ...DETAILS, re: "01993c80-40de-79d7-9b2c-1349f88bb408" },
    undefined,
    false,
  ).render(120);
  assert.match(lines.join("\n"), /re=01993c80/);
});

test("narrow card degrades to one truncated line without a frame", () => {
  const lines = new RelayCardComponent(DETAILS, undefined, false).render(60);
  assert.match(lines[0]!, /relay message from/);
  const narrow = new RelayCardComponent(DETAILS, undefined, false).render(4);
  assert.equal(narrow.length, 1);
  assert.equal(visibleWidth(narrow[0]!), 4);
});

test("Text renders one line regardless of width", () => {
  const component = new Text("hello");
  assert.deepEqual(component.render(10), ["hello"]);
  assert.deepEqual(component.render(2), ["hello"]);
});
