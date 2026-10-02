import assert from "node:assert/strict";
import test from "node:test";

import {
  RelayCardComponent,
  Text,
  truncateStyledToWidth,
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

test("card paints a full-row background when the host exposes theme.bg", () => {
  const calls: string[] = [];
  const theme = {
    fg: (color: string, text: string) => `\u001B[31m${text}\u001B[0m`,
    bold: (text: string) => text,
    bg: (color: string, text: string) => {
      calls.push(color);
      return `\u001B[44m${text}\u001B[0m`;
    },
  };
  const lines = new RelayCardComponent(DETAILS, theme, false).render(80);
  const plain = (line: string) => line.replace(/\u001B\[[0-9;]*m/g, "");
  // Every row is one full-width background span: bg wraps the padded line.
  for (const line of lines) {
    assert.match(line, /^\u001B\[44m/);
    assert.match(line, /\u001B\[0m$/);
    assert.equal(plain(line).length, 80);
  }
  assert.ok(calls.length >= lines.length);
  assert.ok(calls.every((color) => color === "customMessageBg"));
});

test("card without theme.bg renders unchanged plain frame", () => {
  const theme = {
    fg: (color: string, text: string) => `\u001B[31m${text}\u001B[0m`,
    bold: (text: string) => text,
  };
  const lines = new RelayCardComponent(DETAILS, theme, false).render(80);
  for (const line of lines) {
    assert.equal(line.includes("\u001B\[44m"), false);
  }
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
  assert.deepEqual(component.render(2), ["h…"]); // width-1 chars + ellipsis
});

test("Text truncates styled tool lines to terminal width", () => {
  // Shape of the crashing line: label + quoted body + → + full address.
  const theme = {
    fg: (color: string, s: string) => `\u001B[${color === "accent" ? 34 : color === "muted" ? 90 : 1}m${s}\u001B[22m`,
    bold: (s: string) => s,
  };
  const styled = theme.fg("toolTitle", theme.bold("agent_send")) +
    theme.fg("muted", ` "${"x".repeat(60)}"`) +
    " → " +
    theme.fg("accent", "/home/homeserver/homelab@Config-Management");
  const component = new Text(styled);
  for (const width of [91, 55, 40, 20]) {
    const [line] = component.render(width);
    assert.ok(line, `line for width ${width}`);
    assert.equal(visibleWidth(line), width, `width ${width}`);
  }
  assert.match(component.render(20)[0]!, /\u001B\[0m$/); // style closed
});

test("truncateStyledToWidth preserves styles and closes open SGR", () => {
  const styled = "\u001B[1mbold-label\u001B[22m\u001B[2m \"body text\"\u001B[22m → \u001B[34m/path@host\u001B[22m";
  const out = truncateStyledToWidth(styled, 30);
  assert.equal(visibleWidth(out), 30);
  assert.match(out, /\u001B\[0m$/); // style closed so color cannot bleed
  assert.match(out, /bold-label/);
  // Untouched input is returned as-is (no ellipsis/reset appended).
  const untouched = truncateStyledToWidth("\u001B[1mshort\u001B[22m", 50);
  assert.equal(untouched, "\u001B[1mshort\u001B[22m");
  // Pi-style nested wraps (intermediate resets) still measured correctly.
  const wrapped = "\u001B[4murl\u001B[24m\u001B[24mrest\u001B[24m";
  assert.equal(visibleWidth(truncateStyledToWidth(wrapped, 4)), 4);
});
