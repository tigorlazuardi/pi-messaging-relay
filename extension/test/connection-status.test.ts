import assert from "node:assert/strict";
import test from "node:test";

import {
  relayStatusText,
  RELAY_STATUS_KEY,
  RELAY_STATUS_LABEL,
  resolveThemeForeground,
} from "../internal/connection-status.ts";

const themedFg = (color: string, text: string): string => `${color}:${text}`;

test("indicator renders a green circle only for the connected status", () => {
  assert.equal(relayStatusText("connected", themedFg), "success:● relay");
});

test("indicator renders a red circle for every not-connected status", () => {
  for (const status of ["connecting", "disconnected", "config_rejected"] as const) {
    assert.equal(relayStatusText(status, themedFg), "error:● relay");
  }
});

test("indicator keeps the identifying relay label beside the circle", () => {
  assert.equal(RELAY_STATUS_LABEL, "relay");
  assert.match(relayStatusText("connected", themedFg), / relay$/);
});

test("indicator degrades to an uncolored circle without a theme renderer", () => {
  assert.equal(relayStatusText("connected", undefined), "● relay");
  assert.equal(relayStatusText("disconnected", undefined), "● relay");
});

test("resolveThemeForeground binds a present theme renderer and rejects junk", () => {
  const ui = { theme: { fg(color: string, text: string): string { return `${color}!${text}`; } } };
  const resolved = resolveThemeForeground(ui);
  assert.ok(resolved);
  assert.equal(resolved("success", "●"), "success!●");
  assert.equal(resolveThemeForeground(undefined), undefined);
  assert.equal(resolveThemeForeground(null), undefined);
  assert.equal(resolveThemeForeground("nope"), undefined);
  assert.equal(resolveThemeForeground({ theme: null }), undefined);
  assert.equal(resolveThemeForeground({ theme: {} }), undefined);
});

test("footer status key is stable and extension-scoped", () => {
  assert.equal(RELAY_STATUS_KEY, "pi-messaging-relay");
});
