// ponytail: fixed closed status set and fixed "relay" label for one footer
// indicator; make configurable when a second indicator exists.

/** Minimal connection-state signal derived from the existing v2 lifecycle. */
export type RelayConnectionStatus =
  | "connecting"
  | "connected"
  | "disconnected"
  | "config_rejected";

/** Footer status key and label; the label must identify what the circle shows. */
export const RELAY_STATUS_KEY = "pi-messaging-relay";
export const RELAY_STATUS_LABEL = "relay";

export type ThemeForeground = (color: string, text: string) => string;

/** Read one theme foreground renderer from a pi UI context, tolerating hosts without one. */
export function resolveThemeForeground(ui: unknown): ThemeForeground | undefined {
  if (ui === null || typeof ui !== "object") return undefined;
  const theme = (ui as { theme?: unknown }).theme;
  if (theme === null || typeof theme !== "object") return undefined;
  const fg = (theme as { fg?: unknown }).fg;
  if (typeof fg !== "function") return undefined;
  return (fg as ThemeForeground).bind(theme);
}

/** Render the indicator text: green circle only when connected, red otherwise,
 * with the fixed identifying label. */
export function relayStatusText(
  status: RelayConnectionStatus,
  foreground: ThemeForeground | undefined,
): string {
  const circle = "●";
  return `${foreground ? foreground(status === "connected" ? "success" : "error", circle) : circle} ${RELAY_STATUS_LABEL}`;
}
