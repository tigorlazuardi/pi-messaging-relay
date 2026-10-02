// ponytail: fixed to a box-drawing card with local ANSI width helpers; import
// @earendil-works/pi-tui instead when the extension ever ships inside a host
// that resolves it (Nix-installed pi does not).

/** Theme subset the card needs; hosts without a theme get plain text.
 * bg is optional: hosts exposing theme.bg paint the card's full-row
 * background (customMessageBg), pi-intercom style. */
export type CardTheme = {
  fg: (color: string, text: string) => string;
  bold: (text: string) => string;
  bg?: (color: string, text: string) => string;
};

const ANSI_PATTERN = new RegExp("\\u001B\\[[0-9;]*m", "g");

/** Visible width with ANSI SGR sequences and zero-width chars excluded. */
export function visibleWidth(text: string): number {
  let width = 0;
  const stripped = text.replace(ANSI_PATTERN, "");
  for (const character of stripped) {
    const code = character.codePointAt(0) ?? 0;
    // Combining marks and zero-width joiners add no columns.
    if ((code >= 0x0300 && code <= 0x036f) || code === 0x200d || code === 0xfe0f) continue;
    width += 1;
  }
  return width;
}

/* Zero-width exclusions shared by the width helpers. */
function isZeroWidth(code: number): boolean {
  // Combining marks and zero-width joiners add no columns.
  return (code >= 0x0300 && code <= 0x036f) || code === 0x200d || code === 0xfe0f;
}

/** Hard-truncates to at most width visible columns while preserving ANSI SGR
 * sequences, keeping a trailing ellipsis within the budget when characters
 * drop, and closing any open style so color cannot bleed past the line. */
export function truncateStyledToWidth(text: string, width: number): string {
  if (width <= 0) return "";
  const totalVisible = visibleWidth(text);
  if (totalVisible <= width) return text;
  let out = "";
  let column = 0;
  let sawStyle = false;
  const budget = width - 1; // reserve one column for the ellipsis
  for (let index = 0; index < text.length;) {
    const sgr = /^\u001B\[[0-9;]*m/.exec(text.slice(index));
    if (sgr) {
      out += sgr[0];
      sawStyle = true;
      index += sgr[0].length;
      continue;
    }
    const code = text.codePointAt(index) ?? 0;
    const character = String.fromCodePoint(code);
    if (!isZeroWidth(code)) {
      if (column >= budget) break;
      column += 1;
    }
    out += character;
    index += character.length;
  }
  out += "…";
  if (sawStyle) out += "\u001B[0m";
  return out;
}

/** Hard-truncates to at most width visible columns, keeping a trailing
 * ellipsis within the budget when characters drop. */
export function truncateToWidth(text: string, width: number): string {
  if (width <= 0) return "";
  const chars = Array.from(text.replace(ANSI_PATTERN, ""));
  if (chars.length <= width) return chars.join("");
  return chars.slice(0, Math.max(0, width - 1)).join("") + "…";
}

/** Word-wraps to width; long unbroken words are hard-split so the frame holds. */
export function wrapText(text: string, width: number): string[] {
  if (width <= 0) return [];
  const lines: string[] = [];
  for (const sourceLine of text.split("\n")) {
    if (sourceLine === "") {
      lines.push("");
      continue;
    }
    let current = "";
    for (let word of sourceLine.split(" ")) {
      while (visibleWidth(word) > width) {
        if (current !== "") {
          lines.push(current);
          current = "";
        }
        let slice = "";
        let sliceWidth = 0;
        for (const character of word) {
          if (sliceWidth + 1 > width) break;
          slice += character;
          sliceWidth += 1;
        }
        lines.push(slice);
        word = word.slice(slice.length);
      }
      if (current === "") current = word;
      else if (visibleWidth(current) + 1 + visibleWidth(word) <= width) current += ` ${word}`;
      else {
        lines.push(current);
        current = word;
      }
    }
    if (current !== "") lines.push(current);
  }
  return lines.length > 0 ? lines : [""];
}

/** Minimal single-line component matching the pi-tui Text render contract
 * (render(width) -> string[]) without importing the host's TUI package. */
export class Text {
  private readonly value: string;

  constructor(value: string) {
    this.value = value;
  }

  render(width: number): string[] {
    return [truncateStyledToWidth(this.value, width)];
  }

  invalidate(): void {}
}

export type RelayCardDetails = {
  from: string;
  messageID: string;
  re?: string;
  bodyText: string;
};

/** Renders the boxed inbound message card as a Component-like object. */
export class RelayCardComponent {
  private readonly details: RelayCardDetails;
  private readonly theme: CardTheme | undefined;
  private readonly expanded: boolean;
  private wrapped?: { width: number; lines: string[] };

  constructor(details: RelayCardDetails, theme: CardTheme | undefined, expanded: boolean) {
    this.details = details;
    this.theme = theme;
    this.expanded = expanded;
  }

  render(width: number): string[] {
    // A renderer throw must never kill the host session; degrade to the
    // one-line fallback (observed: unbound theme methods crashing render).
    try {
      return this.renderLines(width);
    } catch {
      try {
        return [truncateToWidth(`relay message from ${this.details.from}`, Math.max(1, width))];
      } catch {
        return ["relay message"];
      }
    }
  }

  private renderLines(width: number): string[] {
    const muted = (text: string) => this.theme ? this.theme.fg("muted", text) : text;
    const title = (text: string) => this.theme ? this.theme.fg("toolTitle", text) : text;
    const dim = (text: string) => this.theme ? this.theme.fg("dim", text) : text;
    const text = (value: string) => this.theme ? this.theme.fg("text", value) : value;
    // Intercom-style full-row background: paint each padded line when the
    // host exposes theme.bg. Applied last so fg styles nest inside it.
    const paint = this.theme?.bg
      ? (line: string) => this.theme!.bg!("customMessageBg", line)
      : (line: string) => line;

    const lines: string[] = [];
    if (width < 8) return [paint(truncateToWidth(`relay message from ${this.details.from}`, Math.max(1, width)))];
    const bodyWidth = Math.max(1, width - 2);

    const shortFrom = truncateToWidth(this.details.from, Math.max(1, bodyWidth - 30));
    const header = ` relay message from ${shortFrom} `;
    const headerText = truncateToWidth(header, bodyWidth);
    const headerPadding = Math.max(0, bodyWidth - visibleWidth(headerText));
    lines.push(paint(muted("╭") + title(headerText) + muted(`${"─".repeat(headerPadding)}╮`)));

    const frame = (content: string): string => {
      const clipped = truncateToWidth(content, bodyWidth);
      const padding = Math.max(0, bodyWidth - visibleWidth(clipped));
      return muted("│") + clipped + muted(`${" ".repeat(padding)}│`);
    };

    const bodyLines = this.expanded
      ? this.details.bodyText.split("\n")
      : (this.wrapped?.width === bodyWidth ? this.wrapped : this.wrapped = {
        width: bodyWidth,
        lines: wrapText(this.details.bodyText.replace(/\n+$/g, ""), bodyWidth),
      }).lines;
    for (const line of bodyLines) lines.push(paint(frame(text(line))));

    const meta: string[] = [`reply via agent_send to=${JSON.stringify(this.details.from)}`];
    if (this.details.re !== undefined) meta.push(`re=${this.details.re.slice(0, 8)}`);
    if (!this.expanded) meta.push("ctrl+o expands");
    const metaPlain = ` ${meta.join(" · ")}`;
    for (const metaLine of wrapText(metaPlain, bodyWidth)) {
      lines.push(paint(frame(dim(metaLine))));
    }
    lines.push(paint(muted(`╰${"─".repeat(bodyWidth)}╯`)));
    return lines;
  }
}
