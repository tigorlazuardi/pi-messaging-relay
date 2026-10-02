import { truncateStyledToWidth, visibleWidth, type CardTheme } from "./relay-box.ts";

/**
 * Scrollable bordered overlay for /relay-logs. A real TUI component: every
 * render(width) line is width-measured and hard-truncated via the shared
 * width helpers, so a wide log line can never exceed the overlay or terminal
 * width and crash the host renderer. The window shows the newest lines and
 * scrolls up through history, like a chat transcript.
 */
export class RelayLogsOverlay {
  private readonly load: () => Promise<string>;
  private readonly done: (value: boolean) => void;
  private readonly theme: CardTheme | undefined;
  private readonly requestRender: () => void;
  private lines: string[];
  private scroll = 0; // lines hidden above the window when scrolled back
  private viewport = 24; // last rendered body height; refined each render

  constructor(
    load: () => Promise<string>,
    done: (value: boolean) => void,
    theme?: CardTheme,
    requestRender?: () => void,
    initial?: string,
  ) {
    this.load = load;
    this.done = done;
    this.theme = theme;
    this.requestRender = requestRender ?? (() => undefined);
    this.lines = initial === undefined ? [] : initial.split("\n");
  }

  /** True when the key was consumed; the host stops routing it elsewhere. */
  onKey = (key: string): boolean => {
    if (key === "escape" || key === "return" || key === "q") {
      this.done(true);
      return true;
    }
    if (key === "r") {
      void this.load()
        .then((text) => {
          this.lines = text.split("\n");
          this.scroll = 0;
          this.requestRender();
        })
        .catch(() => undefined);
      return true;
    }
    if (key === "up" || key === "k") {
      this.scroll = Math.min(this.scroll + 1, this.maxScroll());
      this.requestRender();
      return true;
    }
    if (key === "down" || key === "j") {
      this.scroll = Math.max(0, this.scroll - 1);
      this.requestRender();
      return true;
    }
    if (key === "pageup" || key === "b") {
      this.scroll = Math.min(this.scroll + this.viewport, this.maxScroll());
      this.requestRender();
      return true;
    }
    if (key === "pagedown" || key === "space") {
      this.scroll = Math.max(0, this.scroll - this.viewport);
      this.requestRender();
      return true;
    }
    if (key === "end" || key === "g") {
      this.scroll = 0;
      this.requestRender();
      return true;
    }
    return false;
  };

  private maxScroll(): number {
    return Math.max(0, this.lines.length - this.viewport);
  }

  private frame(width: number, left: string, text: string, right: string): string {
    const inner = Math.max(0, width - visibleWidth(left) - visibleWidth(right));
    const content = this.theme ? this.theme.fg("muted", truncateStyledToWidth(text, inner)) : truncateStyledToWidth(text, inner);
    const pad = "─".repeat(Math.max(0, inner - visibleWidth(truncateStyledToWidth(text, inner))));
    const rule = this.theme ? this.theme.fg("muted", pad) : pad;
    return `${left}${content}${rule}${right}`;
  }

  private padded(width: number, text: string): string {
    const inner = Math.max(0, width - 4); // "│ " + " │"
    const content = truncateStyledToWidth(text, inner);
    const padding = " ".repeat(Math.max(0, inner - visibleWidth(content)));
    return `│ ${content}${padding} │`;
  }

  render(width: number): string[] {
    const bordered = this.theme !== undefined;
    const title = " relay logs — r refresh · ↑↓/pgup/pgdn scroll · esc close ";
    const out = [this.frame(width, bordered ? "┌" : " ", title, bordered ? "┐" : " ")];
    const bodyWidth = Math.max(1, width - (bordered ? 4 : 2));
    const maxBodyLines = 24; // ponytail: fixed height; resize with terminal when needed
    const height = Math.max(1, Math.min(this.lines.length, maxBodyLines));
    this.viewport = height;
    // Newest at the bottom: window ends at lines.length - scroll.
    const end = Math.max(0, this.lines.length - this.scroll);
    const start = Math.max(0, end - height);
    for (let index = start; index < end; index += 1) {
      out.push(this.padded(width, this.lines[index] ?? ""));
    }
    const blank = "";
    while (out.length < height + 2) out.push(this.padded(width, blank));
    out.push(this.frame(width, bordered ? "└" : " ", "", bordered ? "┘" : " "));
    return out;
  }
}
