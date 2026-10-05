// ponytail: fixed 8-page /relay-peers roster walk and fixed full-route
// column; make configurable when a production roster fills 8 pages or a
// second display profile exists.
import {
  truncateToWidth,
  visibleWidth,
  type CardTheme,
} from "./relay-box.ts";

/** Entry customType for display-only peer roster snapshots. Custom entries
 * never reach LLM context; the entry renderer paints them user-side only. */
export const PEER_ROSTER_ENTRY_TYPE = "pi-messaging-relay-peer-roster-v1";

const MAX_ROSTER_PAGES = 8;
const UUID_DASHED_LENGTH = 36;

/** Injected roster transport so the view never touches sockets directly. */
export type RosterListFunction = (cursor: string | undefined) => Promise<{
  peers?: Array<{ address?: unknown }>;
  next_cursor?: unknown;
}>;

export type PeerRosterPeer = {
  cwd: string;
  hostname: string;
  routeID: string;
};

export type PeerRosterGroup = {
  hostname: string;
  peers: PeerRosterPeer[];
};

/** User-side display snapshot. Addresses are never stored whole: the card
 * recomposes cwd@hostname#routeID from parts for copy-paste sending. */
export type PeerRosterSnapshot = {
  groups: PeerRosterGroup[];
  totalCount: number;
  truncated: boolean;
};

const UNPARSED_HOSTNAME = "(unparsed)";

/** Splits one opaque relay address `cwd@hostname#routeID` on the LAST
 * separators so cwd may contain @ or # and hostname may contain @. Anything
 * malformed falls into one "(unparsed)" group with the raw address as cwd. */
export function parsePeerAddress(address: string): PeerRosterPeer {
  const hash = address.lastIndexOf("#");
  const routeCandidate = hash >= 0 ? address.slice(hash + 1) : "";
  const head = hash >= 0 ? address.slice(0, hash) : address;
  const at = head.lastIndexOf("@");
  if (hash < 0 || at < 0 || routeCandidate.length !== UUID_DASHED_LENGTH || head === "") {
    return { cwd: address, hostname: UNPARSED_HOSTNAME, routeID: "" };
  }
  return { cwd: head.slice(0, at), hostname: head.slice(at + 1), routeID: routeCandidate };
}

/** Walks address-only roster pages through the injected list function until
 * the relay reports exhaustion or the fixed page budget is hit. `truncated`
 * marks a budget hit so the card can say the view is partial. */
export async function buildPeerRosterSnapshot(list: RosterListFunction): Promise<PeerRosterSnapshot> {
  const addresses: string[] = [];
  let cursor: string | undefined;
  let truncated = true;
  for (let page = 0; page < MAX_ROSTER_PAGES; page += 1) {
    const result = await list(cursor);
    const peers = Array.isArray(result?.peers) ? result.peers : [];
    for (const peer of peers) {
      if (peer !== null && typeof peer === "object" && typeof peer.address === "string") {
        addresses.push(peer.address);
      }
    }
    const next = result?.next_cursor;
    if (typeof next !== "string" || next === "") {
      truncated = false;
      break;
    }
    cursor = next;
  }
  const groups = new Map<string, PeerRosterGroup>();
  for (const address of addresses) {
    const peer = parsePeerAddress(address);
    const group = groups.get(peer.hostname);
    if (group) group.peers.push(peer);
    else groups.set(peer.hostname, { hostname: peer.hostname, peers: [peer] });
  }
  const sorted = [...groups.values()].sort((left, right) =>
    left.hostname < right.hostname ? -1 : left.hostname > right.hostname ? 1 : 0
  );
  for (const group of sorted) {
    group.peers.sort((left, right) =>
      left.cwd < right.cwd ? -1 : left.cwd > right.cwd ? 1 : left.routeID < right.routeID ? -1 : left.routeID > right.routeID ? 1 : 0
    );
  }
  return { groups: sorted, totalCount: addresses.length, truncated };
}

/** Rebuilds a snapshot from persisted entry data, or undefined when the shape
 * does not match; restored sessions must never render foreign entry data. */
export function snapshotFromUnknown(value: unknown): PeerRosterSnapshot | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as { groups?: unknown; totalCount?: unknown; truncated?: unknown };
  if (!Array.isArray(record.groups) || typeof record.totalCount !== "number" ||
      typeof record.truncated !== "boolean") {
    return undefined;
  }
  const groups: PeerRosterGroup[] = [];
  for (const group of record.groups) {
    if (group === null || typeof group !== "object" || Array.isArray(group)) return undefined;
    const groupRecord = group as { hostname?: unknown; peers?: unknown };
    if (typeof groupRecord.hostname !== "string" || !Array.isArray(groupRecord.peers)) return undefined;
    const peers: PeerRosterPeer[] = [];
    for (const peer of groupRecord.peers) {
      if (peer === null || typeof peer !== "object" || Array.isArray(peer)) return undefined;
      const peerRecord = peer as { cwd?: unknown; hostname?: unknown; routeID?: unknown };
      if (typeof peerRecord.cwd !== "string" || typeof peerRecord.hostname !== "string" ||
          typeof peerRecord.routeID !== "string") {
        return undefined;
      }
      peers.push({ cwd: peerRecord.cwd, hostname: peerRecord.hostname, routeID: peerRecord.routeID });
    }
    groups.push({ hostname: groupRecord.hostname, peers });
  }
  return { groups, totalCount: record.totalCount, truncated: record.truncated };
}

/** Reads the newest persisted roster snapshot from session entries, or
 * undefined when none survives; used on session_start restore. */
export function restorePeerRosterSnapshot(context: {
  sessionManager: { getEntries(): unknown[] };
}): PeerRosterSnapshot | undefined {
  const entries = context.sessionManager.getEntries();
  for (let index = entries.length - 1; index >= 0; index -= 1) {
    const candidate = entries[index];
    if (candidate === null || typeof candidate !== "object" ||
        (candidate as { type?: unknown }).type !== "custom" ||
        (candidate as { customType?: unknown }).customType !== PEER_ROSTER_ENTRY_TYPE) {
      continue;
    }
    return snapshotFromUnknown((candidate as { data?: unknown }).data);
  }
  return undefined;
}

/** Renders the grouped markdown tables as a bordered card. Every line is
 * width-measured and hard-truncated through the shared width helpers, so a
 * long cwd or hostname can never exceed the terminal and crash the host
 * renderer. Painted with customMessageBg when the host exposes theme.bg so
 * the card reads as relay UI, not a chat message. */
export class PeerRosterCardComponent {
  private readonly snapshot: PeerRosterSnapshot;
  private readonly theme: CardTheme | undefined;

  constructor(snapshot: PeerRosterSnapshot, theme: CardTheme | undefined) {
    this.snapshot = snapshot;
    this.theme = theme;
  }

  render(width: number): string[] {
    // A renderer throw must never kill the host session; degrade to one line.
    try {
      return this.renderLines(width);
    } catch {
      try {
        return [truncateToWidth(`relay peers — ${this.snapshot.totalCount} online`, Math.max(1, width))];
      } catch {
        return ["relay peers"];
      }
    }
  }

  private renderLines(width: number): string[] {
    const muted = (text: string) => this.theme ? this.theme.fg("muted", text) : text;
    const title = (text: string) => this.theme ? this.theme.fg("toolTitle", this.theme.bold(text)) : text;
    // Intercom-style full-row background; applied last so fg styles nest inside it.
    const paint = this.theme?.bg
      ? (line: string) => this.theme!.bg!("customMessageBg", line)
      : (line: string) => line;

    if (width < 12) {
      return [paint(truncateToWidth(`relay peers — ${this.snapshot.totalCount} online`, Math.max(1, width)))];
    }
    const bodyWidth = Math.max(1, width - 2);
    const frame = (content: string): string => {
      const clipped = truncateToWidth(content, bodyWidth);
      const padding = Math.max(0, bodyWidth - visibleWidth(clipped));
      return muted("│") + clipped + muted(`${" ".repeat(padding)}│`);
    };

    const lines: string[] = [];
    const partial = this.snapshot.truncated ? " (partial)" : "";
    const header = ` relay peers — ${this.snapshot.totalCount} online${partial} `;
    const headerText = truncateToWidth(header, bodyWidth);
    const headerPadding = Math.max(0, bodyWidth - visibleWidth(headerText));
    lines.push(paint(muted("╭") + title(headerText) + muted(`${"─".repeat(headerPadding)}╮`)));

    if (this.snapshot.totalCount === 0 || this.snapshot.groups.length === 0) {
      lines.push(paint(frame(muted("no peers online"))));
      lines.push(paint(muted(`╰${"─".repeat(bodyWidth)}╯`)));
      return lines;
    }

    for (const group of this.snapshot.groups) {
      const section = ` ── ${group.hostname} (${group.peers.length}) `;
      const sectionText = truncateToWidth(section, bodyWidth);
      const sectionPadding = Math.max(0, bodyWidth - visibleWidth(sectionText));
      lines.push(paint(muted("├") + title(sectionText) + muted(`${"─".repeat(sectionPadding)}┤`)));
      for (const line of this.renderTable(group, bodyWidth)) lines.push(paint(frame(line)));
    }
    lines.push(paint(muted(`╰${"─".repeat(bodyWidth)}╯`)));
    return lines;
  }

  /** One markdown table for one hostname group: CWD and ROUTE columns; the
   * full address recomposes as cwd@hostname#routeID. Route stays whole so
   * copy-paste keeps working; only cwd absorbs narrow terminals. */
  private renderTable(group: PeerRosterGroup, bodyWidth: number): string[] {
    const muted = (text: string) => this.theme ? this.theme.fg("muted", text) : text;
    const headerCell = (text: string) => this.theme ? this.theme.fg("toolTitle", text) : text;
    const cell = (text: string) => this.theme ? this.theme.fg("text", text) : text;
    // `| a | b |` chrome: "| " + col + " | " + col + " |".
    const available = Math.max(2, bodyWidth - 7);
    const routeWidth = Math.max(1, Math.min(UUID_DASHED_LENGTH, available - 4));
    const cwdWidth = Math.max(1, available - routeWidth);

    const routeCellText = (routeID: string) => routeID === "" ? "—" : routeID;
    const pad = (value: string, width: number) => {
      const clipped = truncateToWidth(value, width);
      return clipped + " ".repeat(Math.max(0, width - visibleWidth(clipped)));
    };

    const lines: string[] = [
      muted("| ") + headerCell(pad("CWD", cwdWidth)) + muted(" | ") + headerCell(pad("ROUTE", routeWidth)) + muted(" |"),
      muted("| ") + muted(`${"-".repeat(cwdWidth)}`) + muted(" | ") + muted(`${"-".repeat(routeWidth)}`) + muted(" |"),
    ];
    for (const peer of group.peers) {
      lines.push(
        muted("| ") + cell(pad(peer.cwd, cwdWidth)) + muted(" | ") +
        cell(pad(routeCellText(peer.routeID), routeWidth)) + muted(" |"),
      );
    }
    return lines;
  }
}
