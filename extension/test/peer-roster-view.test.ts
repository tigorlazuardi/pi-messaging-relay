import assert from "node:assert/strict";
import test from "node:test";

import {
  buildPeerRosterSnapshot,
  parsePeerAddress,
  PeerRosterCardComponent,
  PEER_ROSTER_ENTRY_TYPE,
  restorePeerRosterSnapshot,
  snapshotFromUnknown,
} from "../internal/peer-roster-view.ts";
import { visibleWidth } from "../internal/relay-box.ts";

const ROUTE_A = "01993c84-5d38-7d75-8bc1-f945bfa42cdf";
const ROUTE_B = "01993c84-5d38-7d75-8bc1-f945bfa42cfe";

test("parsePeerAddress splits on the last @ and # separators", () => {
  assert.deepEqual(
    parsePeerAddress(`/srv/data@backup@host-01#${ROUTE_A}`),
    { cwd: "/srv/data@backup", hostname: "host-01", routeID: ROUTE_A },
  );
});

test("parsePeerAddress falls back to one unparsed group for malformed addresses", () => {
  for (const malformed of ["", "no-separators", "/srv/x@host", `/srv/x@host#not-a-uuid`]) {
    const parsed = parsePeerAddress(malformed);
    assert.equal(parsed.hostname, "(unparsed)");
    assert.equal(parsed.cwd, malformed);
    assert.equal(parsed.routeID, "");
  }
});

test("buildPeerRosterSnapshot groups by hostname and sorts groups and peers", async () => {
  const snapshot = await buildPeerRosterSnapshot(async () => ({
    peers: [
      { address: `/srv/delta@zeta-host#${ROUTE_A}` },
      { address: `/srv/alpha@alpha-host#${ROUTE_B}` },
      { address: `/srv/alpha@alpha-host#${ROUTE_A}` },
    ],
  }));
  assert.equal(snapshot.totalCount, 3);
  assert.equal(snapshot.truncated, false);
  assert.deepEqual(snapshot.groups.map((group) => group.hostname), ["alpha-host", "zeta-host"]);
  const [alphaGroup] = snapshot.groups;
  assert.deepEqual(alphaGroup.peers.map((peer) => peer.cwd), ["/srv/alpha", "/srv/alpha"]);
  assert.deepEqual(alphaGroup.peers.map((peer) => peer.routeID), [ROUTE_A, ROUTE_B]);
  assert.deepEqual(alphaGroup.peers[0], { cwd: "/srv/alpha", hostname: "alpha-host", routeID: ROUTE_A });
});

test("buildPeerRosterSnapshot walks next_cursor pages until exhaustion or the 8-page budget", async () => {
  const seen: Array<string | undefined> = [];
  let page = 0;
  const snapshot = await buildPeerRosterSnapshot(async (cursor) => {
    seen.push(cursor);
    page += 1;
    if (page < 3) return { peers: [{ address: `/srv/x@h#${ROUTE_A}` }], next_cursor: `cur_${page}` };
    return { peers: [{ address: `/srv/y@h#${ROUTE_B}` }] };
  });
  assert.equal(snapshot.totalCount, 3);
  assert.equal(snapshot.truncated, false);
  assert.deepEqual(seen, [undefined, "cur_1", "cur_2"]);
  assert.deepEqual(snapshot.groups[0].peers.map((peer) => peer.cwd), ["/srv/x", "/srv/x", "/srv/y"]);

  let budgetPages = 0;
  const truncated = await buildPeerRosterSnapshot(async () => {
    budgetPages += 1;
    return { peers: [{ address: `/srv/x@h#${ROUTE_A}` }], next_cursor: `cur_${budgetPages}` };
  });
  assert.equal(budgetPages, 8);
  assert.equal(truncated.totalCount, 8);
  assert.equal(truncated.truncated, true);
});

test("buildPeerRosterSnapshot ignores malformed peer records", async () => {
  const snapshot = await buildPeerRosterSnapshot(async () => ({
    peers: [{ address: `/srv/x@h#${ROUTE_A}` }, { address: 42 }, "junk", {}, { other: true }],
  }));
  assert.equal(snapshot.totalCount, 1);
});

test("snapshotFromUnknown rejects foreign or malformed entry data", () => {
  const good: PeerRosterSnapshot = {
    groups: [{ hostname: "h", peers: [{ cwd: "/srv", hostname: "h", routeID: ROUTE_A }] }],
    totalCount: 1,
    truncated: false,
  };
  assert.deepEqual(snapshotFromUnknown(good), good);
  for (const bad of [
    undefined,
    null,
    42,
    "snapshot",
    [],
    {},
    { ...good, totalCount: "1" },
    { ...good, truncated: 1 },
    { ...good, groups: "nope" },
    { ...good, groups: [{ hostname: 5, peers: [] }] },
    { ...good, groups: [{ hostname: "h", peers: [{ cwd: "/srv" }] }] },
  ]) {
    assert.equal(snapshotFromUnknown(bad), undefined);
  }
});

test("restorePeerRosterSnapshot returns the newest relay roster entry", () => {
  const snapshot: PeerRosterSnapshot = { groups: [], totalCount: 0, truncated: false };
  const restored = restorePeerRosterSnapshot({
    sessionManager: {
      getEntries: () => [
        { type: "custom", customType: "other-extension", data: { junk: true } },
        { type: "custom", customType: PEER_ROSTER_ENTRY_TYPE, data: snapshot },
        { type: "message", role: "user" },
      ],
    },
  });
  assert.deepEqual(restored, snapshot);
  assert.equal(
    restorePeerRosterSnapshot({ sessionManager: { getEntries: () => [{ type: "custom", customType: PEER_ROSTER_ENTRY_TYPE, data: { broken: 1 } }] } }),
    undefined,
  );
  assert.equal(restorePeerRosterSnapshot({ sessionManager: { getEntries: () => [] } }), undefined);
});

function stripAnsi(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\u001B\[[0-9;]*m/g, "");
}

test("card renders one markdown table per hostname group inside the width budget", () => {
  const snapshot: PeerRosterSnapshot = {
    groups: [
      { hostname: "alpha-host", peers: [
        { cwd: "/srv/alpha", hostname: "alpha-host", routeID: ROUTE_A },
        { cwd: "/srv/bravo", hostname: "alpha-host", routeID: ROUTE_B },
      ] },
      { hostname: "zeta-host", peers: [{ cwd: "/srv/delta", hostname: "zeta-host", routeID: ROUTE_A }] },
    ],
    totalCount: 3,
    truncated: false,
  };
  for (const width of [40, 60, 80, 120]) {
    const lines = new PeerRosterCardComponent(snapshot, undefined).render(width);
    assert.ok(lines.length > 0);
    for (const line of lines) {
      assert.ok(visibleWidth(line) <= width, `line exceeded ${width}: ${JSON.stringify(line)}`);
    }
    const tables = lines.filter((line) => /^\u2502\| CWD/.test(stripAnsi(line)));
    assert.equal(tables.length, 2);
  }
  const rendered = new PeerRosterCardComponent(snapshot, undefined).render(80).map(stripAnsi).join("\n");
  assert.match(rendered, /relay peers — 3 online/);
  assert.match(rendered, /── alpha-host \(2\)/);
  assert.match(rendered, /\| CWD +\| ROUTE +\|/);
  assert.match(rendered, /01993c84-5d38-7d75-8bc1-f945bfa42cdf/);
});

test("card truncates oversized cwd rows and marks partial snapshots", () => {
  const snapshot: PeerRosterSnapshot = {
    groups: [{ hostname: "h".repeat(60), peers: [{ cwd: "/srv/" + "x".repeat(200), hostname: "h".repeat(60), routeID: ROUTE_A }] }],
    totalCount: 1,
    truncated: true,
  };
  const lines = new PeerRosterCardComponent(snapshot, undefined).render(50);
  for (const line of lines) assert.ok(visibleWidth(line) <= 50);
  const joined = lines.map(stripAnsi).join("\n");
  assert.match(joined, /partial/);
  assert.match(joined, /…/);
});

test("card renders an empty roster and a tiny-width fallback", () => {
  const empty = new PeerRosterCardComponent({ groups: [], totalCount: 0, truncated: false }, undefined).render(40);
  assert.match(empty.map(stripAnsi).join("\n"), /no peers online/);
  const narrow = new PeerRosterCardComponent({ groups: [], totalCount: 7, truncated: false }, undefined).render(30);
  assert.match(stripAnsi(narrow.join("\n")), /7 online/);
  const tiny = new PeerRosterCardComponent({ groups: [], totalCount: 7, truncated: false }, undefined).render(8);
  assert.ok(tiny.length === 1);
  assert.ok(visibleWidth(tiny[0]) <= 8, "tiny fallback must respect width");
});

test("card paints full-row background and survives a throwing theme", () => {
  const snapshot: PeerRosterSnapshot = {
    groups: [{ hostname: "h", peers: [{ cwd: "/srv", hostname: "h", routeID: ROUTE_A }] }],
    totalCount: 1,
    truncated: false,
  };
  const bgPainted: string[] = [];
  const painted = new PeerRosterCardComponent(snapshot, {
    fg: (color, text) => text,
    bold: (text) => text,
    bg: (color, text) => {
      bgPainted.push(color);
      return `[${color}]${text}[/]`;
    },
  }).render(60);
  assert.ok(bgPainted.length > 0);
  assert.ok(bgPainted.every((color) => color === "customMessageBg"));
  assert.match(stripAnsi(painted.join("\n")), /\[customMessageBg\]/);

  const hostile = new PeerRosterCardComponent(snapshot, {
    fg: () => {
      throw new Error("theme crash");
    },
    bold: (text) => text,
  });
  assert.doesNotThrow(() => hostile.render(60));
  assert.match(hostile.render(60).map(stripAnsi).join("\n"), /1 online/);
});
