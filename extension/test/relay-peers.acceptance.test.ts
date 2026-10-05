import assert from "node:assert/strict";
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { hostname as operatingSystemHostname, EOL } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import test from "node:test";

import { FakePiHost } from "./fake-pi-host.ts";
import { PEER_ROSTER_ENTRY_TYPE } from "../internal/peer-roster-view.ts";
import {
  installIsolatedHome,
  SHARED_RELAY_SECRET,
  writeClientConfig,
  writeServerSecretFile,
} from "./secret-relay.ts";

const TEST_TIMEOUT_MS = 15_000;

type Output = { iterator: AsyncIterator<string>; lines: string[] };

async function within<T>(promise: Promise<T>, action: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`timed out ${action}`)), TEST_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function nextEvent(
  output: Output,
  name: string,
  matches: (event: Record<string, unknown>) => boolean = () => true,
): Promise<Record<string, unknown>> {
  while (true) {
    const next = await within(output.iterator.next(), `waiting for ${name}`);
    if (next.done) throw new Error(`server output ended before ${name}`);
    output.lines.push(next.value);
    const event = JSON.parse(next.value) as Record<string, unknown>;
    if (event.event === name && matches(event)) return event;
  }
}

async function stop(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  child.kill("SIGTERM");
  try {
    await within(exited, "stopping relay");
  } catch {
    child.kill("SIGKILL");
    await within(exited, "killing relay");
  }
}

test("/relay-peers appends a display-only grouped roster and never touches the LLM", { timeout: 60_000, concurrency: false }, async () => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const root = await mkdtemp(join(tmpdir(), "pi-relay-peers-"));
  let child: ChildProcessWithoutNullStreams | undefined;
  let lines: ReturnType<typeof createInterface> | undefined;
  const originalError = console.error;
  const extensionLogs: string[] = [];
  const hosts: FakePiHost[] = [];
  let environment: { restore(): void } | undefined;

  try {
    await chmod(root, 0o700);
    const binary = join(root, "relay-server");
    const state = join(root, "server-state");
    const extensionHome = join(root, "extension-home");
    const secretFile = await writeServerSecretFile(state);
    execFileSync("go", ["build", "-o", binary, "./cmd/pi-messaging-relay-server"], {
      cwd: repositoryRoot,
      stdio: "pipe",
    });
    child = spawn(binary, [
      "--listen", "127.0.0.1:0",
      "--state-dir", state,
      "--secret-file", secretFile,
    ], { cwd: repositoryRoot, stdio: ["ignore", "pipe", "pipe"] });
    const stderr: Buffer[] = [];
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
    const output: Output = { iterator: lines[Symbol.asyncIterator](), lines: [] };
    console.error = (...values: unknown[]) => extensionLogs.push(values.map(String).join(" "));
    const ready = await nextEvent(output, "server_ready");
    environment = installIsolatedHome(extensionHome);
    await writeClientConfig(extensionHome, {
      url: `http://${String(ready.address)}`,
      secret: SHARED_RELAY_SECRET,
    });
    const relayExtension = (await import(`../index.ts?relay-peers=${Date.now()}`)).default;

    // Caller plus one visible peer on another cwd of the same host.
    const caller = new FakePiHost();
    caller.cwd = "/srv/caller";
    relayExtension(caller.api as never);
    hosts.push(caller);
    await caller.emit("session_start");
    await nextEvent(output, "auth_accepted");

    const peer = new FakePiHost();
    peer.cwd = "/srv/peer";
    relayExtension(peer.api as never);
    hosts.push(peer);
    await peer.emit("session_start");
    await nextEvent(output, "auth_accepted");

    // A host that never started a session has no connection: the command must
    // warn without appending any entry.
    const cold = new FakePiHost();
    cold.cwd = "/srv/cold";
    relayExtension(cold.api as never);
    hosts.push(cold);

    await caller.executeCommand("relay-peers");
    const rosterEntries = caller.appendEntryAttempts.filter((attempt) => attempt.customType === PEER_ROSTER_ENTRY_TYPE);
    assert.equal(rosterEntries.length, 1, "exactly one roster entry");
    const entry = rosterEntries[0];
    const snapshotData = entry.data as {
      groups: Array<{ hostname: string; peers: Array<{ cwd: string; hostname: string; routeID: string }> }>;
      totalCount: number;
      truncated: boolean;
    };
    assert.equal(snapshotData.totalCount, 1);
    assert.equal(snapshotData.truncated, false);
    assert.equal(snapshotData.groups.length, 1);
    assert.equal(snapshotData.groups[0].hostname, operatingSystemHostname());
    assert.equal(snapshotData.groups[0].peers.length, 1);
    assert.deepEqual(snapshotData.groups[0].peers[0], {
      cwd: "/srv/peer",
      hostname: operatingSystemHostname(),
      routeID: snapshotData.groups[0].peers[0].routeID,
    });
    assert.match(snapshotData.groups[0].peers[0].routeID, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.deepEqual(caller.notifications, []);
    assert.equal(caller.sendMessageAttempts.length, 0, "roster must not send custom messages");
    assert.equal(caller.sendUserMessageAttempts.length, 0, "roster must not trigger an LLM turn");

    // The registered entry renderer paints the grouped tables user-side.
    const renderer = caller.entryRenderers.get(PEER_ROSTER_ENTRY_TYPE);
    assert.equal(typeof renderer, "function");
    const component = (renderer as (entry: unknown, options: unknown, theme: unknown) => unknown)(
      { type: "custom", customType: PEER_ROSTER_ENTRY_TYPE, data: entry.data },
      { expanded: false },
      { fg: (_color: string, text: string) => text, bold: (text: string) => text },
    );
    const rendered = (component as { render(width: number): string[] }).render(80).join(EOL);
    assert.match(rendered, /relay peers — 1 online/);
    assert.match(rendered, new RegExp(`── ${operatingSystemHostname()} \\(1\\)`));
    assert.match(rendered, /\| CWD/);
    assert.match(rendered, /\/srv\/peer/);

    // The never-connected host warns without touching the session transcript.
    await cold.executeCommand("relay-peers");
    assert.equal(cold.appendEntryAttempts.filter((attempt) => attempt.customType === PEER_ROSTER_ENTRY_TYPE).length, 0);
    assert.equal(cold.notifications.length, 1);
    assert.match(cold.notifications[0].message, /disconnected/);
    assert.equal(cold.sendMessageAttempts.length, 0);
    assert.equal(cold.sendUserMessageAttempts.length, 0);

    // Peer leaves; the next snapshot is empty but still display-only.
    await peer.emit("session_shutdown");
    await nextEvent(output, "session_disconnected");
    await caller.executeCommand("relay-peers");
    assert.equal(caller.appendEntryAttempts.filter((attempt) => attempt.customType === PEER_ROSTER_ENTRY_TYPE).length, 2);
    assert.deepEqual(caller.appendEntryAttempts.filter((attempt) => attempt.customType === PEER_ROSTER_ENTRY_TYPE)[1].data, { groups: [], totalCount: 0, truncated: false });
    assert.equal(caller.sendMessageAttempts.length, 0);
    assert.equal(caller.sendUserMessageAttempts.length, 0);

    assert.equal(hosts.some((host) => host.sendMessageAttempts.length > 0), false);
    assert.equal(hosts.some((host) => host.sendUserMessageAttempts.length > 0), false);
    assert.equal(stderr.length, 0);
  } catch (error: unknown) {
    throw error;
  } finally {
    console.error = originalError;
    let cleanupError: unknown;
    for (const host of hosts) {
      try {
        await host.emit("session_shutdown");
      } catch (error: unknown) {
        cleanupError ??= error;
      }
    }
    try {
      await stop(child!);
    } catch (error: unknown) {
      cleanupError ??= error;
    }
    try {
      lines?.iterator.return?.(undefined);
    } catch {
      // Input stream already closed with the child process.
    }
    try {
      await rm(root, { recursive: true, force: true });
    } catch (error: unknown) {
      cleanupError ??= error;
    }
    environment?.restore();
    if (cleanupError) throw cleanupError;
  }
});
