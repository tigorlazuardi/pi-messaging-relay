import assert from "node:assert/strict";
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import test from "node:test";

import { FakePiHost } from "./fake-pi-host.ts";
import {
  installIsolatedHome,
  SHARED_RELAY_SECRET,
  writeClientConfig,
  writeServerSecretFile,
} from "./secret-relay.ts";

const TEST_TIMEOUT_MS = 15_000;

type Output = { iterator: AsyncIterator<string>; lines: string[] };

type ToolPage = {
  content: Array<{ type: string; text: string }>;
  details: {
    peers: Array<{ address: string; annotations?: Record<string, string> }>;
    next_cursor?: string;
  };
};

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
  if (child.exitCode !== null && child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  child.kill("SIGTERM");
  try {
    await within(exited, "stopping relay");
  } catch {
    child.kill("SIGKILL");
    await within(exited, "killing relay");
  }
}

function page(result: unknown): ToolPage {
  const typed = result as ToolPage;
  assert.equal(typed.content.length, 1);
  assert.equal(typed.content[0].type, "text");
  assert.equal(typed.content[0].text, JSON.stringify(typed.details));
  return typed;
}

/** Polls the roster until the predicate holds for the single listed peer. */
async function waitForPeer(
  host: FakePiHost,
  matches: (peer: { address: string; annotations?: Record<string, string> }) => boolean,
): Promise<{ address: string; annotations?: Record<string, string> }> {
  const deadline = Date.now() + 8_000;
  let last: { address: string; annotations?: Record<string, string> } | undefined;
  while (Date.now() < deadline) {
    const result = page(await host.executeTool("relay_list_peers", {}));
    last = result.details.peers[0];
    if (last && matches(last)) return last;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`peer never matched: ${JSON.stringify(last)}`);
}

test("two sessions in one cwd are told apart by their published annotations", { timeout: 60_000, concurrency: false }, async () => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const root = await mkdtemp(join(tmpdir(), "pi-relay-annotations-"));
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
    const relayExtension = (await import(`../index.ts?annotations=${Date.now()}`)).default;

    // Two sessions in the same working directory.
    const first = new FakePiHost();
    first.cwd = "/srv/shared";
    first.sessionID = "session-first";
    relayExtension(first.api as never);
    hosts.push(first);
    await first.emit("session_start");
    await nextEvent(output, "auth_accepted");

    const second = new FakePiHost();
    second.cwd = "/srv/shared";
    second.sessionID = "session-second";
    relayExtension(second.api as never);
    hosts.push(second);
    await second.emit("session_start");
    await nextEvent(output, "auth_accepted");

    const peer = await waitForPeer(first, (candidate) => candidate.annotations?.session === "session-second");
    assert.match(peer.address, /^\/srv\/shared@/);
    assert.equal(peer.annotations?.state, "idle");
    assert.equal(peer.annotations?.session, "session-second");

    // The rendered tool output quotes annotation values as JSON strings.
    const rendered = page(await first.executeTool("relay_list_peers", {})).content[0].text;
    assert.match(rendered, /"session":"session-second"/);
    assert.match(rendered, /"state":"idle"/);

    // An update changes the roster output without changing the address.
    await second.emit("session_info_changed", { type: "session_info_changed", name: "reviewer-two" });
    const updated = await waitForPeer(first, (candidate) => candidate.annotations?.name === "reviewer-two");
    assert.equal(updated.address, peer.address, "an annotation update must not change the address");
    assert.equal(updated.annotations?.session, "session-second");

    // The filter matches annotation values, not only addresses.
    const filtered = page(await first.executeTool("relay_list_peers", { filter: "reviewer-two" })).details;
    assert.equal(filtered.peers.length, 1);
    assert.equal(filtered.peers[0].annotations?.name, "reviewer-two");
    const unfiltered = page(await first.executeTool("relay_list_peers", { filter: "session-second" })).details;
    assert.equal(unfiltered.peers.length, 1);

    // No annotation value reaches the extension or server logs.
    const allLogs = [...output.lines, ...extensionLogs].join("\n");
    assert.equal(allLogs.includes("reviewer-two"), false);
    assert.equal(allLogs.includes("session-second"), false);

    assert.equal(hosts.some((host) => host.sendMessageAttempts.length > 0), false);
    assert.equal(hosts.some((host) => host.sendUserMessageAttempts.length > 0), false);
    assert.equal(stderr.length, 0);
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
