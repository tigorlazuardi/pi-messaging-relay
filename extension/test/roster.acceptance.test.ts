import assert from "node:assert/strict";
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import test from "node:test";

import { FakePiHost } from "./fake-pi-host.ts";

const TEST_TIMEOUT_MS = 15_000;

type Output = { iterator: AsyncIterator<string>; lines: string[] };
type ToolPage = {
  content: Array<{ type: string; text: string }>;
  details: { peers: Array<{ address: string }>; next_cursor?: string };
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

function page(result: unknown): ToolPage {
  const typed = result as ToolPage;
  assert.equal(typed.content.length, 1);
  assert.equal(typed.content[0].type, "text");
  assert.equal(typed.content[0].text, JSON.stringify(typed.details));
  return typed;
}

test("real extensions list live authenticated peers with strict address-only continuation", { timeout: 60_000, concurrency: false }, async () => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const root = await mkdtemp(join(tmpdir(), "pi-relay-roster-"));
  let child: ChildProcessWithoutNullStreams | undefined;
  let lines: ReturnType<typeof createInterface> | undefined;
  let primaryError: unknown;
  const oldURL = process.env.PI_MESSAGING_RELAY_URL;
  const oldState = process.env.PI_MESSAGING_RELAY_STATE_DIR;
  const originalError = console.error;
  const extensionLogs: string[] = [];
  const hosts: FakePiHost[] = [];

  try {
    await chmod(root, 0o700);
    const binary = join(root, "relay-server");
    const state = join(root, "server-state");
    const extensionState = join(root, "extension-state");
    const codeFile = join(root, "pairing-code");
    execFileSync("go", ["build", "-o", binary, "./cmd/pi-messaging-relay-server"], {
      cwd: repositoryRoot,
      stdio: "pipe",
    });
    child = spawn(binary, [
      "--listen", "127.0.0.1:0",
      "--state-dir", state,
      "--pairing-code-file", codeFile,
    ], { cwd: repositoryRoot, stdio: ["ignore", "pipe", "pipe"] });
    const stderr: Buffer[] = [];
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
    const output: Output = { iterator: lines[Symbol.asyncIterator](), lines: [] };
    console.error = (...values: unknown[]) => extensionLogs.push(values.map(String).join(" "));
    const ready = await nextEvent(output, "server_ready");
    await nextEvent(output, "pairing_code_created");
    process.env.PI_MESSAGING_RELAY_URL = `http://${String(ready.address)}`;
    process.env.PI_MESSAGING_RELAY_STATE_DIR = extensionState;
    const pairingCode = (await readFile(codeFile, "utf8")).trim();
    const relayExtension = (await import(`../index.ts?roster=${Date.now()}`)).default;
    const addresses: string[] = [];

    for (const cwd of ["/srv/delta", "/srv/alpha", "/srv/charlie", "/srv/bravo"]) {
      const host = new FakePiHost();
      host.cwd = cwd;
      relayExtension(host.api as never);
      hosts.push(host);
      await host.emit("session_start");
      if (hosts.length === 1) {
        await host.executeCommand("relay-pair", pairingCode);
        await nextEvent(output, "pair_accepted");
      }
      const accepted = await nextEvent(output, "auth_accepted");
      addresses.push(String(accepted.address));
    }

    for (let index = 0; index < hosts.length; index += 1) {
      const result = page(await hosts[index].executeTool("list_peers", {}));
      const expected = addresses.filter((_address, candidate) => candidate !== index).sort();
      assert.deepEqual(result.details, { peers: expected.map((address) => ({ address })) });
      assert.equal(/idle|busy|connection_name|client_id|client_public_key/.test(result.content[0].text), false);
      const settled = await nextEvent(output, "operation_settled", (event) => event.type === "list");
      assert.equal(settled.result, "settled");
      assert.equal(settled.count, expected.length);
      assert.equal("cursor" in settled || "peers" in settled || "address" in settled, false);
    }

    const first = page(await hosts[0].executeTool("list_peers", {})).details;
    await nextEvent(output, "operation_settled", (event) => event.type === "list");
    assert.equal(first.peers.length, 3);
    const cursor = `cur_${Buffer.from(first.peers[0].address, "utf8").toString("base64url")}`;
    const continuation = page(await hosts[0].executeTool("list_peers", { cursor })).details;
    await nextEvent(output, "operation_settled", (event) => event.type === "list");
    assert.deepEqual(continuation.peers, first.peers.slice(1));
    assert.ok(continuation.peers.every((peer) => peer.address > first.peers[0].address));

    const removedAddress = addresses[3];
    await hosts[3].emit("session_shutdown");
    await nextEvent(output, "session_disconnected", (event) => event.address === removedAddress);
    const afterDisconnect = page(await hosts[0].executeTool("list_peers", {})).details;
    await nextEvent(output, "operation_settled", (event) => event.type === "list");
    assert.equal(afterDisconnect.peers.some((peer) => peer.address === removedAddress), false);
    assert.deepEqual(
      afterDisconnect.peers.map((peer) => peer.address),
      addresses.slice(1, 3).sort(),
    );

    assert.equal(hosts.some((host) => host.sendMessageAttempts.length > 0), false);
    assert.equal(hosts.some((host) => host.sendUserMessageAttempts.length > 0), false);
    assert.equal(stderr.length, 0);
  } catch (error: unknown) {
    primaryError = error;
    throw error;
  } finally {
    let cleanupError: unknown;
    for (const host of hosts) {
      try {
        await host.emit("session_shutdown");
      } catch (error: unknown) {
        cleanupError ??= error;
      }
    }
    console.error = originalError;
    if (oldURL === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = oldURL;
    if (oldState === undefined) delete process.env.PI_MESSAGING_RELAY_STATE_DIR;
    else process.env.PI_MESSAGING_RELAY_STATE_DIR = oldState;
    if (child) {
      try {
        await stop(child);
      } catch (error: unknown) {
        cleanupError ??= error;
      }
    }
    try {
      lines?.close();
    } catch (error: unknown) {
      cleanupError ??= error;
    }
    try {
      await rm(root, { recursive: true, force: true });
    } catch (error: unknown) {
      cleanupError ??= error;
    }
    if (primaryError === undefined && cleanupError !== undefined) throw cleanupError;
  }
});
