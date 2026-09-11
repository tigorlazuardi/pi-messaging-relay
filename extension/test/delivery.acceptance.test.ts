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
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

type Output = { iterator: AsyncIterator<string>; lines: string[] };
type ToolResult = {
  content: Array<{ type: string; text: string }>;
  details: { message_id: string; status: string; reason?: string };
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

async function waitForAttempt(host: FakePiHost, count: number): Promise<void> {
  await within(new Promise<void>((resolve) => {
    const check = () => {
      if (host.sendUserMessageAttempts.length >= count) resolve();
      else setTimeout(check, 1);
    };
    check();
  }), "recipient sendUserMessage attempt");
}

test("agent_send crosses real relay and two real extensions before settling received", { timeout: 60_000, concurrency: false }, async () => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const root = await mkdtemp(join(tmpdir(), "pi-relay-delivery-"));
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
    const relayExtension = (await import(`../index.ts?delivery=${Date.now()}`)).default;

    const sender = new FakePiHost();
    sender.cwd = "/srv/sender";
    relayExtension(sender.api as never);
    hosts.push(sender);
    await sender.emit("session_start");
    await sender.executeCommand("relay-pair", pairingCode);
    await nextEvent(output, "pair_accepted");
    const senderAuth = await nextEvent(output, "auth_accepted");

    const recipient = new FakePiHost();
    recipient.cwd = "/srv/recipient";
    relayExtension(recipient.api as never);
    hosts.push(recipient);
    await recipient.emit("session_start");
    const recipientAuth = await nextEvent(output, "auth_accepted");
    const recipientAddress = String(recipientAuth.address);

    const objectMarker = "local-object-body-must-not-cross-wire";
    await assert.rejects(
      sender.executeTool("agent_send", { to: recipientAddress, body: { private: objectMarker } }),
      (error: unknown) => error !== null && typeof error === "object" &&
        "name" in error && error.name === "RosterRequestError" &&
        "reason" in error && error.reason === "object_body_unsupported" &&
        "message" in error && error.message === "Relay agent_send object bodies are not supported by this release.",
    );
    const rosterResult = await sender.executeTool("list_peers", {}) as {
      details: { peers: Array<{ address: string }> };
    };
    assert.equal(rosterResult.details.peers.some((peer) => peer.address === recipientAddress), true);
    assert.equal(recipient.sendUserMessageAttempts.length, 0);

    const messageIDs: string[] = [];
    const deliveryIDs: string[] = [];
    for (const [index, body] of ["Review exact idle text", "Second unique message"].entries()) {
      const resultPromise = sender.executeTool("agent_send", { to: recipientAddress, body });
      await waitForAttempt(recipient, index + 1);
      assert.deepEqual(recipient.sendUserMessageAttempts[index], [body]);
      const result = await within(resultPromise, "sender received result") as ToolResult;
      assert.deepEqual(Object.keys(result.details).sort(), ["message_id", "status"]);
      assert.match(result.details.message_id, UUID_V7);
      assert.equal(result.details.status, "received");
      assert.equal(result.content[0].text, JSON.stringify(result.details));
      messageIDs.push(result.details.message_id);

      const settled = await nextEvent(output, "send_settled", (event) =>
        event.type === "send" && event.message_id === result.details.message_id);
      assert.equal(settled.delivery_id === undefined, false);
      assert.match(String(settled.delivery_id), UUID_V7);
      assert.equal(settled.sender_route, senderAuth.address);
      assert.equal(settled.recipient_route, recipientAddress);
      assert.equal(settled.status, "received");
      assert.equal(settled.body, "<redacted>");
      assert.equal(settled.result, "settled");
      deliveryIDs.push(String(settled.delivery_id));
    }

    assert.equal(new Set(messageIDs).size, 2);
    assert.equal(new Set(deliveryIDs).size, 2);
    assert.deepEqual(recipient.sendMessageAttempts, []);
    assert.deepEqual(sender.sendMessageAttempts, []);
    assert.equal(recipient.sendUserMessageAttempts.every((attempt) => attempt.length === 1), true);
    assert.equal(extensionLogs.some((line) => line.includes("Review exact idle text")), false);
    assert.equal(extensionLogs.some((line) => line.includes(objectMarker)), false);
    assert.equal(extensionLogs.some((line) => {
      const event = JSON.parse(line) as Record<string, unknown>;
      return event.event === "relay_operation_failed" &&
        event.operation === "agent_send" && event.reason === "object_body_unsupported";
    }), true);
    assert.equal(output.lines.some((line) => line.includes("Review exact idle text")), false);
    assert.equal(output.lines.some((line) => line.includes(objectMarker)), false);
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
    lines?.close();
    try {
      await rm(root, { recursive: true, force: true });
    } catch (error: unknown) {
      cleanupError ??= error;
    }
    if (primaryError === undefined && cleanupError !== undefined) throw cleanupError;
  }
});
