import assert from "node:assert/strict";
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import test from "node:test";

import WebSocket from "ws";

import { FakePiHost } from "./fake-pi-host.ts";

const TEST_TIMEOUT_MS = 15_000;
const UUID_V7_SOURCE = "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const UUID_V7 = new RegExp(`^${UUID_V7_SOURCE}$`);

type Output = { iterator: AsyncIterator<string>; lines: string[] };
type ToolResult = {
  content: Array<{ type: string; text: string }>;
  details: { message_id: string; status: string; reason?: string };
};
type Injection = { from: string; messageID: string; re?: string; body: string };
type ACKFrame = {
  request_id: string;
  payload: { delivery_id: string; message_id: string };
};
type SendCallback = (error?: Error) => void;
type SendMethod = (data: unknown, optionsOrCallback?: unknown, callback?: SendCallback) => void;

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
  const deadline = Date.now() + TEST_TIMEOUT_MS;
  let timer: NodeJS.Timeout | undefined;

  await new Promise<void>((resolve, reject) => {
    const settle = (error?: Error) => {
      if (timer) clearTimeout(timer);
      timer = undefined;
      if (error) reject(error);
      else resolve();
    };
    const check = () => {
      timer = undefined;
      if (host.sendUserMessageAttempts.length >= count) {
        settle();
      } else if (Date.now() >= deadline) {
        settle(new Error("timed out recipient sendUserMessage attempt"));
      } else {
        timer = setTimeout(check, Math.min(1, deadline - Date.now()));
      }
    };
    check();
  });
}

function parseInjection(value: unknown): Injection {
  assert.equal(typeof value, "string");
  const separator = value.indexOf("\n");
  assert.notEqual(separator, -1);
  const header = value.slice(0, separator);
  const match = new RegExp(
    `^\\[pi-messaging-relay\\] message from (".*") \\(id=(${UUID_V7_SOURCE})(?:, re=(${UUID_V7_SOURCE}))?\\):$`,
  ).exec(header);
  assert.ok(match, `invalid relay provenance header: ${header}`);
  const from: unknown = JSON.parse(match[1]);
  assert.equal(typeof from, "string");
  return {
    from,
    messageID: match[2],
    ...(match[3] === undefined ? {} : { re: match[3] }),
    body: value.slice(separator + 1),
  };
}

function installReceivedACKGate(): {
  blockNext(): { frame: Promise<ACKFrame>; release(): void };
  restore(): void;
} {
  const prototype = WebSocket.prototype as unknown as { send: SendMethod };
  const originalSend = prototype.send;
  let armed: {
    resolve(frame: ACKFrame): void;
    releaseWrite?: () => void;
    released: boolean;
  } | undefined;

  prototype.send = function gatedSend(
    this: WebSocket,
    data: unknown,
    optionsOrCallback?: unknown,
    callback?: SendCallback,
  ): void {
    const current = armed;
    if (current && typeof data === "string") {
      let frame: Record<string, unknown> | undefined;
      try {
        frame = JSON.parse(data) as Record<string, unknown>;
      } catch {
        frame = undefined;
      }
      if (frame?.type === "received") {
        const args = [data, optionsOrCallback, callback];
        current.releaseWrite = () => Reflect.apply(originalSend, this, args);
        current.resolve(frame as unknown as ACKFrame);
        return;
      }
    }
    Reflect.apply(originalSend, this, [data, optionsOrCallback, callback]);
  };

  return {
    blockNext() {
      if (armed && !armed.released) throw new Error("received ACK gate already armed");
      let resolveFrame!: (frame: ACKFrame) => void;
      const frame = new Promise<ACKFrame>((resolve) => {
        resolveFrame = resolve;
      });
      const state = { resolve: resolveFrame, released: false } as {
        resolve(frame: ACKFrame): void;
        releaseWrite?: () => void;
        released: boolean;
      };
      armed = state;
      return {
        frame,
        release() {
          if (!state.releaseWrite) throw new Error("received ACK gate released before interception");
          if (state.released) return;
          state.released = true;
          if (armed === state) armed = undefined;
          state.releaseWrite();
        },
      };
    },
    restore() {
      if (armed?.releaseWrite && !armed.released) {
        armed.released = true;
        armed.releaseWrite();
      }
      armed = undefined;
      prototype.send = originalSend;
    },
  };
}

test("reply uses captured provenance in a second ordinary agent_send with independent received settlement", { timeout: 60_000, concurrency: false }, async () => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const root = await mkdtemp(join(tmpdir(), "pi-relay-reply-"));
  let child: ChildProcessWithoutNullStreams | undefined;
  let lines: ReturnType<typeof createInterface> | undefined;
  let ackGate: ReturnType<typeof installReceivedACKGate> | undefined;
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
      timeout: 30_000,
      killSignal: "SIGKILL",
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
    const relayExtension = (await import(`../index.ts?reply=${Date.now()}`)).default;

    const sender = new FakePiHost();
    sender.cwd = "/srv/reply-origin";
    relayExtension(sender.api as never);
    hosts.push(sender);
    await sender.emit("session_start");
    await sender.executeCommand("relay-pair", pairingCode);
    await nextEvent(output, "pair_accepted");
    const senderAuth = await nextEvent(output, "auth_accepted");

    const recipient = new FakePiHost();
    recipient.cwd = "/srv/reply-recipient";
    recipient.setIdle(false);
    relayExtension(recipient.api as never);
    hosts.push(recipient);
    await recipient.emit("session_start");
    const recipientAuth = await nextEvent(output, "auth_accepted");
    const recipientAddress = String(recipientAuth.address);

    ackGate = installReceivedACKGate();
    const originalBody = "original-message-body-must-remain-private\nwith exact spacing  ";
    const originalACKGate = ackGate.blockNext();
    let originalState = "pending";
    const originalResultPromise = sender.executeTool("agent_send", {
      to: recipientAddress,
      body: originalBody,
    }) as Promise<ToolResult>;
    void originalResultPromise.then(
      () => { originalState = "received"; },
      () => { originalState = "rejected"; },
    );

    await waitForAttempt(recipient, 1);
    assert.deepEqual(recipient.sendUserMessageAttempts[0]?.slice(1), [{ deliverAs: "followUp" }]);
    const originalInjection = parseInjection(recipient.sendUserMessageAttempts[0]?.[0]);
    assert.equal(originalInjection.from, senderAuth.address);
    assert.equal(originalInjection.re, undefined);
    assert.equal(originalInjection.body, originalBody);
    const originalACK = await within(originalACKGate.frame, "capturing original received ACK");
    assert.equal(originalState, "pending", "original send settled before its ACK was released");
    assert.match(originalACK.request_id, UUID_V7);
    assert.match(originalACK.payload.delivery_id, UUID_V7);
    assert.equal(originalACK.payload.message_id, originalInjection.messageID);

    originalACKGate.release();
    const originalResult = await within(originalResultPromise, "original sender received result");
    assert.deepEqual(originalResult.details, {
      message_id: originalInjection.messageID,
      status: "received",
    });
    assert.equal(originalResult.content[0]?.text, JSON.stringify(originalResult.details));
    const originalSettlement = await nextEvent(output, "send_settled", (event) =>
      event.message_id === originalInjection.messageID);

    sender.setIdle(true);
    const replyBody = {
      "2": "two",
      "10": "ten",
      answer: "reply-message-body-must-remain-private",
      nested: { z: false, a: [null, 1] },
    };
    const canonicalReplyBody =
      '{"10":"ten","2":"two","answer":"reply-message-body-must-remain-private","nested":{"a":[null,1],"z":false}}';
    const replyACKGate = ackGate.blockNext();
    let replyState = "pending";
    const replyResultPromise = recipient.executeTool("agent_send", {
      to: originalInjection.from,
      body: replyBody,
      re: originalInjection.messageID,
    }) as Promise<ToolResult>;
    void replyResultPromise.then(
      () => { replyState = "received"; },
      () => { replyState = "rejected"; },
    );

    await waitForAttempt(sender, 1);
    assert.deepEqual(sender.sendUserMessageAttempts[0]?.slice(1), []);
    const replyInjection = parseInjection(sender.sendUserMessageAttempts[0]?.[0]);
    assert.equal(replyInjection.from, recipientAddress);
    assert.equal(replyInjection.re, originalInjection.messageID);
    assert.equal(replyInjection.body, canonicalReplyBody);
    assert.match(replyInjection.messageID, UUID_V7);
    assert.notEqual(replyInjection.messageID, originalInjection.messageID);
    const replyACK = await within(replyACKGate.frame, "capturing reply received ACK");
    assert.equal(replyState, "pending", "reply send settled before its own ACK was released");
    assert.equal(originalState, "received", "reply ACK changed original settlement");
    assert.match(replyACK.request_id, UUID_V7);
    assert.match(replyACK.payload.delivery_id, UUID_V7);
    assert.equal(replyACK.payload.message_id, replyInjection.messageID);
    assert.notEqual(replyACK.payload.delivery_id, originalACK.payload.delivery_id);

    replyACKGate.release();
    const replyResult = await within(replyResultPromise, "reply sender received result");
    assert.deepEqual(replyResult.details, {
      message_id: replyInjection.messageID,
      status: "received",
    });
    assert.equal(replyResult.content[0]?.text, JSON.stringify(replyResult.details));
    const replySettlement = await nextEvent(output, "send_settled", (event) =>
      event.message_id === replyInjection.messageID);

    for (const [settlement, expected] of [
      [originalSettlement, {
        messageID: originalInjection.messageID,
        deliveryID: originalACK.payload.delivery_id,
        sender: String(senderAuth.address),
        recipient: recipientAddress,
      }],
      [replySettlement, {
        messageID: replyInjection.messageID,
        deliveryID: replyACK.payload.delivery_id,
        sender: recipientAddress,
        recipient: String(senderAuth.address),
      }],
    ] as const) {
      assert.match(String(settlement.request_id), UUID_V7);
      assert.equal(settlement.message_id, expected.messageID);
      assert.equal(settlement.delivery_id, expected.deliveryID);
      assert.equal(settlement.sender_route, expected.sender);
      assert.equal(settlement.recipient_route, expected.recipient);
      assert.equal(settlement.status, "received");
      assert.equal(settlement.result, "settled");
      assert.equal(settlement.reason, "received");
      assert.equal(settlement.code, "received");
      assert.equal(typeof settlement.latency_ms, "number");
      assert.equal(settlement.body, "<redacted>");
    }
    assert.equal(new Set([
      String(originalSettlement.request_id),
      String(replySettlement.request_id),
    ]).size, 2);
    assert.equal(new Set([originalInjection.messageID, replyInjection.messageID]).size, 2);
    assert.equal(new Set([originalACK.payload.delivery_id, replyACK.payload.delivery_id]).size, 2);
    assert.equal(new Set([
      String(originalSettlement.request_id),
      String(replySettlement.request_id),
      originalACK.request_id,
      replyACK.request_id,
    ]).size, 4);
    assert.equal(
      output.lines.filter((line) => JSON.parse(line).event === "send_settled").length,
      2,
    );

    assert.deepEqual(sender.sendMessageAttempts, []);
    assert.deepEqual(recipient.sendMessageAttempts, []);
    assert.equal(JSON.stringify(sender.sendUserMessageAttempts).includes("steer"), false);
    assert.equal(JSON.stringify(recipient.sendUserMessageAttempts).includes("steer"), false);
    for (const privateValue of [
      originalBody,
      canonicalReplyBody,
      "original-message-body-must-remain-private",
      "reply-message-body-must-remain-private",
      "[pi-messaging-relay] message from",
    ]) {
      assert.equal(extensionLogs.some((line) => line.includes(privateValue)), false);
      assert.equal(output.lines.some((line) => line.includes(privateValue)), false);
    }
    assert.equal(stderr.length, 0);
  } catch (error: unknown) {
    primaryError = error;
    throw error;
  } finally {
    let cleanupError: unknown;
    ackGate?.restore();
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
