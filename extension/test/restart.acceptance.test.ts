import assert from "node:assert/strict";
import { spawn, execFileSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import test from "node:test";

import WebSocket from "ws";

import {
  installReconnectDependenciesForTest,
  type ReconnectDeadline,
} from "../internal/reconnect.ts";
import { FakePiHost } from "./fake-pi-host.ts";

const TEST_TIMEOUT_MS = 15_000;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

type ProcessOutput = {
  iterator: AsyncIterator<string>;
  lines: string[];
};

type RelayProcess = {
  child: ChildProcessWithoutNullStreams;
  output: ProcessOutput;
  stderr: Buffer[];
  closeOutput(): void;
};

type RosterPage = { details: { peers: Array<{ address: string }> } };
type ToolResult = {
  details: {
    message_id: string;
    status: string;
    reason?: string;
  };
};
type RecipientFrame = {
  attempt: number;
  type: string;
  messageID?: string;
  deliveryID?: string;
  body?: unknown;
};
type RecipientAttempt = { socket: WebSocket };
type HeldACK = { messageID: string; deliveryID: string };

type DurableAllowlist = {
  version: number;
  clients: Array<{
    client_id: string;
    client_public_key: string;
    paired_at: string;
  }>;
};

class RestartClock {
  nowMS = 1_800_000_000_000;
  readonly scheduledDelays: number[] = [];
  private nextID = 0;
  private readonly tasks = new Map<number, { at: number; callback(): void }>();

  readonly dependencies = {
    now: () => this.nowMS,
    randomUnit: () => 0.5,
    schedule: (callback: () => void, delayMS: number): ReconnectDeadline => {
      this.scheduledDelays.push(delayMS);
      const id = this.nextID++;
      this.tasks.set(id, { at: this.nowMS + delayMS, callback });
      return { cancel: () => { this.tasks.delete(id); } };
    },
  };

  get pendingCount(): number {
    return this.tasks.size;
  }

  async advanceBy(durationMS: number): Promise<void> {
    const target = this.nowMS + durationMS;
    while (true) {
      const next = [...this.tasks.entries()]
        .filter(([, task]) => task.at <= target)
        .sort((left, right) => left[1].at - right[1].at || left[0] - right[0])[0];
      if (!next) break;
      const [id, task] = next;
      this.tasks.delete(id);
      this.nowMS = task.at;
      task.callback();
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    this.nowMS = target;
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}

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

async function waitUntil(predicate: () => boolean, action: string): Promise<void> {
  const started = Date.now();
  while (!predicate()) {
    if (Date.now() - started >= TEST_TIMEOUT_MS) throw new Error(`timed out ${action}`);
    await new Promise<void>((resolve) => setTimeout(resolve, 1));
  }
}

async function nextEvent(
  output: ProcessOutput,
  name: string,
  matches: (event: Record<string, unknown>) => boolean = () => true,
): Promise<Record<string, unknown>> {
  while (true) {
    const next = await within(output.iterator.next(), `waiting for ${name}`);
    if (next.done) throw new Error(`relay output ended before ${name}`);
    output.lines.push(next.value);
    const event = JSON.parse(next.value) as Record<string, unknown>;
    if (event.event === name && matches(event)) return event;
  }
}

async function startRelay(
  binary: string,
  repositoryRoot: string,
  stateDirectory: string,
  codeFile: string | undefined,
  listen: string,
): Promise<{ relay: RelayProcess; ready: Record<string, unknown> }> {
  const args = ["--listen", listen, "--state-dir", stateDirectory];
  if (codeFile !== undefined) args.push("--pairing-code-file", codeFile);
  const child = spawn(binary, args, { cwd: repositoryRoot, stdio: ["ignore", "pipe", "pipe"] });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const relay: RelayProcess = {
    child: child as ChildProcessWithoutNullStreams,
    output: { iterator: lines[Symbol.asyncIterator](), lines: [] },
    stderr,
    closeOutput: () => lines.close(),
  };
  const ready = await nextEvent(relay.output, "server_ready");
  await nextEvent(relay.output, "pairing_code_created");
  return { relay, ready };
}

async function stopRelay(relay: RelayProcess): Promise<void> {
  if (relay.child.exitCode !== null || relay.child.signalCode !== null) return;
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    relay.child.once("exit", (code, signal) => resolve({ code, signal }));
  });
  assert.equal(relay.child.kill("SIGTERM"), true);
  const stopped = await nextEvent(relay.output, "server_stopped");
  assert.equal(stopped.result, "graceful");
  const result = await within(exited, "waiting for graceful relay exit");
  assert.deepEqual(result, { code: 0, signal: null });
}

async function killRelay(relay: RelayProcess): Promise<void> {
  if (relay.child.exitCode !== null || relay.child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => relay.child.once("exit", () => resolve()));
  relay.child.kill("SIGKILL");
  await within(exited, "killing relay during cleanup");
}

async function reserveLoopbackAddress(): Promise<string> {
  const listener = createServer();
  await new Promise<void>((resolve, reject) => {
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", resolve);
  });
  const address = listener.address();
  assert.ok(address && typeof address === "object");
  await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
  return `127.0.0.1:${address.port}`;
}

async function writeInstallationKey(stateDirectory: string): Promise<string> {
  await mkdir(stateDirectory, { mode: 0o700 });
  await chmod(stateDirectory, 0o700);
  const privateKey = generateKeyPairSync("ed25519").privateKey;
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  await writeFile(join(stateDirectory, "installation-ed25519.pem"), pem, { mode: 0o600 });
  return pem;
}

function assertClosedAllowlist(text: string, forbiddenValues: string[]): DurableAllowlist {
  const parsed = JSON.parse(text) as DurableAllowlist;
  assert.deepEqual(Object.keys(parsed).sort(), ["clients", "version"]);
  assert.equal(parsed.version, 1);
  assert.equal(parsed.clients.length, 1);
  assert.deepEqual(Object.keys(parsed.clients[0]).sort(), [
    "client_id",
    "client_public_key",
    "paired_at",
  ]);
  assert.match(parsed.clients[0].client_id, /^cli_[A-Za-z0-9_-]{16}$/);
  assert.match(parsed.clients[0].client_public_key, /^ed25519:[A-Za-z0-9+/]{43}=$/);
  assert.match(parsed.clients[0].paired_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/);

  const forbiddenKeys = new Set([
    "body",
    "pending",
    "pending_sends",
    "dedupe",
    "offline_inbox",
    "inbox",
    "request_id",
    "message_id",
    "delivery_id",
    "route_id",
  ]);
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (value === null || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      assert.equal(forbiddenKeys.has(key), false, `durable allowlist contains forbidden key ${key}`);
      visit(child);
    }
  };
  visit(parsed);
  for (const value of forbiddenValues) assert.equal(text.includes(value), false);
  return parsed;
}

async function listedAddresses(host: FakePiHost): Promise<string[]> {
  const result = await host.executeTool("list_peers", {}) as RosterPage;
  return result.details.peers.map((peer) => peer.address);
}

function installRecipientSocketControl(recipientCWD: string): {
  attempts: RecipientAttempt[];
  frames: RecipientFrame[];
  heldACKs: HeldACK[];
  holdNextACK(): void;
  restore(): void;
} {
  type SendCallback = (error?: Error) => void;
  type SendMethod = (data: unknown, ...rest: unknown[]) => unknown;
  const prototype = WebSocket.prototype as unknown as { send: SendMethod };
  const originalSend = prototype.send;
  const attempts: RecipientAttempt[] = [];
  const frames: RecipientFrame[] = [];
  const heldACKs: HeldACK[] = [];
  let holdNextACK = false;

  prototype.send = function controlledSend(this: WebSocket, data: unknown, ...rest: unknown[]): unknown {
    if (typeof data === "string") {
      try {
        const frame = JSON.parse(data) as Record<string, unknown>;
        const payload = frame.payload as Record<string, unknown> | undefined;
        if (frame.type === "hello" && payload?.cwd === recipientCWD) {
          const attempt = attempts.length + 1;
          attempts.push({ socket: this });
          this.on("message", (incoming: WebSocket.RawData, isBinary: boolean) => {
            if (isBinary) return;
            const decoded = JSON.parse(incoming.toString()) as Record<string, unknown>;
            const incomingPayload = decoded.payload as Record<string, unknown> | undefined;
            frames.push({
              attempt,
              type: String(decoded.type),
              ...(typeof incomingPayload?.message_id === "string"
                ? { messageID: incomingPayload.message_id }
                : {}),
              ...(typeof incomingPayload?.delivery_id === "string"
                ? { deliveryID: incomingPayload.delivery_id }
                : {}),
              ...(incomingPayload && Object.hasOwn(incomingPayload, "body")
                ? { body: incomingPayload.body }
                : {}),
            });
          });
        }
        if (holdNextACK && frame.type === "received" && payload) {
          holdNextACK = false;
          heldACKs.push({
            messageID: String(payload.message_id),
            deliveryID: String(payload.delivery_id),
          });
          const callback = rest.find((value) => typeof value === "function") as SendCallback | undefined;
          if (callback) setImmediate(() => callback());
          return undefined;
        }
      } catch {
        // Non-JSON writes remain owned by the real WebSocket implementation.
      }
    }
    return Reflect.apply(originalSend, this, [data, ...rest]);
  };

  return {
    attempts,
    frames,
    heldACKs,
    holdNextACK: () => { holdNextACK = true; },
    restore: () => { prototype.send = originalSend; },
  };
}

async function boundedQuietCheckpoint(
  sender: FakePiHost,
  recipientAddress: string,
  recipient: FakePiHost,
  expectedInjectionCount: number,
  action: string,
): Promise<void> {
  const started = Date.now();
  while (true) {
    try {
      assert.deepEqual(await listedAddresses(sender), [recipientAddress]);
      break;
    } catch (error) {
      if (Date.now() - started >= TEST_TIMEOUT_MS) throw error;
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
  }
  for (let turn = 0; turn < 3; turn += 1) {
    await within(new Promise<void>((resolve) => setImmediate(resolve)), `${action} quiet turn ${turn + 1}`);
  }
  assert.equal(recipient.sendUserMessageAttempts.length, expectedInjectionCount, action);
}

function recipientMessages(frames: RecipientFrame[]): RecipientFrame[] {
  return frames.filter((frame) => frame.type === "message");
}

function injectedText(host: FakePiHost): string[] {
  return host.sendUserMessageAttempts.map((attempt) => String((attempt as unknown[])[0]));
}

test("recipient delivery stream never replays across reconnect and child-process restart", {
  timeout: 60_000,
  concurrency: false,
}, async (context) => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const root = await mkdtemp(join(tmpdir(), "pi-relay-restart-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const binary = join(root, "relay-server");
  const serverState = join(root, "server-state");
  const pairedExtensionState = join(root, "paired-extension-state");
  const unknownExtensionState = join(root, "unknown-extension-state");
  const codeFile = join(serverState, "pairing-code");
  execFileSync("go", ["build", "-o", binary, "./cmd/pi-messaging-relay-server"], {
    cwd: repositoryRoot,
    stdio: "pipe",
  });

  const listen = await reserveLoopbackAddress();
  const clock = new RestartClock();
  const restoreReconnect = installReconnectDependenciesForTest(clock.dependencies);
  const recipientCWD = "/srv/lifecycle-recipient";
  const socketControl = installRecipientSocketControl(recipientCWD);
  const previousURL = process.env.PI_MESSAGING_RELAY_URL;
  const previousState = process.env.PI_MESSAGING_RELAY_STATE_DIR;
  const originalError = console.error;
  const extensionLogs: string[] = [];
  const hosts: FakePiHost[] = [];
  const relays: RelayProcess[] = [];
  const bodies = {
    settledBeforeLoss: "settled-before-lifecycle-loss-private-body",
    interruptedByDisconnect: "disconnect-pending-private-body",
    freshAfterReconnect: "fresh-after-reconnect-private-body",
    interruptedByRestart: "restart-pending-private-body",
    freshAfterRestart: "fresh-after-restart-private-body",
  };
  const allBodies = Object.values(bodies);
  const messageIDs: string[] = [];
  let primaryError: unknown;

  try {
    console.error = (...values: unknown[]) => extensionLogs.push(values.map(String).join(" "));
    const first = await startRelay(binary, repositoryRoot, serverState, codeFile, listen);
    relays.push(first.relay);
    assert.equal(first.ready.address, listen);
    assert.equal(first.ready.state_dir, serverState);
    process.env.PI_MESSAGING_RELAY_URL = `http://${listen}`;
    process.env.PI_MESSAGING_RELAY_STATE_DIR = pairedExtensionState;

    const relayExtension = (await import(`../index.ts?lifecycle-delivery=${Date.now()}`)).default;
    const sender = new FakePiHost();
    sender.cwd = "/srv/lifecycle-sender";
    relayExtension(sender.api as never);
    hosts.push(sender);
    await sender.emit("session_start", { type: "session_start", reason: "startup" });
    const pairingCode = (await readFile(codeFile, "utf8")).trim();
    await sender.executeCommand("relay-pair", pairingCode);
    const acceptedPair = await nextEvent(first.relay.output, "pair_accepted");
    const senderAuth = await nextEvent(
      first.relay.output,
      "auth_accepted",
      (event) => event.cwd === sender.cwd,
    );
    assert.equal(acceptedPair.client_public_key, senderAuth.client_public_key);
    const senderAddress = String(senderAuth.address);

    const recipient = new FakePiHost();
    recipient.cwd = recipientCWD;
    relayExtension(recipient.api as never);
    hosts.push(recipient);
    await recipient.emit("session_start", { type: "session_start", reason: "startup" });
    const recipientAuth = await nextEvent(
      first.relay.output,
      "auth_accepted",
      (event) => event.cwd === recipient.cwd,
    );
    const recipientAddress = String(recipientAuth.address);
    const recipientRouteID = String(recipientAuth.route_id);
    assert.deepEqual(await listedAddresses(sender), [recipientAddress]);
    assert.deepEqual(await listedAddresses(recipient), [senderAddress]);
    assert.equal(socketControl.attempts.length, 1);

    const settledBeforeLoss = await within(sender.executeTool("agent_send", {
      to: recipientAddress,
      body: bodies.settledBeforeLoss,
    }), "settling message before lifecycle loss") as ToolResult;
    assert.deepEqual(settledBeforeLoss.details, {
      message_id: settledBeforeLoss.details.message_id,
      status: "received",
    });
    assert.match(settledBeforeLoss.details.message_id, UUID_V7);
    messageIDs.push(settledBeforeLoss.details.message_id);
    await nextEvent(first.relay.output, "send_settled", (event) =>
      event.message_id === settledBeforeLoss.details.message_id);

    socketControl.holdNextACK();
    const interruptedByDisconnectPromise = sender.executeTool("agent_send", {
      to: recipientAddress,
      body: bodies.interruptedByDisconnect,
    }) as Promise<ToolResult>;
    await waitUntil(() => socketControl.heldACKs.length === 1, "holding recipient ACK before disconnect");
    const disconnectACK = socketControl.heldACKs[0];
    assert.match(disconnectACK.messageID, UUID_V7);
    assert.match(disconnectACK.deliveryID, UUID_V7);
    messageIDs.push(disconnectACK.messageID);
    const disconnectedSocket = socketControl.attempts.at(-1)?.socket;
    assert.ok(disconnectedSocket);
    disconnectedSocket.terminate();
    const interruptedByDisconnect = await within(
      interruptedByDisconnectPromise,
      "settling recipient disconnect",
    );
    assert.deepEqual(interruptedByDisconnect.details, {
      message_id: disconnectACK.messageID,
      status: "timeout",
      reason: "recipient_disconnected",
    });
    await nextEvent(first.relay.output, "send_settled", (event) =>
      event.message_id === disconnectACK.messageID && event.reason === "recipient_disconnected");
    await waitUntil(() => clock.pendingCount === 1, "recipient reconnect deadline");
    await clock.advanceBy(500);
    const reconnectedRecipient = await nextEvent(
      first.relay.output,
      "auth_accepted",
      (event) => event.cwd === recipient.cwd,
    );
    assert.equal(reconnectedRecipient.address, recipientAddress);
    assert.equal(reconnectedRecipient.route_id, recipientRouteID);
    assert.equal(socketControl.attempts.length, 2);
    await boundedQuietCheckpoint(
      sender,
      recipientAddress,
      recipient,
      2,
      "reconnect emitted no startup or historical delivery",
    );

    const freshAfterReconnect = await within(sender.executeTool("agent_send", {
      to: recipientAddress,
      body: bodies.freshAfterReconnect,
    }), "settling fresh post-reconnect send") as ToolResult;
    assert.deepEqual(freshAfterReconnect.details, {
      message_id: freshAfterReconnect.details.message_id,
      status: "received",
    });
    assert.match(freshAfterReconnect.details.message_id, UUID_V7);
    messageIDs.push(freshAfterReconnect.details.message_id);
    await nextEvent(first.relay.output, "send_settled", (event) =>
      event.message_id === freshAfterReconnect.details.message_id);

    socketControl.holdNextACK();
    const interruptedByRestartPromise = sender.executeTool("agent_send", {
      to: recipientAddress,
      body: bodies.interruptedByRestart,
    });
    const restartRejection = assert.rejects(
      within(interruptedByRestartPromise, "abandoning send on graceful relay shutdown"),
      (error: unknown) => error instanceof Error &&
        error.name === "RosterRequestError" &&
        (error as Error & { reason?: string }).reason === "disconnected",
    );
    await waitUntil(() => socketControl.heldACKs.length === 2, "holding recipient ACK before restart");
    const restartACK = socketControl.heldACKs[1];
    assert.match(restartACK.messageID, UUID_V7);
    assert.match(restartACK.deliveryID, UUID_V7);
    messageIDs.push(restartACK.messageID);

    assert.deepEqual(await readdir(serverState), ["allowlist.json"]);
    const allowlistPath = join(serverState, "allowlist.json");
    assert.equal((await stat(serverState)).mode & 0o777, 0o700);
    assert.equal((await stat(allowlistPath)).mode & 0o777, 0o600);
    const privatePEM = await readFile(join(pairedExtensionState, "installation-ed25519.pem"), "utf8");
    const beforeStop = await readFile(allowlistPath, "utf8");
    const storedBeforeStop = assertClosedAllowlist(beforeStop, [...allBodies, ...messageIDs, privatePEM.trim(), pairingCode]);
    assert.equal(storedBeforeStop.clients[0].client_id, acceptedPair.client_id);
    assert.equal(storedBeforeStop.clients[0].client_public_key, acceptedPair.client_public_key);

    await stopRelay(first.relay);
    await restartRejection;
    await waitUntil(() => clock.pendingCount === 2, "sender and recipient restart reconnect deadlines");
    const afterStop = await readFile(allowlistPath, "utf8");
    assert.equal(afterStop, beforeStop);
    assertClosedAllowlist(afterStop, [...allBodies, ...messageIDs, privatePEM.trim(), pairingCode]);

    const second = await startRelay(binary, repositoryRoot, serverState, undefined, listen);
    relays.push(second.relay);
    assert.equal(second.ready.address, listen);
    assert.equal(await readFile(allowlistPath, "utf8"), beforeStop);
    await clock.advanceBy(500);
    const restartedAuth = [
      await nextEvent(second.relay.output, "auth_accepted"),
      await nextEvent(second.relay.output, "auth_accepted"),
    ];
    assert.deepEqual(
      new Set(restartedAuth.map((event) => event.cwd)),
      new Set([sender.cwd, recipient.cwd]),
    );
    const restartedSender = restartedAuth.find((event) => event.cwd === sender.cwd);
    const restartedRecipient = restartedAuth.find((event) => event.cwd === recipient.cwd);
    assert.ok(restartedSender);
    assert.ok(restartedRecipient);
    assert.equal(restartedSender.address, senderAddress);
    assert.equal(restartedSender.client_id, acceptedPair.client_id);
    assert.equal(restartedSender.client_public_key, acceptedPair.client_public_key);
    assert.equal(restartedRecipient.address, recipientAddress);
    assert.equal(restartedRecipient.route_id, recipientRouteID);
    assert.equal(socketControl.attempts.length, 3);
    await boundedQuietCheckpoint(
      sender,
      recipientAddress,
      recipient,
      4,
      "restart emitted no startup or historical delivery",
    );

    const freshAfterRestart = await within(sender.executeTool("agent_send", {
      to: recipientAddress,
      body: bodies.freshAfterRestart,
    }), "settling fresh post-restart send") as ToolResult;
    assert.deepEqual(freshAfterRestart.details, {
      message_id: freshAfterRestart.details.message_id,
      status: "received",
    });
    assert.match(freshAfterRestart.details.message_id, UUID_V7);
    messageIDs.push(freshAfterRestart.details.message_id);
    await nextEvent(second.relay.output, "send_settled", (event) =>
      event.message_id === freshAfterRestart.details.message_id);

    const messageFrames = recipientMessages(socketControl.frames);
    assert.deepEqual(
      socketControl.frames.map((frame) => ({ attempt: frame.attempt, type: frame.type })),
      [
        { attempt: 1, type: "welcome" },
        { attempt: 1, type: "roster" },
        { attempt: 1, type: "message" },
        { attempt: 1, type: "message" },
        { attempt: 2, type: "welcome" },
        { attempt: 2, type: "message" },
        { attempt: 2, type: "message" },
        { attempt: 3, type: "welcome" },
        { attempt: 3, type: "message" },
      ],
      "recipient sockets received only welcome, requested roster, and exact current delivery frames",
    );
    assert.deepEqual(
      messageFrames.map((frame) => ({
        attempt: frame.attempt,
        messageID: frame.messageID,
        deliveryID: frame.deliveryID,
        body: frame.body,
      })),
      [
        {
          attempt: 1,
          messageID: settledBeforeLoss.details.message_id,
          deliveryID: messageFrames[0]?.deliveryID,
          body: bodies.settledBeforeLoss,
        },
        {
          attempt: 1,
          messageID: disconnectACK.messageID,
          deliveryID: disconnectACK.deliveryID,
          body: bodies.interruptedByDisconnect,
        },
        {
          attempt: 2,
          messageID: freshAfterReconnect.details.message_id,
          deliveryID: messageFrames[2]?.deliveryID,
          body: bodies.freshAfterReconnect,
        },
        {
          attempt: 2,
          messageID: restartACK.messageID,
          deliveryID: restartACK.deliveryID,
          body: bodies.interruptedByRestart,
        },
        {
          attempt: 3,
          messageID: freshAfterRestart.details.message_id,
          deliveryID: messageFrames[4]?.deliveryID,
          body: bodies.freshAfterRestart,
        },
      ],
    );
    for (const frame of messageFrames) {
      assert.match(String(frame.deliveryID), UUID_V7);
    }
    assert.equal(new Set(messageIDs).size, 5);
    assert.equal(new Set(messageFrames.map((frame) => frame.messageID)).size, 5);
    assert.equal(new Set(messageFrames.map((frame) => frame.deliveryID)).size, 5);
    assert.deepEqual(
      injectedText(recipient).map((text, index) => ({
        body: allBodies.find((body) => text.endsWith(`\n${body}`)),
        messageID: messageIDs.find((messageID) => text.includes(`id=${messageID}`)),
        frameMessageID: messageFrames[index]?.messageID,
      })),
      allBodies.map((body, index) => ({
        body,
        messageID: messageIDs[index],
        frameMessageID: messageIDs[index],
      })),
    );
    assert.deepEqual(recipient.sendMessageAttempts, []);
    assert.deepEqual(sender.sendUserMessageAttempts, []);
    assert.deepEqual(sender.sendMessageAttempts, []);

    const firstEvents = first.relay.output.lines.map((line) => JSON.parse(line) as Record<string, unknown>);
    const secondEvents = second.relay.output.lines.map((line) => JSON.parse(line) as Record<string, unknown>);
    const settlementEvents = [...firstEvents, ...secondEvents].filter((event) =>
      event.event === "send_settled" && messageIDs.includes(String(event.message_id)));
    assert.deepEqual(
      settlementEvents.map((event) => ({ messageID: event.message_id, reason: event.reason, body: event.body })),
      [
        { messageID: messageIDs[0], reason: "received", body: "<redacted>" },
        { messageID: messageIDs[1], reason: "recipient_disconnected", body: "<redacted>" },
        { messageID: messageIDs[2], reason: "received", body: "<redacted>" },
        { messageID: messageIDs[4], reason: "received", body: "<redacted>" },
      ],
    );
    assert.equal(settlementEvents.some((event) => event.message_id === restartACK.messageID), false);
    for (const body of allBodies) {
      assert.equal(extensionLogs.some((line) => line.includes(body)), false);
      assert.equal(first.relay.output.lines.some((line) => line.includes(body)), false);
      assert.equal(second.relay.output.lines.some((line) => line.includes(body)), false);
    }

    const unknownPEM = await writeInstallationKey(unknownExtensionState);
    process.env.PI_MESSAGING_RELAY_STATE_DIR = unknownExtensionState;
    const unknown = new FakePiHost();
    unknown.cwd = "/srv/restart-unknown";
    relayExtension(unknown.api as never);
    hosts.push(unknown);
    await unknown.emit("session_start", { type: "session_start", reason: "startup" });
    const rejected = await nextEvent(
      second.relay.output,
      "auth_rejected",
      (event) => event.reason === "not_authorized",
    );
    assert.equal(rejected.reason, "not_authorized");
    await waitUntil(
      () => extensionLogs.some((line) => {
        const event = JSON.parse(line) as Record<string, unknown>;
        return event.event === "relay_auth_rejected" && event.reason === "not_authorized";
      }),
      "unknown extension rejection",
    );
    await assert.rejects(unknown.executeTool("list_peers", {}), /Relay is disconnected/);

    const afterRestart = await readFile(allowlistPath, "utf8");
    assert.equal(afterRestart, beforeStop);
    assertClosedAllowlist(afterRestart, [
      ...allBodies,
      ...messageIDs,
      privatePEM.trim(),
      unknownPEM.trim(),
      pairingCode,
    ]);
    assert.deepEqual(await readdir(serverState), ["allowlist.json"]);
    assert.equal(second.relay.stderr.length, 0);
    assert.equal(first.relay.stderr.length, 0);
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
    for (const relay of relays) {
      try {
        await stopRelay(relay);
      } catch (error: unknown) {
        try {
          await killRelay(relay);
        } catch (killError: unknown) {
          cleanupError ??= killError;
        }
        cleanupError ??= error;
      } finally {
        relay.closeOutput();
      }
    }
    socketControl.restore();
    restoreReconnect();
    console.error = originalError;
    if (previousURL === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = previousURL;
    if (previousState === undefined) delete process.env.PI_MESSAGING_RELAY_STATE_DIR;
    else process.env.PI_MESSAGING_RELAY_STATE_DIR = previousState;
    try {
      await rm(root, { recursive: true, force: true });
    } catch (error: unknown) {
      cleanupError ??= error;
    }
    if (primaryError === undefined && cleanupError !== undefined) throw cleanupError;
  }
});
