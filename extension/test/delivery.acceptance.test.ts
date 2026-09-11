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

    const offlineAddress = "/srv/absent@workstation#01993ca3-3333-7aaa-8aaa-333333333333";
    const offlineBodyMarker = "offline-body-must-never-reach-recipient-or-logs";
    const offlineStarted = Date.now();
    const offlineResult = await within(sender.executeTool("agent_send", {
      to: offlineAddress,
      body: offlineBodyMarker,
    }), "sender received offline result") as ToolResult;
    assert.equal(Date.now() - offlineStarted < 4_000, true);
    assert.deepEqual(Object.keys(offlineResult.details), ["message_id", "status", "reason"]);
    assert.match(offlineResult.details.message_id, UUID_V7);
    assert.deepEqual(offlineResult.details, {
      message_id: offlineResult.details.message_id,
      status: "timeout",
      reason: "offline",
    });
    assert.deepEqual(offlineResult.content, [{
      type: "text",
      text: JSON.stringify(offlineResult.details),
    }]);
    assert.deepEqual(recipient.sendUserMessageAttempts, []);
    assert.deepEqual(recipient.sendMessageAttempts, []);

    const offlineSettled = await nextEvent(output, "send_settled", (event) =>
      event.message_id === offlineResult.details.message_id);
    assert.equal(offlineSettled.level, "info");
    assert.equal(offlineSettled.result, "settled");
    assert.equal(offlineSettled.reason, "offline");
    assert.equal(offlineSettled.code, "offline");
    assert.equal(offlineSettled.type, "send");
    assert.match(String(offlineSettled.request_id), UUID_V7);
    assert.equal(offlineSettled.message_id, offlineResult.details.message_id);
    assert.equal(offlineSettled.delivery_id, undefined);
    assert.equal(offlineSettled.sender_route, senderAuth.address);
    assert.equal(offlineSettled.recipient_route, offlineAddress);
    assert.equal(offlineSettled.status, "timeout");
    assert.equal(offlineSettled.body, "<redacted>");
    assert.equal(typeof offlineSettled.latency_ms, "number");
    assert.equal(output.lines.some((line) => line.includes(offlineBodyMarker)), false);
    assert.equal(extensionLogs.some((line) => line.includes(offlineBodyMarker)), false);

    const rosterAfterOffline = await within(
      sender.executeTool("list_peers", {}),
      "listing peers after offline result",
    ) as { content: Array<{ type: string; text: string }>; details: { peers: Array<{ address: string }> } };
    assert.deepEqual(rosterAfterOffline.details, { peers: [{ address: recipientAddress }] });
    assert.deepEqual(rosterAfterOffline.content, [{
      type: "text",
      text: JSON.stringify(rosterAfterOffline.details),
    }]);

    const rejectedMarker = "proxy-content-must-not-cross-any-boundary";
    let proxyTrapCalls = 0;
    const transparentProxy = new Proxy({ value: rejectedMarker }, {});
    const mutatingTarget = { value: rejectedMarker };
    const mutatingProxy = new Proxy(mutatingTarget, {
      ownKeys(target) {
        proxyTrapCalls += 1;
        target.value = "mutated-proxy-content-must-not-cross";
        return Reflect.ownKeys(target);
      },
    });
    for (const body of [transparentProxy, { nested: transparentProxy }, { nested: mutatingProxy }]) {
      await assert.rejects(
        sender.executeTool("agent_send", { to: recipientAddress, body }),
        (error: unknown) => error instanceof Error &&
          error.name === "RosterRequestError" &&
          (error as Error & { reason?: string }).reason === "invalid_arguments" &&
          error.message === "Relay agent_send body is not safe JSON." &&
          !error.message.includes(rejectedMarker),
      );
    }
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(proxyTrapCalls, 0);
    assert.equal(mutatingTarget.value, rejectedMarker);
    assert.deepEqual(recipient.sendUserMessageAttempts, []);
    assert.equal(extensionLogs.some((line) => line.includes(rejectedMarker)), false);
    assert.equal(output.lines.some((line) => line.includes(rejectedMarker)), false);

    const bodyBoundaryMarker = "model-body-boundary-private-marker-\"-\n-💾";
    const bodyBoundaryPrefixBytes = Buffer.byteLength(JSON.stringify(bodyBoundaryMarker), "utf8");
    const atBodyLimit = bodyBoundaryMarker + "x".repeat((256 * 1024) - bodyBoundaryPrefixBytes);
    assert.equal(Buffer.byteLength(JSON.stringify(atBodyLimit), "utf8"), 262_144);
    const atLimitResult = await within(sender.executeTool("agent_send", {
      to: recipientAddress,
      body: atBodyLimit,
    }), "sending exact body limit") as ToolResult;
    assert.equal(atLimitResult.details.status, "received");
    assert.equal(recipient.sendUserMessageAttempts.length, 1);
    assert.equal(String(recipient.sendUserMessageAttempts[0][0]).endsWith(atBodyLimit), true);
    await nextEvent(output, "send_settled", (event) => event.message_id === atLimitResult.details.message_id);

    const attemptsAtBoundary = recipient.sendUserMessageAttempts.length;
    await assert.rejects(
      sender.executeTool("agent_send", { to: recipientAddress, body: atBodyLimit + "x" }),
      (error: unknown) => error instanceof Error &&
        error.name === "RosterRequestError" &&
        (error as Error & { reason?: string }).reason === "body_too_large" &&
        error.message === "Relay agent_send body exceeds 256 KiB." &&
        !error.message.includes(bodyBoundaryMarker),
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(recipient.sendUserMessageAttempts.length, attemptsAtBoundary);
    assert.equal(extensionLogs.some((line) => line.includes(bodyBoundaryMarker)), false);
    assert.equal(output.lines.some((line) => line.includes(bodyBoundaryMarker)), false);
    assert.equal(extensionLogs.some((line) => line.includes('"reason":"body_too_large"')), true);
    const rosterAfterBodyDenial = await within(
      sender.executeTool("list_peers", {}),
      "listing peers after local body denial",
    ) as { details: { peers: Array<{ address: string }> } };
    assert.deepEqual(rosterAfterBodyDenial.details, { peers: [{ address: recipientAddress }] });
    recipient.sendUserMessageAttempts.length = 0;

    const objectMarker = "local-object-body-crosses-canonically";
    const messageIDs: string[] = [];
    const deliveryIDs: string[] = [];
    const deliveries = [
      {
        body: { "2": "two", "10": "ten", private: objectMarker, nested: { z: false, a: [null, 1] } },
        renderedBody: `{"10":"ten","2":"two","nested":{"a":[null,1],"z":false},"private":"${objectMarker}"}`,
        re: "01993c80-40de-79d7-9b2c-1349f88bb408",
        idle: false,
      },
      {
        body: "  Review exact idle text\nwithout normalization\n",
        renderedBody: "  Review exact idle text\nwithout normalization\n",
        idle: true,
      },
      {
        body: "Attempt busy delivery even when Pi rejects it",
        renderedBody: "Attempt busy delivery even when Pi rejects it",
        idle: false,
        throwFromPi: true,
      },
      {
        body: "Fail safe when recipient idle observation throws",
        renderedBody: "Fail safe when recipient idle observation throws",
        idle: true,
        throwFromIdleCheck: true,
      },
    ];
    for (const [index, delivery] of deliveries.entries()) {
      recipient.setIdle(delivery.idle);
      if (delivery.throwFromIdleCheck) recipient.failNextIdleCheck(new Error("simulated stale context"));
      if (delivery.throwFromPi) recipient.failNextSendUserMessage(new Error("simulated Pi rejection"));
      const resultPromise = sender.executeTool("agent_send", {
        to: recipientAddress,
        body: delivery.body,
        ...(delivery.re === undefined ? {} : { re: delivery.re }),
      });
      await waitForAttempt(recipient, index + 1);
      const result = await within(resultPromise, "sender received result") as ToolResult;
      const rendered = `[pi-messaging-relay] message from ${JSON.stringify(String(senderAuth.address))} ` +
        `(id=${result.details.message_id}${delivery.re === undefined ? "" : `, re=${delivery.re}`}):\n${delivery.renderedBody}`;
      assert.deepEqual(
        recipient.sendUserMessageAttempts[index],
        delivery.idle && !delivery.throwFromIdleCheck
          ? [rendered]
          : [rendered, { deliverAs: "followUp" }],
      );
      assert.equal(rendered.includes(`id=${result.details.message_id}`), true);
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

    assert.equal(new Set(messageIDs).size, deliveries.length);
    assert.equal(new Set(deliveryIDs).size, deliveries.length);
    assert.deepEqual(recipient.sendMessageAttempts, []);
    assert.deepEqual(sender.sendMessageAttempts, []);
    assert.equal(JSON.stringify(recipient.sendUserMessageAttempts).includes("steer"), false);
    const stringBodies = deliveries.filter((delivery) => typeof delivery.body === "string")
      .map((delivery) => delivery.body as string);
    assert.equal(stringBodies.some((body) =>
      extensionLogs.some((line) => line.includes(body))), false);
    assert.equal(extensionLogs.some((line) => line.includes(objectMarker)), false);
    assert.equal(extensionLogs.some((line) => line.includes("[pi-messaging-relay] message from")), false);
    assert.equal(stringBodies.some((body) =>
      output.lines.some((line) => line.includes(body))), false);
    assert.equal(output.lines.some((line) => line.includes(objectMarker)), false);
    assert.equal(output.lines.some((line) => line.includes("[pi-messaging-relay] message from")), false);
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
