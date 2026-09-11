import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import { hostname } from "node:os";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import test from "node:test";

import { FakePiHost } from "./fake-pi-host.ts";

const TEST_TIMEOUT_MS = 15_000;
const AUTH_TRANSCRIPT_DOMAIN = "pi-messaging-relay-auth-v1\n";

type ServerOutput = {
  iterator: AsyncIterator<string>;
  lines: string[];
};

function captureStructuredErrors(): { lines: string[]; restore(): void } {
  const lines: string[] = [];
  const original = console.error;
  console.error = (...values: unknown[]) => lines.push(values.map(String).join(" "));
  return { lines, restore: () => (console.error = original) };
}

async function withTimeout<T>(promise: Promise<T>, action: string): Promise<T> {
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

async function nextServerEvent(
  output: ServerOutput,
  expectedEvent: string,
  matches: (event: Record<string, unknown>) => boolean = () => true,
): Promise<Record<string, unknown>> {
  while (true) {
    const result = await withTimeout(output.iterator.next(), `waiting for ${expectedEvent}`);
    if (result.done) throw new Error(`relay output closed before ${expectedEvent}`);
    output.lines.push(result.value);
    const event = JSON.parse(result.value) as Record<string, unknown>;
    if (event.event === expectedEvent && matches(event)) return event;
  }
}

function structuredEvents(lines: string[]): Record<string, unknown>[] {
  return lines.map((line) => JSON.parse(line) as Record<string, unknown>);
}

async function waitForStructuredEvent(
  lines: string[],
  eventName: string,
  matches: (event: Record<string, unknown>) => boolean,
): Promise<Record<string, unknown>> {
  const started = Date.now();
  while (Date.now() - started < TEST_TIMEOUT_MS) {
    const event = structuredEvents(lines).find((candidate) => candidate.event === eventName && matches(candidate));
    if (event) return event;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`timed out waiting for extension event ${eventName}`);
}

async function settlesWithin(promise: Promise<void>, timeoutMS: number): Promise<boolean> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), timeoutMS);
    promise.then(() => {
      clearTimeout(timer);
      resolve(true);
    });
  });
}

async function terminateAndReap(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  child.kill("SIGTERM");
  if (await settlesWithin(exited, 3_000)) return;
  child.kill("SIGKILL");
  await withTimeout(exited, "reaping relay child");
}

function encodedPublicKey(privateKey: KeyObject): string {
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  assert.equal(typeof jwk.x, "string");
  return `ed25519:${Buffer.from(jwk.x as string, "base64url").toString("base64")}`;
}

function transcript(
  nonce: string,
  values: { requestID: string; clientPublicKey: string; routeID: string; hostname: string; cwd: string },
): Buffer {
  const fields: ReadonlyArray<readonly [string, string]> = [
    ["nonce", nonce],
    ["request_id", values.requestID],
    ["client_public_key", values.clientPublicKey],
    ["route_id", values.routeID],
    ["hostname", values.hostname],
    ["cwd", values.cwd],
  ];
  return Buffer.from(
    AUTH_TRANSCRIPT_DOMAIN + fields.map(([name, value]) =>
      `${name}:${Buffer.byteLength(value, "utf8")}:${value}\n`).join(""),
    "utf8",
  );
}

async function nextMessage(socket: WebSocket): Promise<Record<string, unknown>> {
  return withTimeout(new Promise((resolve, reject) => {
    socket.addEventListener("message", (event) => {
      try {
        assert.equal(typeof event.data, "string");
        resolve(JSON.parse(event.data) as Record<string, unknown>);
      } catch (error) {
        reject(error);
      }
    }, { once: true });
    socket.addEventListener("error", () => reject(new Error("raw WebSocket failed")), { once: true });
  }), "waiting for WebSocket frame");
}

async function nextClose(socket: WebSocket): Promise<CloseEvent> {
  if (socket.readyState === WebSocket.CLOSED) throw new Error("socket closed before close listener was installed");
  return withTimeout(new Promise((resolve) => {
    socket.addEventListener("close", resolve, { once: true });
  }), "waiting for WebSocket peer close");
}

async function openChallenge(endpoint: string): Promise<{ socket: WebSocket; nonce: string }> {
  const socket = new WebSocket(endpoint);
  const challenge = await nextMessage(socket);
  assert.deepEqual(Object.keys(challenge).sort(), ["payload", "type", "v"]);
  assert.equal(challenge.v, 1);
  assert.equal(challenge.type, "challenge");
  const payload = challenge.payload as Record<string, unknown>;
  assert.deepEqual(Object.keys(payload), ["nonce"]);
  assert.match(String(payload.nonce), /^[A-Za-z0-9_-]{43}$/);
  return { socket, nonce: String(payload.nonce) };
}

function sendHello(
  socket: WebSocket,
  nonce: string,
  values: { requestID: string; clientPublicKey: string; routeID: string; hostname: string; cwd: string },
  signingKey: KeyObject,
): string {
  const signature = sign(null, transcript(nonce, values), signingKey).toString("base64");
  socket.send(JSON.stringify({
    v: 1,
    type: "hello",
    request_id: values.requestID,
    payload: {
      client_public_key: values.clientPublicKey,
      route_id: values.routeID,
      hostname: values.hostname,
      cwd: values.cwd,
      signature,
    },
  }));
  return signature;
}

test("real WebSocket boundary authenticates paired extension and rejects unauthorized raw clients", { timeout: 60_000 }, async (context) => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const testRoot = await mkdtemp(join(tmpdir(), "pi-relay-session-auth-"));
  await chmod(testRoot, 0o700);
  context.after(async () => rm(testRoot, { recursive: true, force: true }));
  const binary = join(testRoot, "relay-server");
  const serverState = join(testRoot, "server-state");
  const extensionState = join(testRoot, "extension-state");
  const codeFile = join(serverState, "pairing-code");
  execFileSync("go", ["build", "-o", binary, "./cmd/pi-messaging-relay-server"], {
    cwd: repositoryRoot,
    stdio: "pipe",
  });

  const child = spawn(binary, [
    "--listen", "127.0.0.1:0",
    "--state-dir", serverState,
    "--pairing-code-file", codeFile,
  ], { cwd: repositoryRoot, stdio: ["ignore", "pipe", "pipe"] });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const stdout = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const output: ServerOutput = { iterator: stdout[Symbol.asyncIterator](), lines: [] };
  context.after(async () => terminateAndReap(child));

  const previousURL = process.env.PI_MESSAGING_RELAY_URL;
  const previousState = process.env.PI_MESSAGING_RELAY_STATE_DIR;
  const logs = captureStructuredErrors();
  let rawPairingCode = "";
  let privatePEM = "";
  try {
    const ready = await nextServerEvent(output, "server_ready");
    await nextServerEvent(output, "pairing_code_created");
    const address = String(ready.address);
    const wsEndpoint = `ws://${address}/v1/connect`;
    rawPairingCode = (await readFile(codeFile, "utf8")).trim();
    process.env.PI_MESSAGING_RELAY_URL = `http://${address}`;
    process.env.PI_MESSAGING_RELAY_STATE_DIR = extensionState;

    const host = new FakePiHost();
    host.cwd = "/srv/auth-acceptance";
    const relayExtension = (await import(`../index.ts?session-auth=${Date.now()}`)).default;
    relayExtension(host.api as never);
    assert.equal(output.lines.some((line) => line.includes(rawPairingCode)), false);

    await host.emit("session_start");
    await host.executeCommand("relay-pair", rawPairingCode);
    const pairAccepted = await nextServerEvent(output, "pair_accepted");
    const extensionAccepted = await nextServerEvent(output, "auth_accepted");
    assert.equal(extensionAccepted.cwd, host.cwd);
    assert.equal(extensionAccepted.hostname, hostname());
    assert.match(String(extensionAccepted.route_id), /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.equal(
      extensionAccepted.address,
      `${host.cwd}@${hostname()}#${String(extensionAccepted.route_id)}`,
    );
    assert.deepEqual(
      {
        result: extensionAccepted.result,
        nonce: extensionAccepted.nonce,
        signature: extensionAccepted.signature,
        private_key: extensionAccepted.private_key,
      },
      { result: "accepted", nonce: "<redacted>", signature: "<redacted>", private_key: "<redacted>" },
    );
    assert.equal(pairAccepted.client_public_key, extensionAccepted.client_public_key);
    const extensionRouteID = String(extensionAccepted.route_id);
    const extensionAddress = String(extensionAccepted.address);
    const extensionAuthEvents = structuredEvents(logs.lines).filter((event) =>
      event.event === "relay_auth_accepted" && event.route_id === extensionRouteID);
    assert.equal(extensionAuthEvents.length, 1);
    assert.equal(extensionAuthEvents[0].address, extensionAddress);
    assert.equal(extensionAuthEvents[0].client_public_key, extensionAccepted.client_public_key);
    assert.equal(structuredEvents(logs.lines).some((event) =>
      event.event === "relay_session_disconnected" && event.route_id === extensionRouteID), false);
    assert.equal(host.registrations.filter((entry) => entry.kind === "tool").length, 2);
    assert.deepEqual(host.sendMessageAttempts, []);
    assert.deepEqual(host.sendUserMessageAttempts, []);

    privatePEM = await readFile(join(extensionState, "installation-ed25519.pem"), "utf8");
    const pairedPrivateKey = createPrivateKey(privatePEM);
    const pairedPublicKey = encodedPublicKey(pairedPrivateKey);

    const validRaw = await openChallenge(wsEndpoint);
    const displayValues = {
      requestID: "01993c79-8ad7-79fa-83e3-9789dcaca168",
      clientPublicKey: pairedPublicKey,
      routeID: "01993ca1-1111-7aaa-8aaa-111111111111",
      hostname: "display@host#only",
      cwd: "/display/@and#metadata",
    };
    const validRawSignature = sendHello(validRaw.socket, validRaw.nonce, displayValues, pairedPrivateKey);
    const welcome = await nextMessage(validRaw.socket);
    assert.deepEqual(welcome, {
      v: 1,
      type: "welcome",
      request_id: displayValues.requestID,
      payload: {
        self_address: `${displayValues.cwd}@${displayValues.hostname}#${displayValues.routeID}`,
        heartbeat_ms: 30_000,
        max_body_bytes: 262_144,
      },
    });
    const rawAccepted = await nextServerEvent(output, "auth_accepted");
    assert.equal(rawAccepted.request_id, displayValues.requestID);
    assert.equal(rawAccepted.client_id, pairAccepted.client_id);
    assert.equal(rawAccepted.cwd, displayValues.cwd);
    assert.equal(rawAccepted.hostname, displayValues.hostname);
    validRaw.socket.close(1000, "test complete");
    await nextServerEvent(output, "session_disconnected");

    const unknownKey = generateKeyPairSync("ed25519").privateKey;
    const unknownRaw = await openChallenge(wsEndpoint);
    const unknownValues = {
      ...displayValues,
      requestID: "01993c79-8ad8-79fa-83e3-9789dcaca168",
      routeID: "01993ca1-1112-7aaa-8aaa-111111111111",
      clientPublicKey: encodedPublicKey(unknownKey),
    };
    const unknownRawSignature = sendHello(unknownRaw.socket, unknownRaw.nonce, unknownValues, unknownKey);
    const unknownErrorPromise = nextMessage(unknownRaw.socket);
    const unknownClosePromise = nextClose(unknownRaw.socket);
    assert.deepEqual(await unknownErrorPromise, {
      v: 1,
      type: "error",
      request_id: unknownValues.requestID,
      payload: { code: "not_authorized", message: "Client key is not authorized", close: true },
    });
    assert.notEqual((await unknownClosePromise).code, 1000);
    const unknownRejected = await nextServerEvent(output, "auth_rejected");
    assert.equal(unknownRejected.reason, "not_authorized");
    assert.equal(unknownRejected.request_id, unknownValues.requestID);

    const invalidRaw = await openChallenge(wsEndpoint);
    const invalidValues = {
      ...displayValues,
      requestID: "01993c79-8ad9-79fa-83e3-9789dcaca168",
      routeID: "01993ca1-1113-7aaa-8aaa-111111111111",
    };
    const invalidRawSignature = sendHello(invalidRaw.socket, invalidRaw.nonce, invalidValues, unknownKey);
    const invalidErrorPromise = nextMessage(invalidRaw.socket);
    const invalidClosePromise = nextClose(invalidRaw.socket);
    assert.deepEqual(await invalidErrorPromise, {
      v: 1,
      type: "error",
      request_id: invalidValues.requestID,
      payload: { code: "not_authorized", message: "Client key is not authorized", close: true },
    });
    await invalidClosePromise;
    const invalidRejected = await nextServerEvent(output, "auth_rejected");
    assert.equal(invalidRejected.reason, "not_authorized");
    assert.equal(invalidRejected.request_id, invalidValues.requestID);

    assert.equal(new Set([validRaw.nonce, unknownRaw.nonce, invalidRaw.nonce]).size, 3);
    assert.equal(structuredEvents(logs.lines).some((event) =>
      event.event === "relay_session_disconnected" && event.route_id === extensionRouteID), false);

    const childExited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
    assert.equal(child.kill("SIGTERM"), true);
    const extensionDisconnected = await nextServerEvent(
      output,
      "session_disconnected",
      (event) => event.route_id === extensionRouteID && event.address === extensionAddress,
    );
    assert.equal(extensionDisconnected.client_public_key, extensionAccepted.client_public_key);
    const stopped = await nextServerEvent(output, "server_stopped");
    assert.equal(stopped.result, "graceful");
    await withTimeout(childExited, "waiting for graceful relay shutdown");
    const clientDisconnected = await waitForStructuredEvent(
      logs.lines,
      "relay_session_disconnected",
      (event) => event.route_id === extensionRouteID && event.address === extensionAddress,
    );
    assert.equal(clientDisconnected.client_public_key, extensionAccepted.client_public_key);
    await host.emit("session_shutdown");
    await host.emit("session_shutdown");
    assert.equal(structuredEvents(logs.lines).filter((event) =>
      event.event === "relay_session_disconnected" && event.route_id === extensionRouteID).length, 1);

    const allOutput = [...output.lines, ...logs.lines, Buffer.concat(stderr).toString("utf8")].join("\n");
    assert.equal(allOutput.includes(rawPairingCode), false);
    assert.equal(allOutput.includes(privatePEM.trim()), false);
    for (const sensitiveValue of [
      validRaw.nonce,
      unknownRaw.nonce,
      invalidRaw.nonce,
      validRawSignature,
      unknownRawSignature,
      invalidRawSignature,
    ]) {
      assert.equal(allOutput.includes(sensitiveValue), false);
    }
    for (const line of [...output.lines, ...logs.lines]) {
      const event = JSON.parse(line) as Record<string, unknown>;
      if ("nonce" in event) assert.equal(event.nonce, "<redacted>");
      if ("signature" in event) assert.equal(event.signature, "<redacted>");
      if ("private_key" in event) assert.equal(event.private_key, "<redacted>");
    }
  } finally {
    logs.restore();
    if (previousURL === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = previousURL;
    if (previousState === undefined) delete process.env.PI_MESSAGING_RELAY_STATE_DIR;
    else process.env.PI_MESSAGING_RELAY_STATE_DIR = previousState;
    await terminateAndReap(child);
    stdout.close();
    await rm(testRoot, { recursive: true, force: true });
  }
});

test("pre-paired installation authenticates exactly once when session lifecycle starts", { timeout: 60_000 }, async (context) => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const testRoot = await mkdtemp(join(tmpdir(), "pi-relay-prepaired-session-auth-"));
  await chmod(testRoot, 0o700);
  context.after(async () => rm(testRoot, { recursive: true, force: true }));
  const binary = join(testRoot, "relay-server");
  const serverState = join(testRoot, "server-state");
  const extensionState = join(testRoot, "extension-state");
  const codeFile = join(serverState, "pairing-code");
  execFileSync("go", ["build", "-o", binary, "./cmd/pi-messaging-relay-server"], {
    cwd: repositoryRoot,
    stdio: "pipe",
  });

  const child = spawn(binary, [
    "--listen", "127.0.0.1:0",
    "--state-dir", serverState,
    "--pairing-code-file", codeFile,
  ], { cwd: repositoryRoot, stdio: ["ignore", "pipe", "pipe"] });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const stdout = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const output: ServerOutput = { iterator: stdout[Symbol.asyncIterator](), lines: [] };
  context.after(async () => terminateAndReap(child));

  const previousURL = process.env.PI_MESSAGING_RELAY_URL;
  const previousState = process.env.PI_MESSAGING_RELAY_STATE_DIR;
  const logs = captureStructuredErrors();
  let rawPairingCode = "";
  try {
    const ready = await nextServerEvent(output, "server_ready");
    await nextServerEvent(output, "pairing_code_created");
    rawPairingCode = (await readFile(codeFile, "utf8")).trim();
    process.env.PI_MESSAGING_RELAY_URL = `http://${String(ready.address)}`;
    process.env.PI_MESSAGING_RELAY_STATE_DIR = extensionState;

    const host = new FakePiHost();
    host.cwd = "/srv/prepaired-acceptance";
    const relayExtension = (await import(`../index.ts?prepaired-session-auth=${Date.now()}`)).default;
    relayExtension(host.api as never);

    await host.executeCommand("relay-pair", rawPairingCode);
    const pairAccepted = await nextServerEvent(output, "pair_accepted");
    assert.equal(structuredEvents(logs.lines).some((event) => event.event === "relay_auth_accepted"), false);

    await host.emit("session_start");
    const serverAccepted = await nextServerEvent(output, "auth_accepted");
    const routeID = String(serverAccepted.route_id);
    const address = String(serverAccepted.address);
    assert.equal(serverAccepted.client_public_key, pairAccepted.client_public_key);
    assert.equal(serverAccepted.cwd, host.cwd);
    const extensionAccepted = structuredEvents(logs.lines).filter((event) =>
      event.event === "relay_auth_accepted" && event.route_id === routeID);
    assert.equal(extensionAccepted.length, 1);
    assert.equal(extensionAccepted[0].address, address);
    assert.equal(extensionAccepted[0].client_public_key, pairAccepted.client_public_key);

    await host.emit("session_shutdown");
    const serverDisconnected = await nextServerEvent(
      output,
      "session_disconnected",
      (event) => event.route_id === routeID && event.address === address,
    );
    assert.equal(serverDisconnected.client_public_key, pairAccepted.client_public_key);
    const extensionDisconnected = await waitForStructuredEvent(
      logs.lines,
      "relay_session_disconnected",
      (event) => event.route_id === routeID && event.address === address,
    );
    assert.equal(extensionDisconnected.client_public_key, pairAccepted.client_public_key);

    const childExited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
    assert.equal(child.kill("SIGTERM"), true);
    const stopped = await nextServerEvent(output, "server_stopped");
    assert.equal(stopped.result, "graceful");
    await withTimeout(childExited, "waiting for pre-paired relay shutdown");

    assert.equal(output.lines.filter((line) => {
      const event = JSON.parse(line) as Record<string, unknown>;
      return event.event === "auth_accepted" && event.route_id === routeID;
    }).length, 1);
    assert.equal(structuredEvents(logs.lines).filter((event) =>
      event.event === "relay_auth_accepted" && event.route_id === routeID).length, 1);
    const allOutput = [...output.lines, ...logs.lines, Buffer.concat(stderr).toString("utf8")].join("\n");
    assert.equal(allOutput.includes(rawPairingCode), false);
  } finally {
    logs.restore();
    if (previousURL === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
    else process.env.PI_MESSAGING_RELAY_URL = previousURL;
    if (previousState === undefined) delete process.env.PI_MESSAGING_RELAY_STATE_DIR;
    else process.env.PI_MESSAGING_RELAY_STATE_DIR = previousState;
    await terminateAndReap(child);
    stdout.close();
    await rm(testRoot, { recursive: true, force: true });
  }
});
