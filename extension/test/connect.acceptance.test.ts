import assert from "node:assert/strict";
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import test from "node:test";

import WebSocket from "ws";

import { clientConfigurationPath } from "../internal/client-config.ts";
import { FakePiHost } from "./fake-pi-host.ts";

const TEST_TIMEOUT_MS = 15_000;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHARED_SECRET = "acceptance-shared-secret";

type Output = { iterator: AsyncIterator<string>; lines: string[] };

type RelayProcess = {
  child: ChildProcessWithoutNullStreams;
  output: Output;
  stderr: Buffer[];
  closeOutput(): void;
};

function captureStructuredErrors(): { lines: string[]; restore(): void } {
  const lines: string[] = [];
  const original = console.error;
  console.error = (...values: unknown[]) => lines.push(values.map(String).join(" "));
  return { lines, restore: () => (console.error = original) };
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
  output: Output,
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

function structuredEvents(lines: string[]): Record<string, unknown>[] {
  return lines.map((line) => JSON.parse(line) as Record<string, unknown>);
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

async function startRelay(
  binary: string,
  repositoryRoot: string,
  stateDirectory: string,
  secretFile: string | undefined,
): Promise<RelayProcess> {
  const args = ["--listen", "127.0.0.1:0", "--state-dir", stateDirectory];
  if (secretFile !== undefined) args.push("--secret-file", secretFile);
  const child = spawn(binary, args, { cwd: repositoryRoot, stdio: ["ignore", "pipe", "pipe"] });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  return {
    child,
    output: { iterator: lines[Symbol.asyncIterator](), lines: [] },
    stderr,
    closeOutput: () => lines.close(),
  };
}

async function writeClientConfig(home: string, configuration: { url: string; secret?: string }): Promise<void> {
  await mkdir(join(home, ".config", "pi"), { recursive: true, mode: 0o700 });
  await writeFile(
    clientConfigurationPath(home),
    JSON.stringify(configuration),
    { mode: 0o600 },
  );
}

function installIsolatedHome(home: string): { restore(): void } {
  const previousHome = process.env.HOME;
  const previousXDG = process.env.XDG_CONFIG_HOME;
  const previousEndpoint = process.env.PI_MESSAGING_RELAY_URL;
  process.env.HOME = home;
  delete process.env.XDG_CONFIG_HOME;
  delete process.env.PI_MESSAGING_RELAY_URL;
  return {
    restore: () => {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
      if (previousXDG === undefined) delete process.env.XDG_CONFIG_HOME;
      else process.env.XDG_CONFIG_HOME = previousXDG;
      if (previousEndpoint === undefined) delete process.env.PI_MESSAGING_RELAY_URL;
      else process.env.PI_MESSAGING_RELAY_URL = previousEndpoint;
    },
  };
}

type UpgradeResult = { status: string; body: string; headers: Record<string, string> };

let rawRouteCounter = 0;

function rawUpgrade(origin: string, authorization: string | undefined, helloPayload?: object): Promise<UpgradeResult> {
  rawRouteCounter += 1;
  const counter = rawRouteCounter;
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(`ws://${origin}/v1/connect`, {
      headers: authorization === undefined ? {} : { Authorization: authorization },
    });
    let settled = false;
    const finish = (result: UpgradeResult) => {
      if (settled) return;
      settled = true;
      socket.close();
      resolve(result);
    };
    socket.addEventListener("error", () => {
      if (settled) return;
      settled = true;
      reject(new Error("raw WebSocket upgrade failed before any response"));
    });
    socket.addEventListener("open", () => {
      socket.send(JSON.stringify({
        v: 1,
        type: "hello",
        request_id: "01993c79-8ad7-79fa-83e3-9789dcaca168",
        payload: helloPayload ?? {
          route_id: `01993ca1-111${String(counter).padStart(1, "0")}-7aaa-8aaa-${String(counter).padStart(12, "0")}`,
          hostname: "raw-acceptance-host",
          cwd: `/srv/raw-acceptance-${counter}`,
        },
      }));
      socket.addEventListener("message", (event) => {
        finish({
          status: "101",
          body: String(event.data),
          headers: {},
        });
      });
    });
    socket.addEventListener("close", () => finish({ status: "closed", body: "", headers: {} }));
  });
}

function httpRequest(origin: string, path: string, authorization: string | undefined): Promise<UpgradeResult> {
  return fetch(`http://${origin}${path}`, {
    headers: authorization === undefined ? {} : { Authorization: authorization },
  }).then(async (response) => ({
    status: String(response.status),
    body: await response.text(),
    headers: Object.fromEntries(response.headers),
  }));
}

test("secret-mode server authenticates the configured extension and closes every wrong credential identically", {
  timeout: 60_000,
  concurrency: false,
}, async (context) => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const root = await mkdtemp(join(tmpdir(), "pi-relay-connect-secret-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const binary = join(root, "relay-server");
  const serverState = join(root, "server-state");
  const extensionHome = join(root, "extension-home");
  const secretFile = join(serverState, "relay.secret");
  execFileSync("go", ["build", "-o", binary, "./cmd/pi-messaging-relay-server"], {
    cwd: repositoryRoot,
    stdio: "pipe",
  });
  await mkdir(serverState, { recursive: true, mode: 0o700 });
  await writeFile(secretFile, SHARED_SECRET, { mode: 0o600 });

  const relay = await startRelay(binary, repositoryRoot, serverState, secretFile);
  context.after(async () => {
    await stop(relay.child);
    relay.closeOutput();
  });
  const environment = installIsolatedHome(extensionHome);
  const logs = captureStructuredErrors();
  const host = new FakePiHost();
  host.cwd = "/srv/connect-acceptance";

  try {
    const ready = await nextEvent(relay.output, "server_ready");
    assert.deepEqual(
      { result: ready.result, auth: ready.auth, state_dir: ready.state_dir },
      { result: "ready", auth: "secret", state_dir: serverState },
    );
    const origin = String(ready.address);
    await writeClientConfig(extensionHome, { url: `http://${origin}`, secret: SHARED_SECRET });

    const relayExtension = (await import(`../index.ts?connect-secret=${Date.now()}`)).default;
    relayExtension(host.api as never);
    await host.emit("session_start", { type: "session_start", reason: "startup" });
    const accepted = await nextEvent(relay.output, "auth_accepted", (event) => event.cwd === host.cwd);
    const routeID = String(accepted.route_id);
    const address = String(accepted.address);
    assert.match(routeID, UUID_V7);
    assert.equal(address, `${host.cwd}@${String(accepted.hostname)}#${routeID}`);
    assert.deepEqual(
      Object.keys(accepted).sort(),
      ["address", "cwd", "event", "hostname", "latency_ms", "level", "request_id", "result", "route_id"],
    );
    const extensionAccepted = structuredEvents(logs.lines).find((event) =>
      event.event === "relay_auth_accepted" && event.route_id === routeID);
    assert.ok(extensionAccepted);
    assert.equal(extensionAccepted.address, address);
    assert.deepEqual(
      Object.keys(extensionAccepted).sort(),
      ["address", "event", "latency_ms", "level", "result", "route_id"],
    );

    const missing = await httpRequest(origin, "/v1/connect", undefined);
    assert.deepEqual(
      { status: missing.status, body: missing.body },
      { status: "401", body: '{"error":"not_authorized","message":"Authentication is required"}' },
    );
    assert.equal(missing.headers["www-authenticate"], "Bearer");
    const wrongScheme = await httpRequest(origin, "/v1/connect", `Basic ${SHARED_SECRET}`);
    assert.deepEqual({ status: wrongScheme.status, body: wrongScheme.body }, {
      status: "401",
      body: '{"error":"not_authorized","message":"Authentication is required"}',
    });
    const wrongSecret = await httpRequest(origin, "/v1/connect", "Bearer wrong-secret");
    assert.deepEqual({ status: wrongSecret.status, body: wrongSecret.body }, {
      status: "401",
      body: '{"error":"not_authorized","message":"Authentication is required"}',
    });

    const rawAddress = {
      route_id: "01993ca1-1111-7aaa-8aaa-111111111111",
      hostname: "raw-acceptance-host",
      cwd: "/srv/raw-acceptance",
    };
    const raw = await rawUpgrade(origin, `Bearer ${SHARED_SECRET}`, rawAddress);
    assert.equal(raw.status, "101");
    const welcome = JSON.parse(raw.body) as Record<string, unknown>;
    assert.deepEqual(Object.keys(welcome).sort(), ["payload", "request_id", "type", "v"]);
    assert.deepEqual(welcome.payload, {
      self_address: `${rawAddress.cwd}@${rawAddress.hostname}#${rawAddress.route_id}`,
      heartbeat_ms: 30_000,
      max_body_bytes: 262_144,
    });
    await nextEvent(relay.output, "auth_accepted", (event) => event.cwd === rawAddress.cwd);
    await nextEvent(relay.output, "session_disconnected", (event) =>
      event.cwd === undefined && event.address === `${rawAddress.cwd}@${rawAddress.hostname}#${rawAddress.route_id}`);

    const rejectedCount = structuredEvents(relay.output.lines).filter((event) =>
      event.event === "auth_rejected" && event.reason === "not_authorized").length;
    assert.equal(rejectedCount, 3);

    const roster = await within(host.executeTool("list_peers", {}), "listing peers while authenticated");
    assert.deepEqual(
      (roster as { details: { peers: Array<{ address: string }> } }).details,
      { peers: [] },
    );

    await host.emit("session_shutdown");
    await nextEvent(relay.output, "session_disconnected", (event) => event.address === address);

    const allOutput = [...relay.output.lines, ...logs.lines, Buffer.concat(relay.stderr).toString("utf8")].join("\n");
    assert.equal(allOutput.includes(SHARED_SECRET), false);
    for (const line of [...relay.output.lines, ...logs.lines]) {
      const event = JSON.parse(line) as Record<string, unknown>;
      if ("secret" in event) assert.equal(event.secret, "<redacted>");
      assert.equal("client_public_key" in event || "nonce" in event || "signature" in event, false);
    }
  } finally {
    logs.restore();
    environment.restore();
  }
});

test("auth-off server accepts header-less and credentialed clients identically", {
  timeout: 60_000,
  concurrency: false,
}, async (context) => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const root = await mkdtemp(join(tmpdir(), "pi-relay-connect-off-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const binary = join(root, "relay-server");
  const serverState = join(root, "server-state");
  const extensionHome = join(root, "extension-home");
  execFileSync("go", ["build", "-o", binary, "./cmd/pi-messaging-relay-server"], {
    cwd: repositoryRoot,
    stdio: "pipe",
  });
  const relay = await startRelay(binary, repositoryRoot, serverState, undefined);
  context.after(async () => {
    await stop(relay.child);
    relay.closeOutput();
  });
  const environment = installIsolatedHome(extensionHome);
  const logs = captureStructuredErrors();
  const host = new FakePiHost();
  host.cwd = "/srv/auth-off-acceptance";

  try {
    const ready = await nextEvent(relay.output, "server_ready");
    assert.equal(ready.auth, "off");
    const origin = String(ready.address);
    await writeClientConfig(extensionHome, { url: `http://${origin}` });

    const relayExtension = (await import(`../index.ts?connect-off=${Date.now()}`)).default;
    relayExtension(host.api as never);
    await host.emit("session_start", { type: "session_start", reason: "startup" });
    const accepted = await nextEvent(relay.output, "auth_accepted", (event) => event.cwd === host.cwd);

    const anonymous = await rawUpgrade(origin, undefined);
    assert.equal(anonymous.status, "101");
    await nextEvent(relay.output, "auth_accepted", (event) =>
      String(event.cwd ?? "").startsWith("/srv/raw-acceptance-"));

    const credentialed = await rawUpgrade(origin, "Bearer irrelevant-value");
    assert.equal(credentialed.status, "101");
    await nextEvent(relay.output, "auth_accepted", (event) =>
      String(event.cwd ?? "").startsWith("/srv/raw-acceptance-") && event.route_id !== accepted.route_id);

    assert.equal(structuredEvents(relay.output.lines).some((event) => event.event === "auth_rejected"), false);
    assert.equal(structuredEvents(logs.lines).some((event) => event.event === "relay_auth_rejected"), false);
    assert.equal(Buffer.concat(relay.stderr).length, 0);
  } finally {
    await host.emit("session_shutdown");
    logs.restore();
    environment.restore();
  }
});

test("environment url substitutes the file url while the file secret authenticates", {
  timeout: 60_000,
  concurrency: false,
}, async (context) => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const root = await mkdtemp(join(tmpdir(), "pi-relay-connect-override-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const binary = join(root, "relay-server");
  const fileServerState = join(root, "file-server-state");
  const envServerState = join(root, "env-server-state");
  const extensionHome = join(root, "extension-home");
  const secretFile = join(envServerState, "relay.secret");
  execFileSync("go", ["build", "-o", binary, "./cmd/pi-messaging-relay-server"], {
    cwd: repositoryRoot,
    stdio: "pipe",
  });
  const decoy = await startRelay(binary, repositoryRoot, fileServerState, undefined);
  context.after(async () => {
    await stop(decoy.child);
    decoy.closeOutput();
  });
  await mkdir(envServerState, { recursive: true, mode: 0o700 });
  await writeFile(secretFile, SHARED_SECRET, { mode: 0o600 });
  const target = await startRelay(binary, repositoryRoot, envServerState, secretFile);
  context.after(async () => {
    await stop(target.child);
    target.closeOutput();
  });
  const environment = installIsolatedHome(extensionHome);
  const logs = captureStructuredErrors();
  const host = new FakePiHost();
  host.cwd = "/srv/override-acceptance";

  try {
    const decoyReady = await nextEvent(decoy.output, "server_ready");
    const targetReady = await nextEvent(target.output, "server_ready");
    assert.equal(targetReady.auth, "secret");
    await writeClientConfig(extensionHome, { url: `http://${String(decoyReady.address)}`, secret: SHARED_SECRET });
    process.env.PI_MESSAGING_RELAY_URL = `http://${String(targetReady.address)}`;

    const relayExtension = (await import(`../index.ts?connect-override=${Date.now()}`)).default;
    relayExtension(host.api as never);
    await host.emit("session_start", { type: "session_start", reason: "startup" });
    const accepted = await nextEvent(target.output, "auth_accepted", (event) => event.cwd === host.cwd);
    assert.match(String(accepted.route_id), UUID_V7);
    assert.equal(structuredEvents(decoy.output.lines).some((event) => event.event === "auth_accepted"), false);
    assert.equal(structuredEvents(logs.lines).some((event) => event.event === "relay_auth_rejected"), false);
    assert.equal([...target.output.lines, ...logs.lines].join("\n").includes(SHARED_SECRET), false);
  } finally {
    await host.emit("session_shutdown");
    logs.restore();
    environment.restore();
  }
});

test("wrong client secret receives the closed 401 and bounded not_authorized retries", {
  timeout: 60_000,
  concurrency: false,
}, async (context) => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const root = await mkdtemp(join(tmpdir(), "pi-relay-connect-wrong-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const binary = join(root, "relay-server");
  const serverState = join(root, "server-state");
  const extensionHome = join(root, "extension-home");
  const secretFile = join(serverState, "relay.secret");
  execFileSync("go", ["build", "-o", binary, "./cmd/pi-messaging-relay-server"], {
    cwd: repositoryRoot,
    stdio: "pipe",
  });
  await mkdir(serverState, { recursive: true, mode: 0o700 });
  await writeFile(secretFile, SHARED_SECRET, { mode: 0o600 });
  const relay = await startRelay(binary, repositoryRoot, serverState, secretFile);
  context.after(async () => {
    await stop(relay.child);
    relay.closeOutput();
  });
  const environment = installIsolatedHome(extensionHome);
  const logs = captureStructuredErrors();
  const host = new FakePiHost();
  host.cwd = "/srv/wrong-secret";

  try {
    const ready = await nextEvent(relay.output, "server_ready");
    assert.equal(ready.auth, "secret");
    await writeClientConfig(extensionHome, { url: `http://${String(ready.address)}`, secret: "wrong-secret" });

    const relayExtension = (await import(`../index.ts?connect-wrong=${Date.now()}`)).default;
    relayExtension(host.api as never);
    await host.emit("session_start", { type: "session_start", reason: "startup" });
    await waitUntil(
      () => structuredEvents(logs.lines).some((event) =>
        event.event === "relay_auth_rejected" && event.reason === "not_authorized"),
      "first not_authorized rejection",
    );
    await waitUntil(
      () => structuredEvents(logs.lines).filter((event) =>
        event.event === "relay_reconnect_scheduled" && event.reason === "not_authorized").length >= 1,
      "bounded not_authorized retry schedule",
    );
    const rejections: Record<string, unknown>[] = [];
    for (let drained = 0; drained < 40 && rejections.length === 0; drained += 1) {
      const next = await within(relay.output.iterator.next(), "waiting for server auth_rejected");
      if (next.done) break;
      relay.output.lines.push(next.value);
      const event = JSON.parse(next.value) as Record<string, unknown>;
      if (event.event === "auth_rejected" && event.reason === "not_authorized") rejections.push(event);
    }
    assert.equal(rejections.length >= 1, true);
    await assert.rejects(host.executeTool("list_peers", {}), /Relay is disconnected/);
    assert.equal(logs.lines.join("\n").includes("wrong-secret"), false);
    assert.equal(logs.lines.join("\n").includes(SHARED_SECRET), false);
  } finally {
    await host.emit("session_shutdown");
    logs.restore();
    environment.restore();
  }
});
