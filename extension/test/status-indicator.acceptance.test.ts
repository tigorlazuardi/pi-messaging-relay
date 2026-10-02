import assert from "node:assert/strict";
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import test from "node:test";

import { RELAY_STATUS_KEY } from "../internal/connection-status.ts";
import { clientConfigurationPath } from "../internal/client-config.ts";
import { FakePiHost } from "./fake-pi-host.ts";
import { installIsolatedHome, SHARED_RELAY_SECRET } from "./secret-relay.ts";

const TEST_TIMEOUT_MS = 15_000;
const SHARED_SECRET = SHARED_RELAY_SECRET;

type Output = { iterator: AsyncIterator<string>; lines: string[] };

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

let relayBinaryPath: string | undefined;
let relayBinaryPromise: Promise<string> | undefined;

/** Build the staged Go server once per test process for the real harness. */
function relayBinary(): Promise<string> {
  relayBinaryPromise ??= (async () => {
    const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
    const root = await mkdtemp(join(tmpdir(), "pi-relay-status-binary-"));
    const binary = join(root, "relay-server");
    execFileSync("go", ["build", "-o", binary, "./cmd/pi-messaging-relay-server"], {
      cwd: repositoryRoot,
      stdio: "pipe",
    });
    relayBinaryPath = binary;
    return binary;
  })();
  return relayBinaryPromise;
}

async function startRelay(
  binary: string,
  repositoryRoot: string,
  stateDirectory: string,
  secretFile: string | undefined,
): Promise<{ child: ChildProcessWithoutNullStreams; output: Output }> {
  const args = ["--listen", "127.0.0.1:0", "--state-dir", stateDirectory];
  if (secretFile !== undefined) args.push("--secret-file", secretFile);
  const child = spawn(binary, args, { cwd: repositoryRoot, stdio: ["ignore", "pipe", "pipe"] });
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  return {
    child,
    output: { iterator: lines[Symbol.asyncIterator](), lines: [] },
  };
}

async function prepareHome(context: { after(callback: () => Promise<void>): void }, prefix: string): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), prefix));
  context.after(async () => rm(home, { recursive: true, force: true }));
  await chmod(home, 0o700);
  return home;
}

async function writeClientConfig(home: string, configuration: { url: string; secret?: string }): Promise<void> {
  await mkdir(join(home, ".config", "pi"), { recursive: true, mode: 0o700 });
  await writeFile(clientConfigurationPath(home), JSON.stringify(configuration), { mode: 0o600 });
}

/** Latest rendered indicator text for the relay status key, or undefined when nothing renders. */
function renderedIndicator(host: FakePiHost): string | undefined {
  return host.statusFor(RELAY_STATUS_KEY);
}

test("no configured endpoint renders no indicator at all", { concurrency: false }, async (context) => {
  const home = await prepareHome(context, "pi-relay-status-unconfigured-");
  const environment = installIsolatedHome(home);
  const logs = captureStructuredErrors();
  const host = new FakePiHost();

  try {
    const relayExtension = (await import("../index.ts")).default;
    relayExtension(host.api as never);
    await host.emit("session_start", { type: "session_start", reason: "startup" });
  } finally {
    logs.restore();
    environment.restore();
    await host.emit("session_shutdown");
  }

  // Only clearing calls may occur; nothing is ever rendered for the key.
  assert.deepEqual(
    host.statusMessages.filter((entry) => entry.key === RELAY_STATUS_KEY && entry.text !== undefined),
    [],
  );
});

test("connected session renders the green relay indicator and a disconnect turns it red", {
  timeout: 60_000,
  concurrency: false,
}, async (context) => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const binary = await relayBinary();
  const root = await mkdtemp(join(tmpdir(), "pi-relay-status-connected-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const serverState = join(root, "server-state");
  const extensionHome = join(root, "extension-home");
  const secretFile = join(serverState, "relay.secret");
  await mkdir(serverState, { recursive: true, mode: 0o700 });
  await writeFile(secretFile, SHARED_SECRET, { mode: 0o600 });

  const relay = await startRelay(binary, repositoryRoot, serverState, secretFile);
  context.after(async () => {
    await stop(relay.child);
  });
  const environment = installIsolatedHome(extensionHome);
  const logs = captureStructuredErrors();
  const host = new FakePiHost();

  try {
    const ready = await nextEvent(relay.output, "server_ready");
    const origin = String(ready.address);
    await writeClientConfig(extensionHome, { url: `http://${origin}`, secret: SHARED_SECRET });

    const relayExtension = (await import("../index.ts")).default;
    relayExtension(host.api as never);
    await host.emit("session_start", { type: "session_start", reason: "startup" });

    // Connecting is red before the welcome completes, then the accepted
    // session flips the same indicator green.
    await nextEvent(relay.output, "auth_accepted");
    assert.equal(renderedIndicator(host), "success:● relay");

    // Killing the server disconnects the socket; the indicator goes red again.
    await stop(relay.child);
    await waitUntil(
      () => renderedIndicator(host) === "error:● relay",
      "waiting for red indicator after disconnect",
    );
  } finally {
    logs.restore();
    environment.restore();
    await host.emit("session_shutdown");
  }
});

test("rejected credentials render the red relay indicator", { timeout: 60_000, concurrency: false }, async (context) => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const binary = await relayBinary();
  const root = await mkdtemp(join(tmpdir(), "pi-relay-status-auth-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  const serverState = join(root, "server-state");
  const extensionHome = join(root, "extension-home");
  const secretFile = join(serverState, "relay.secret");
  await mkdir(serverState, { recursive: true, mode: 0o700 });
  await writeFile(secretFile, SHARED_SECRET, { mode: 0o600 });

  const relay = await startRelay(binary, repositoryRoot, serverState, secretFile);
  context.after(async () => {
    await stop(relay.child);
  });
  const environment = installIsolatedHome(extensionHome);
  const logs = captureStructuredErrors();
  const host = new FakePiHost();

  try {
    const ready = await nextEvent(relay.output, "server_ready");
    const origin = String(ready.address);
    await writeClientConfig(extensionHome, { url: `http://${origin}`, secret: "wrong-secret" });

    const relayExtension = (await import("../index.ts")).default;
    relayExtension(host.api as never);
    await host.emit("session_start", { type: "session_start", reason: "startup" });

    // Connect is fire-and-forget; wait for the rejection to land.
    await waitUntil(
      () => structuredEvents(logs.lines).some(
        (event) => event.event === "relay_auth_rejected" && event.reason === "not_authorized"),
      "waiting for not_authorized rejection",
    );
    await waitUntil(
      () => renderedIndicator(host) === "error:● relay",
      "waiting for red indicator after auth rejection",
    );
  } finally {
    logs.restore();
    environment.restore();
    await host.emit("session_shutdown");
  }
});

test("a rejected configuration file renders the red relay indicator", { concurrency: false }, async (context) => {
  const home = await prepareHome(context, "pi-relay-status-config-");
  await mkdir(join(home, ".config", "pi"), { recursive: true, mode: 0o700 });
  await writeFile(
    clientConfigurationPath(home),
    JSON.stringify({ url: "http://127.0.0.1:8080", extra: true }),
    { mode: 0o600 },
  );
  const environment = installIsolatedHome(home);
  const logs = captureStructuredErrors();
  const host = new FakePiHost();

  try {
    const relayExtension = (await import("../index.ts")).default;
    relayExtension(host.api as never);
    await host.emit("session_start", { type: "session_start", reason: "startup" });

    // Connect is fire-and-forget; wait for the closed diagnostic to land.
    await waitUntil(
      () => structuredEvents(logs.lines).some((event) => event.event === "relay_config_rejected"),
      "waiting for relay_config_rejected",
    );
    const rejected = structuredEvents(logs.lines).find((event) => event.event === "relay_config_rejected");
    assert.ok(rejected);
    assert.equal(renderedIndicator(host), "error:● relay");

    await host.emit("session_shutdown");
    assert.equal(renderedIndicator(host), undefined);
  } finally {
    logs.restore();
    environment.restore();
  }
});

function structuredEvents(lines: string[]): Record<string, unknown>[] {
  return lines.map((line) => JSON.parse(line) as Record<string, unknown>);
}
