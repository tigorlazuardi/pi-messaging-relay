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

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

type ServerOutput = {
  iterator: AsyncIterator<string>;
  lines: string[];
};

type UpgradeResult = { status: string; body: string };

function captureStructuredErrors(): { lines: string[]; restore(): void } {
  const lines: string[] = [];
  const original = console.error;
  console.error = (...values: unknown[]) => lines.push(values.map(String).join(" "));
  return { lines, restore: () => (console.error = original) };
}

async function nextServerEvent(
  output: ServerOutput,
  expectedEvent: string,
  matches: (event: Record<string, unknown>) => boolean = () => true,
): Promise<Record<string, unknown>> {
  while (true) {
    const result = await output.iterator.next();
    if (result.done) throw new Error(`relay output closed before ${expectedEvent}`);
    output.lines.push(result.value);
    const event = JSON.parse(result.value) as Record<string, unknown>;
    if (event.event === expectedEvent && matches(event)) return event;
  }
}

function structuredEvents(lines: string[]): Record<string, unknown>[] {
  return lines.map((line) => JSON.parse(line) as Record<string, unknown>);
}

async function stop(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  child.kill("SIGTERM");
  const timer = setTimeout(() => child.kill("SIGKILL"), 5_000);
  await exited;
  clearTimeout(timer);
}

/** One raw upgrade attempt against the real HTTP boundary; resolves on first frame or close. */
function rawUpgrade(origin: string, authorization: string | undefined): Promise<UpgradeResult> {
  return fetch(`http://${origin}/v1/connect`, {
    headers: authorization === undefined ? {} : { Authorization: authorization },
  }).then(async (response) => ({
    status: String(response.status),
    body: await response.text(),
  }));
}

test("configured extension authenticates once per session lifecycle over the real WebSocket boundary", {
  timeout: 60_000,
  concurrency: false,
}, async (context) => {
  const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
  const root = await mkdtemp(join(tmpdir(), "pi-relay-session-auth-"));
  await chmod(root, 0o700);
  context.after(async () => rm(root, { recursive: true, force: true }));
  const binary = join(root, "relay-server");
  const serverState = join(root, "server-state");
  const extensionHome = join(root, "extension-home");
  const secretFile = await writeServerSecretFile(serverState);
  execFileSync("go", ["build", "-o", binary, "./cmd/pi-messaging-relay-server"], {
    cwd: repositoryRoot,
    stdio: "pipe",
  });

  const child = spawn(binary, [
    "--listen", "127.0.0.1:0",
    "--state-dir", serverState,
    "--secret-file", secretFile,
  ], { cwd: repositoryRoot, stdio: ["ignore", "pipe", "pipe"] });
  child.stderr.on("data", () => undefined);
  const stdout = createInterface({ input: child.stdout, crlfDelay: Infinity });
  const output: ServerOutput = { iterator: stdout[Symbol.asyncIterator](), lines: [] };
  context.after(async () => {
    await stop(child);
    stdout.close();
  });

  const environment = installIsolatedHome(extensionHome);
  const logs = captureStructuredErrors();
  const host = new FakePiHost();
  host.cwd = "/srv/auth-acceptance";
  let primaryError: unknown;

  try {
    const ready = await nextServerEvent(output, "server_ready");
    assert.equal(ready.auth, "secret");
    await writeClientConfig(extensionHome, {
      url: `http://${String(ready.address)}`,
      secret: SHARED_RELAY_SECRET,
    });

    const relayExtension = (await import(`../index.ts?session-auth=${Date.now()}`)).default;
    relayExtension(host.api as never);
    await host.emit("session_start", { type: "session_start", reason: "startup" });

    const accepted = await nextServerEvent(output, "auth_accepted");
    assert.equal(accepted.cwd, host.cwd);
    assert.match(String(accepted.route_id), UUID_V7);
    assert.equal(
      accepted.address,
      `${host.cwd}@${String(accepted.hostname)}#${String(accepted.route_id)}`,
    );
    // v2 establishment is unsigned: no challenge, signature, or key material fields exist.
    for (const event of structuredEvents(output.lines)) {
      assert.equal("client_public_key" in event || "nonce" in event || "signature" in event, false);
    }

    const routeID = String(accepted.route_id);
    const address = String(accepted.address);
    const extensionAuthEvents = structuredEvents(logs.lines).filter((event) =>
      event.event === "relay_auth_accepted" && event.route_id === routeID);
    assert.equal(extensionAuthEvents.length, 1);
    assert.equal(extensionAuthEvents[0].address, address);
    assert.equal(host.registrations.filter((entry) => entry.kind === "tool").length, 2);

    // Unauthorized raw clients receive the one closed 401 spelling on the real boundary.
    const missing = await rawUpgrade(String(ready.address), undefined);
    assert.deepEqual(
      { status: missing.status, body: missing.body },
      { status: "401", body: '{"error":"not_authorized","message":"Authentication is required"}' },
    );
    const wrongSecret = await rawUpgrade(String(ready.address), "Bearer wrong-secret");
    assert.equal(wrongSecret.status, "401");
    assert.equal(wrongSecret.body, '{"error":"not_authorized","message":"Authentication is required"}');
    for (const rejection of structuredEvents(output.lines)) {
      if (rejection.event === "auth_rejected") {
        assert.equal(rejection.reason, "not_authorized");
      }
    }

    // Graceful shutdown tears the authenticated session down exactly once.
    await host.emit("session_shutdown");
    const disconnected = await nextServerEvent(output, "session_disconnected");
    assert.equal(disconnected.address, address);
    assert.equal(structuredEvents(logs.lines).some((event) =>
      event.event === "relay_session_disconnected" && event.route_id === routeID), true);

    const allOutput = [...output.lines, ...logs.lines].join("\n");
    assert.equal(allOutput.includes(SHARED_RELAY_SECRET), false);
    for (const line of [...output.lines, ...logs.lines]) {
      const event = JSON.parse(line) as Record<string, unknown>;
      if ("secret" in event) assert.equal(event.secret, "<redacted>");
    }
  } finally {
    logs.restore();
    environment.restore();
    await host.emit("session_shutdown").catch(() => undefined);
    await stop(child);
  }
});
