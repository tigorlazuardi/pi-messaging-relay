import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { homedir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  ClientConfigurationError,
  clientConfigurationPath,
  ENDPOINT_ENV,
  loadClientConfiguration,
  MAX_SECRET_BYTES,
  parseClientConfigurationText,
  parseLoopbackOrigin,
} from "../internal/client-config.ts";

const LOOPBACK_URL = "http://127.0.0.1:8080";

function captureEnvironment(): { restore(): void } {
  const previousEndpoint = process.env[ENDPOINT_ENV];
  const previousXDG = process.env.XDG_CONFIG_HOME;
  delete process.env[ENDPOINT_ENV];
  delete process.env.XDG_CONFIG_HOME;
  return {
    restore: () => {
      if (previousEndpoint === undefined) delete process.env[ENDPOINT_ENV];
      else process.env[ENDPOINT_ENV] = previousEndpoint;
      if (previousXDG === undefined) delete process.env.XDG_CONFIG_HOME;
      else process.env.XDG_CONFIG_HOME = previousXDG;
    },
  };
}

async function createHome(context: { after(callback: () => Promise<void>): void }): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), "pi-relay-client-config-"));
  context.after(async () => rm(home, { recursive: true, force: true }));
  return home;
}

async function writeConfig(home: string, text: string | Buffer, mode = 0o600): Promise<string> {
  await mkdir(join(home, ".config", "pi"), { recursive: true, mode: 0o700 });
  const path = clientConfigurationPath(home);
  await writeFile(path, text, { mode: 0o600 });
  await chmod(path, mode);
  return path;
}

async function expectConfigurationError(
  home: string,
  reason: string,
  action: string,
): Promise<void> {
  await assert.rejects(
    loadClientConfiguration(home),
    (error: unknown) => error instanceof ClientConfigurationError && error.reason === reason,
    action,
  );
}

test("valid url-only configuration loads without a secret", { concurrency: false }, async (context) => {
  const environment = captureEnvironment();
  const home = await createHome(context);
  try {
    await writeConfig(home, JSON.stringify({ url: LOOPBACK_URL }));
    const configuration = await loadClientConfiguration(home);
    assert.deepEqual(
      { href: configuration?.endpoint.href, secret: configuration?.secret },
      { href: `${LOOPBACK_URL}/`, secret: undefined },
    );
  } finally {
    environment.restore();
  }
});

test("valid secret is retained verbatim without trimming", { concurrency: false }, async (context) => {
  const environment = captureEnvironment();
  const home = await createHome(context);
  try {
    const secret = " padded-secret\t";
    await writeConfig(home, JSON.stringify({ url: LOOPBACK_URL, secret }));
    const configuration = await loadClientConfiguration(home);
    assert.equal(configuration?.secret, secret);
  } finally {
    environment.restore();
  }
});

test("secret boundaries are 1 through 512 UTF-8 bytes", { concurrency: false }, async (context) => {
  const environment = captureEnvironment();
  const home = await createHome(context);
  try {
    const maximum = "é".repeat(MAX_SECRET_BYTES / 2);
    assert.equal(Buffer.byteLength(maximum, "utf8"), MAX_SECRET_BYTES);
    await writeConfig(home, JSON.stringify({ url: LOOPBACK_URL, secret: maximum }));
    assert.equal((await loadClientConfiguration(home))?.secret, maximum);
  } finally {
    environment.restore();
  }

  for (const [name, secret] of [
    ["empty secret", ""],
    ["513-byte secret", "x".repeat(MAX_SECRET_BYTES + 1)],
    ["513-byte multibyte secret", "é".repeat(Math.floor(MAX_SECRET_BYTES / 2) + 1)],
  ] as const) {
    assert.throws(
      () => parseClientConfigurationText(JSON.stringify({ url: LOOPBACK_URL, secret })),
      (error: unknown) => error instanceof ClientConfigurationError && error.reason === "secret_invalid",
      name,
    );
  }
});

for (const [name, text] of [
  ["missing url", JSON.stringify({ secret: "s" })],
  ["unknown field", JSON.stringify({ url: LOOPBACK_URL, secret: "s", extra: true })],
  ["duplicate url keys", '{"url":"http://127.0.0.1:8080","url":"http://127.0.0.1:9090"}'],
  ["wrong url type", JSON.stringify({ url: 5 })],
  ["wrong secret type", JSON.stringify({ url: LOOPBACK_URL, secret: 5 })],
  ["non-string member", '{"url":"http://127.0.0.1:8080","secret":null}'],
  ["trailing JSON", '{"url":"http://127.0.0.1:8080"} {"url":"http://127.0.0.1:9090"}'],
  ["trailing scalar", '{"url":"http://127.0.0.1:8080"} 5'],
  ["malformed JSON", '{"url":'],
  ["top-level array", JSON.stringify([LOOPBACK_URL])],
  ["empty file", ""],
] as const) {
  test(`configuration text rejects ${name}`, () => {
    assert.throws(
      () => parseClientConfigurationText(text),
      (error: unknown) => error instanceof ClientConfigurationError && error.reason === "config_invalid",
      name,
    );
  });
}

for (const [name, value] of [
  ["non-http scheme", "ws://127.0.0.1:8080"],
  ["credentials", "http://user:pass@127.0.0.1:8080"],
  ["credentials on https", "https://user:pass@relay.example.com"],
  ["path", "http://127.0.0.1:8080/v1"],
  ["path on https", "https://relay.example.com/v1"],
  ["query string", "http://127.0.0.1:8080?x=1"],
  ["fragment", "http://127.0.0.1:8080#f"],
  ["external hostname over plain http", "http://relay.example.com"],
  ["external ipv4 over plain http", "http://10.0.0.1"],
  ["private ipv4 over plain http", "http://192.168.1.10"],
  ["ipv6 non-loopback", "http://[::1:1]"],
  ["not a url", "localhost:8080"],
] as const) {
  test(`loopback origin rejects ${name}`, () => {
    assert.throws(
      () => parseLoopbackOrigin(value),
      (error: unknown) => error instanceof ClientConfigurationError && error.reason === "url_invalid",
      name,
    );
  });
}

test("loopback origin accepts 127.0.0.1 and ::1 http forms", () => {
  assert.equal(parseLoopbackOrigin("http://127.0.0.1:8080").href, "http://127.0.0.1:8080/");
  assert.equal(parseLoopbackOrigin("http://127.5.6.7:1").hostname, "127.5.6.7");
  assert.equal(parseLoopbackOrigin("http://[::1]:9000").hostname, "[::1]");
});

test("https origins are accepted to any host including LAN addresses", () => {
  assert.equal(parseLoopbackOrigin("https://pi-relay.tigor.web.id").href, "https://pi-relay.tigor.web.id/");
  assert.equal(parseLoopbackOrigin("https://10.0.0.1:8443").hostname, "10.0.0.1");
  assert.equal(parseLoopbackOrigin("https://192.168.1.10").hostname, "192.168.1.10");
  assert.equal(parseLoopbackOrigin("https://[fd7a:115c:a1e0::1]").hostname, "[fd7a:115c:a1e0::1]");
});

test("absent file without environment override stays disconnected", { concurrency: false }, async (context) => {
  const environment = captureEnvironment();
  const home = await createHome(context);
  try {
    assert.equal(await loadClientConfiguration(home), undefined);
  } finally {
    environment.restore();
  }
});

test("absent file with environment override connects to the environment url only", { concurrency: false }, async (context) => {
  const environment = captureEnvironment();
  const home = await createHome(context);
  try {
    process.env[ENDPOINT_ENV] = "http://127.0.0.1:9999";
    const configuration = await loadClientConfiguration(home);
    assert.deepEqual(
      { href: configuration?.endpoint.href, secret: configuration?.secret },
      { href: "http://127.0.0.1:9999/", secret: undefined },
    );
  } finally {
    environment.restore();
  }
});

test("environment url substitutes the file url while the file secret remains", { concurrency: false }, async (context) => {
  const environment = captureEnvironment();
  const home = await createHome(context);
  try {
    await writeConfig(home, JSON.stringify({ url: LOOPBACK_URL, secret: "file-secret" }));
    process.env[ENDPOINT_ENV] = "http://127.0.0.1:9999";
    const configuration = await loadClientConfiguration(home);
    assert.deepEqual(
      { href: configuration?.endpoint.href, secret: configuration?.secret },
      { href: "http://127.0.0.1:9999/", secret: "file-secret" },
    );
  } finally {
    environment.restore();
  }
});

test("empty environment value is treated as unset", { concurrency: false }, async (context) => {
  const environment = captureEnvironment();
  const home = await createHome(context);
  try {
    await writeConfig(home, JSON.stringify({ url: LOOPBACK_URL }));
    process.env[ENDPOINT_ENV] = "";
    const configuration = await loadClientConfiguration(home);
    assert.equal(configuration?.endpoint.href, `${LOOPBACK_URL}/`);
  } finally {
    environment.restore();
  }
});

test("invalid environment url fails closed even with a valid file", { concurrency: false }, async (context) => {
  const environment = captureEnvironment();
  const home = await createHome(context);
  try {
    await writeConfig(home, JSON.stringify({ url: LOOPBACK_URL, secret: "file-secret" }));
    process.env[ENDPOINT_ENV] = "http://relay.example.com";
    await assert.rejects(
      loadClientConfiguration(home),
      (error: unknown) => error instanceof ClientConfigurationError && error.reason === "url_invalid",
    );
  } finally {
    environment.restore();
  }
});

for (const mode of [0o644, 0o640, 0o604, 0o600 | 0o100, 0o700, 0o400]) {
  test(`configuration mode ${mode.toString(8)} fails closed`, { concurrency: false }, async (context) => {
    const environment = captureEnvironment();
    const home = await createHome(context);
    try {
      await writeConfig(home, JSON.stringify({ url: LOOPBACK_URL, secret: "s" }), mode);
      await expectConfigurationError(home, "unsafe_config_permissions", `mode ${mode.toString(8)}`);
    } finally {
      environment.restore();
    }
  });
}

test("configuration symlink fails closed", { concurrency: false }, async (context) => {
  const environment = captureEnvironment();
  const home = await createHome(context);
  try {
    const target = join(home, "real-config.json");
    await writeFile(target, JSON.stringify({ url: LOOPBACK_URL, secret: "s" }), { mode: 0o600 });
    await mkdir(join(home, ".config", "pi"), { recursive: true, mode: 0o700 });
    await symlink(target, clientConfigurationPath(home));
    await expectConfigurationError(home, "unsafe_config_symlink", "symlinked configuration");
  } finally {
    environment.restore();
  }
});

test("configuration path holding a directory fails closed", { concurrency: false }, async (context) => {
  const environment = captureEnvironment();
  const home = await createHome(context);
  try {
    await mkdir(clientConfigurationPath(home), { recursive: true, mode: 0o700 });
    await expectConfigurationError(home, "unsafe_config_file", "directory at configuration path");
  } finally {
    environment.restore();
  }
});

test("oversize configuration fails closed while exactly 4096 bytes still loads", { concurrency: false }, async (context) => {
  const environment = captureEnvironment();
  const home = await createHome(context);
  try {
    const base = JSON.stringify({ url: LOOPBACK_URL, secret: "s" });
    const padded = base + " ".repeat(4_096 - Buffer.byteLength(base, "utf8"));
    assert.equal(Buffer.byteLength(padded, "utf8"), 4_096);
    await writeConfig(home, padded);
    const configuration = await loadClientConfiguration(home);
    assert.equal(configuration?.secret, "s");

    await writeConfig(home, `${padded} `, 0o600);
    await expectConfigurationError(home, "config_too_large", "4097-byte configuration");
  } finally {
    environment.restore();
  }
});

test("configuration with invalid UTF-8 fails closed", { concurrency: false }, async (context) => {
  const environment = captureEnvironment();
  const home = await createHome(context);
  try {
    const prefix = Buffer.from('{"url":"http://127.0.0.1:8080","secret":"', "utf8");
    const suffix = Buffer.from('"}', "utf8");
    await writeConfig(home, Buffer.concat([prefix, Buffer.from([0xc3, 0x28]), suffix]));
    await expectConfigurationError(home, "config_invalid", "invalid UTF-8 configuration");
  } finally {
    environment.restore();
  }
});

test("XDG_CONFIG_HOME is not honored", { concurrency: false }, async (context) => {
  const environment = captureEnvironment();
  const home = await createHome(context);
  const decoy = await mkdtemp(join(tmpdir(), "pi-relay-client-config-xdg-"));
  context.after(async () => rm(decoy, { recursive: true, force: true }));
  try {
    await mkdir(join(decoy, "pi"), { recursive: true, mode: 0o700 });
    await writeFile(
      join(decoy, "pi", "pi-messaging-relay.json"),
      JSON.stringify({ url: "http://127.0.0.1:6666", secret: "decoy" }),
      { mode: 0o600 },
    );
    process.env.XDG_CONFIG_HOME = decoy;
    await writeConfig(home, JSON.stringify({ url: LOOPBACK_URL, secret: "home-secret" }));
    const configuration = await loadClientConfiguration(home);
    assert.deepEqual(
      { href: configuration?.endpoint.href, secret: configuration?.secret },
      { href: `${LOOPBACK_URL}/`, secret: "home-secret" },
    );
  } finally {
    environment.restore();
  }
});

test("configuration path is fixed under the current user home", () => {
  assert.equal(
    clientConfigurationPath("/home/example"),
    join("/home/example", ".config", "pi", "pi-messaging-relay.json"),
  );
  assert.equal(clientConfigurationPath(), join(homedir(), ".config", "pi", "pi-messaging-relay.json"));
});
