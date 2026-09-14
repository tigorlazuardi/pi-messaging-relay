import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import test from "node:test";

const checker = new URL("./check-internal-links.mjs", import.meta.url);
const siteURL = "https://example.test/pi-messaging-relay/";

async function runChecker(pages) {
  const fixture = await mkdtemp(join(tmpdir(), "pi-relay-link-check-"));
  try {
    for (const [path, html] of Object.entries(pages)) {
      const file = join(fixture, path);
      await mkdir(dirname(file), { recursive: true });
      await writeFile(file, html, { encoding: "utf8", mode: 0o600 });
    }
    return spawnSync(process.execPath, [checker.pathname, fixture, siteURL], {
      encoding: "utf8",
      timeout: 10_000,
    });
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
}

test("rejects a same-origin root URL outside the configured site base", async () => {
  const result = await runChecker({
    "index.html": '<a href="/outside/">Outside</a>',
    "outside/index.html": "<h1>Locally present but not deployed here</h1>",
  });

  assert.equal(result.status, 1);
  assert.equal(result.signal, null);
  assert.equal(
    result.stderr,
    "Internal link check failed (1):\n" +
      '- index.html: page /outside/ is outside site base /pi-messaging-relay from "/outside/"\n',
  );
});

test("checks href after a quoted attribute containing a greater-than sign", async () => {
  const result = await runChecker({
    "index.html": '<a title="left > right" href="missing/">Missing</a>',
  });

  assert.equal(result.status, 1);
  assert.equal(result.signal, null);
  assert.equal(
    result.stderr,
    "Internal link check failed (1):\n" +
      '- index.html: missing page /pi-messaging-relay/missing/ from "missing/"\n',
  );
});

test("reports a missing generated page with a stable diagnostic", async () => {
  const result = await runChecker({
    "guide/index.html": '<a href="../absent/">Absent</a>',
  });

  assert.equal(result.status, 1);
  assert.equal(result.signal, null);
  assert.equal(
    result.stderr,
    "Internal link check failed (1):\n" +
      '- guide/index.html: missing page /pi-messaging-relay/absent/ from "../absent/"\n',
  );
});

test("reports a missing fragment on a base-prefixed page with a stable diagnostic", async () => {
  const result = await runChecker({
    "index.html": '<a href="/pi-messaging-relay/target/#absent">Absent section</a>',
    "target/index.html": '<h2 id="present">Present</h2>',
  });

  assert.equal(result.status, 1);
  assert.equal(result.signal, null);
  assert.equal(
    result.stderr,
    "Internal link check failed (1):\n" +
      '- index.html: missing fragment #absent in target/index.html from "/pi-messaging-relay/target/#absent"\n',
  );
});
