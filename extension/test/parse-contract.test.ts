import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

// pi loads extension sources with an esbuild-based loader that is STRICT about
// duplicate named declarations — including type-only imports that TypeScript
// and the node test runner both accept. A duplicate import once shipped to
// main and disabled every session with this extension installed. These checks
// run the same parse path (esbuild transform) over every shipped source file
// so that declaration conflicts fail npm test instead of production loads.

function listSources(directory: string): string[] {
  const entries: string[] = [];
  for (const name of readdirSync(directory)) {
    if (name === "node_modules" || name === "test") continue;
    const entry = join(directory, name);
    if (statSync(entry).isDirectory()) entries.push(...listSources(entry));
    else if (entry.endsWith(".ts")) entries.push(entry);
  }
  return entries;
}

function transformSource(source: string): { imports: Map<string, string[]> } {
  // Minimal statement scanner: collect named import specifiers per module
  // specifier. esbuild (bun build) validates the syntax separately; this
  // scan catches duplicate named bindings across import statements, which
  // esbuild tolerates inside transform() but the pi jiti loader rejects.
  const imports = new Map<string, string[]>();
  const pattern =
    /import\s+(type\s+)?(\{[^}]*\}|[\w$]+|\*\s+as\s+[\w$]+|[\w$]+\s*,\s*\{[^}]*\})\s+from\s+["']([^"']+)["']/g;
  for (const match of source.matchAll(pattern)) {
    const clause = match[2] ?? "";
    const specifier = match[3];
    const names = imports.get(specifier) ?? [];
    const named = clause.match(/\{([^}]*)\}/);
    if (named) {
      for (const raw of named[1].split(",")) {
        // "type X" and "inline type X as Y" bind X; strip the type marker
        // before matching so type-only duplicates are still counted.
        const binding = raw.trim().replace(/^type\s+/, "");
        const specifierMatch = binding.match(/^([\w$]+)(?:\s+as\s+([\w$]+))?$/);
        if (specifierMatch) names.push(specifierMatch[2] ?? specifierMatch[1]);
      }
    }
    imports.set(specifier, names);
  }
  return { imports };
}

describe("extension source parse contract", () => {
  const sources = listSources(new URL("..", import.meta.url).pathname);

  it("discovers shipped TypeScript sources", () => {
    assert.ok(sources.some((path) => path.endsWith("index.ts")));
    assert.ok(sources.length >= 10);
  });

  it("never declares the same import binding twice from one module", () => {
    for (const path of sources) {
      const { imports } = transformSource(readFileSync(path, "utf8"));
      for (const [specifier, names] of imports) {
        for (const name of names) {
          // The same named binding may appear once; duplicates across
          // repeated import statements from the same module are fatal in
          // the pi loader even when every occurrence is type-only.
          const occurrences = names.filter((candidate) => candidate === name).length;
          assert.ok(occurrences <= 1, `${path}: duplicate import binding "${name}" from "${specifier}"`);
        }
      }
    }
  });

  it("parses every source with esbuild strict TS transform", async () => {
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const run = promisify(execFile);
    for (const path of sources) {
      // bun's bundler enforces duplicate-declaration ParseErrors on TS the
      // same way the pi loader's esbuild pass does.
      await run("bun", ["build", path, "--outdir", "/tmp/pi-relay-parse-guard", "--external", "*"], {
        cwd: new URL("..", import.meta.url).pathname,
      });
    }
  });
});
