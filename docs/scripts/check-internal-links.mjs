import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import process from "node:process";

const outputRoot = resolve(process.argv[2] ?? "dist");
const siteURL = new URL(process.argv[3] ?? "https://tigorlazuardi.github.io/pi-messaging-relay/");
const siteBase = siteURL.pathname.replace(/\/$/, "");

async function walk(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(path));
    else if (entry.isFile() && entry.name.endsWith(".html")) files.push(path);
  }
  return files;
}

function decodeHTML(value) {
  return value.replace(/&(#x[0-9a-f]+|#\d+|amp|quot|apos|lt|gt);/gi, (entity, code) => {
    const named = { amp: "&", quot: '"', apos: "'", lt: "<", gt: ">" };
    if (code[0] !== "#") return named[code.toLowerCase()];
    const radix = code[1].toLowerCase() === "x" ? 16 : 10;
    const digits = radix === 16 ? code.slice(2) : code.slice(1);
    return String.fromCodePoint(Number.parseInt(digits, radix));
  });
}

function anchorHrefs(html) {
  const hrefs = [];
  for (let cursor = 0; cursor < html.length;) {
    const tagStart = html.indexOf("<", cursor);
    if (tagStart === -1) break;
    cursor = tagStart + 1;
    if (html[cursor]?.toLowerCase() !== "a" || !/[\s/>]/.test(html[cursor + 1] ?? "")) continue;

    let tagEnd = cursor + 1;
    let quote;
    for (; tagEnd < html.length; tagEnd += 1) {
      const character = html[tagEnd];
      if (quote) {
        if (character === quote) quote = undefined;
      } else if (character === '"' || character === "'") {
        quote = character;
      } else if (character === ">") {
        break;
      }
    }
    if (tagEnd === html.length) break;

    const attributes = html.slice(cursor + 1, tagEnd);
    for (let index = 0; index < attributes.length;) {
      while (/\s|\//.test(attributes[index] ?? "")) index += 1;
      const nameStart = index;
      while (index < attributes.length && !/[\s=/>]/.test(attributes[index])) index += 1;
      const name = attributes.slice(nameStart, index).toLowerCase();
      while (/\s/.test(attributes[index] ?? "")) index += 1;
      if (attributes[index] !== "=") continue;
      index += 1;
      while (/\s/.test(attributes[index] ?? "")) index += 1;

      let value;
      const valueQuote = attributes[index];
      if (valueQuote === '"' || valueQuote === "'") {
        const valueStart = ++index;
        while (index < attributes.length && attributes[index] !== valueQuote) index += 1;
        value = attributes.slice(valueStart, index);
        if (index < attributes.length) index += 1;
      } else {
        const valueStart = index;
        while (index < attributes.length && !/[\s>]/.test(attributes[index])) index += 1;
        value = attributes.slice(valueStart, index);
      }
      if (name === "href") hrefs.push(decodeHTML(value));
    }
    cursor = tagEnd + 1;
  }
  return hrefs;
}

function pageURL(file) {
  const path = relative(outputRoot, file).split(sep).join("/");
  if (path === "index.html") return "/";
  if (path.endsWith("/index.html")) return `/${path.slice(0, -"index.html".length)}`;
  return `/${path}`;
}

function decodeURL(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return undefined;
  }
}

function isWithinSiteBase(pathname) {
  return !siteBase || pathname === siteBase || pathname.startsWith(`${siteBase}/`);
}

async function pageFile(pathname) {
  let path = decodeURL(pathname);
  if (path === undefined) return undefined;
  if (siteBase && (path === siteBase || path.startsWith(`${siteBase}/`))) {
    path = path.slice(siteBase.length) || "/";
  }
  const relativePath = path.replace(/^\/+/, "");
  const candidates = path.endsWith(".html")
    ? [join(outputRoot, relativePath)]
    : [join(outputRoot, relativePath, "index.html"), join(outputRoot, `${relativePath}.html`)];
  for (const candidate of candidates) {
    if (!candidate.startsWith(`${outputRoot}${sep}`) && candidate !== join(outputRoot, "index.html")) continue;
    try {
      if ((await stat(candidate)).isFile()) return candidate;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
  return undefined;
}

const htmlFiles = await walk(outputRoot);
const documents = new Map();
for (const file of htmlFiles) {
  const html = await readFile(file, "utf8");
  const ids = new Set([...html.matchAll(/\sid=(['"])(.*?)\1/gi)].map((match) => decodeHTML(match[2])));
  documents.set(file, { hrefs: anchorHrefs(html), ids });
}

const failures = [];
for (const [sourceFile, document] of documents) {
  const source = new URL(`${siteURL.origin}${siteBase}${pageURL(sourceFile)}`);
  for (const href of document.hrefs) {
    if (!href || /^(mailto:|tel:|javascript:|data:)/i.test(href)) continue;
    let targetURL;
    try {
      targetURL = new URL(href, source);
    } catch {
      failures.push(`${relative(outputRoot, sourceFile)}: invalid href ${JSON.stringify(href)}`);
      continue;
    }
    if (targetURL.origin !== siteURL.origin) continue;
    if (!isWithinSiteBase(targetURL.pathname)) {
      failures.push(`${relative(outputRoot, sourceFile)}: page ${targetURL.pathname} is outside site base ${siteBase || "/"} from ${JSON.stringify(href)}`);
      continue;
    }
    const targetFile = await pageFile(targetURL.pathname);
    if (!targetFile) {
      failures.push(`${relative(outputRoot, sourceFile)}: missing page ${targetURL.pathname} from ${JSON.stringify(href)}`);
      continue;
    }
    if (targetURL.hash) {
      const fragment = decodeURL(targetURL.hash.slice(1));
      const target = documents.get(targetFile);
      if (fragment === undefined || !target?.ids.has(fragment)) {
        failures.push(`${relative(outputRoot, sourceFile)}: missing fragment ${targetURL.hash} in ${relative(outputRoot, targetFile)} from ${JSON.stringify(href)}`);
      }
    }
  }
}

if (failures.length > 0) {
  console.error(`Internal link check failed (${failures.length}):`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log(`Internal link check passed (${htmlFiles.length} HTML pages).`);
}
