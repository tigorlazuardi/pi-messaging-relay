import { appendFile, mkdir, readFile } from "node:fs/promises";
import { basename } from "node:path";

// ponytail: fixed ~/.local/state/pi-messaging-relay/sessions and a 200-line
// /relay-logs tail; make configurable when an operator needs either knob.

/** One JSONL log file per persisted Pi session under the relay state dir.
 * Only the session file's basename is used, so traversal in the reported
 * path cannot escape the log directory. */
export function resolveSessionLogPath(
  environment: { PI_MESSAGING_RELAY_LOG_DIR?: string; XDG_STATE_HOME?: string; HOME?: string },
  homedir: string,
  sessionFile: string | undefined,
): string | undefined {
  if (!sessionFile) return undefined;
  const name = basename(sessionFile);
  if (!/^[\w.-]+\.jsonl$/.test(name)) return undefined;
  const base = environment.PI_MESSAGING_RELAY_LOG_DIR
    ?? joinPath(environment.XDG_STATE_HOME ?? joinPath(homedir, ".local", "state"), "pi-messaging-relay", "sessions");
  return joinPath(base, `${name}.log.jsonl`);
}

function joinPath(...segments: string[]): string {
  return segments.join("/").replace(/\/+/g, "/");
}

// One mkdir promise per target directory; appends chain after it. Weak
// synchronization overall: the emit path never awaits, each line is one
// plain O_APPEND write, and failures are swallowed. One session owns one
// file, so concurrent sessions never share a write target.
const directoryReady = new Map<string, Promise<void>>();

function ensureDirectory(directory: string): Promise<void> {
  let ready = directoryReady.get(directory);
  if (!ready) {
    ready = mkdir(directory, { recursive: true }).catch(() => undefined);
    directoryReady.set(directory, ready);
  }
  return ready;
}

/** Fire-and-forget append: no await in the emit path, errors swallowed. */
export function appendDiagnosticLine(path: string, line: string): void {
  void ensureDirectory(path.slice(0, path.lastIndexOf("/")))
    .then(() => appendFile(path, `${line}\n`, { encoding: "utf8", flag: "a" }))
    .catch(() => undefined);
}

/** Newest-last tail of at most maxLines entries; missing files read empty. */
export async function readSessionLogTail(path: string, maxLines: number): Promise<string[]> {
  let content: string;
  try {
    content = await readFile(path, "utf8");
  } catch {
    return [];
  }
  const lines = content.split("\n").filter((line) => line.length > 0);
  return lines.slice(Math.max(0, lines.length - maxLines));
}
