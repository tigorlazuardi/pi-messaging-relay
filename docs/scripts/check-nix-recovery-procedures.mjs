import { readFile } from "node:fs/promises";
import process from "node:process";

const sourcePath = process.argv[2] ?? "src/content/docs/user/nix-deployment.mdx";
const source = await readFile(sourcePath, "utf8");

function headingSection(level, heading) {
  const marker = `${level} ${heading}`;
  const start = source.indexOf(marker);
  if (start === -1) return "";
  const nextHeading = new RegExp(`^#{1,${level.length}} `, "m").exec(source.slice(start + marker.length));
  const end = nextHeading ? start + marker.length + nextHeading.index : undefined;
  return source.slice(start, end);
}

function section(heading) {
  return headingSection("###", heading);
}

function tab(body, label) {
  const match = new RegExp(`<TabItem label="${label}">([\\s\\S]*?)</TabItem>`).exec(body);
  return match ? match[1] : "";
}

function bashFence(body) {
  const match = /^[ \t]*```bash[ \t]*\r?\n([\s\S]*?)^[ \t]*```[ \t]*$/m.exec(body);
  if (!match) return "";
  return match[1]
    .replace(/\\\r?\n[ \t]*/g, " ")
    .replace(/\|[ \t]*\r?\n[ \t]*/g, "| ");
}

function hasExecutableExit(block) {
  let lexical = "";
  let quote;
  let comment = false;

  for (let index = 0; index < block.length; index += 1) {
    const character = block[index];
    if (comment) {
      if (character === "\n") {
        comment = false;
        lexical += character;
      } else {
        lexical += " ";
      }
      continue;
    }
    if (quote) {
      if (character === quote) quote = undefined;
      else if (quote === '"' && character === "\\") index += 1;
      lexical += " ";
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      lexical += " ";
      continue;
    }
    if (character === "#" && (index === 0 || /[\s;|&(){}]/.test(block[index - 1]))) {
      comment = true;
      lexical += " ";
      continue;
    }
    if (character === "\\") {
      lexical += " ";
      index += 1;
      lexical += " ";
      continue;
    }
    lexical += character;
  }

  if (quote) return false;
  return lexical.split(/[;\n]/).some((command) => /^exit[ \t]+1$/.test(command.trim()));
}

function failClosedAt(body, command) {
  const match = new RegExp(`^[ \\t]*${command}[ \\t]*\\|\\|[ \\t]*\\{([^}]*)\\}`, "m").exec(body);
  return match && hasExecutableExit(match[1]) ? { index: match.index, text: match[0] } : undefined;
}

function matchAt(body, pattern) {
  const match = pattern.exec(body);
  return match ? { index: match.index, text: match[0] } : undefined;
}

const scopes = [
  {
    name: "system",
    body: section("System service recovery"),
    cursorCommand: /recovery_cursor="\$\(sudo journalctl -u pi-messaging-relay\.service -n 0 --show-cursor\)"/,
    cursorGate: 'recovery_cursor="\\$\\(sudo journalctl -u pi-messaging-relay\\.service -n 0 --show-cursor\\)"',
    activation: "sudo nixos-rebuild switch\\b[^\\n]*?",
    active: "sudo systemctl is-active pi-messaging-relay\\.service[ \\t]*>/dev/null",
    watcher: /^[ \t]*sudo timeout --signal=TERM 30s[ \t]+journalctl -u pi-messaging-relay\.service -o cat\b[^\n]*/m,
    watcherBound: /^[ \t]*sudo timeout --signal=TERM 30s[ \t]+journalctl -u pi-messaging-relay\.service -o cat[ \t]+--after-cursor="\$recovery_cursor"/,
  },
  {
    name: "user",
    body: section("User service recovery"),
    cursorCommand: /recovery_cursor="\$\(journalctl --user -u pi-messaging-relay\.service -n 0 --show-cursor\)"/,
    cursorGate: 'recovery_cursor="\\$\\(journalctl --user -u pi-messaging-relay\\.service -n 0 --show-cursor\\)"',
    activation: "home-manager switch\\b[^\\n]*?",
    active: "systemctl --user is-active pi-messaging-relay\\.service[ \\t]*>/dev/null",
    watcher: /^[ \t]*timeout --signal=TERM 30s[ \t]+journalctl --user -u pi-messaging-relay\.service -o cat\b[^\n]*/m,
    watcherBound: /^[ \t]*timeout --signal=TERM 30s[ \t]+journalctl --user -u pi-messaging-relay\.service -o cat[ \t]+--after-cursor="\$recovery_cursor"/,
  },
];

const cursorNonemptyGate = 'test -n "\\$recovery_cursor"';
const failures = [];

for (const scope of scopes) {
  const fence = bashFence(scope.body);
  if (!fence) {
    failures.push(`${scope.name}: missing recovery Bash fence`);
    continue;
  }

  const cursorCommand = matchAt(fence, scope.cursorCommand);
  const cursor = failClosedAt(fence, scope.cursorGate);
  const cursorNonempty = failClosedAt(fence, cursorNonemptyGate);
  const activation = failClosedAt(fence, scope.activation);
  const active = failClosedAt(fence, scope.active);
  const watcher = matchAt(fence, scope.watcher);

  if (!cursorCommand) failures.push(`${scope.name}: missing matching journal cursor`);
  else if (!cursor) failures.push(`${scope.name}: missing cursor capture failure gate`);
  if (!cursorNonempty) failures.push(`${scope.name}: missing cursor failure gate`);
  if (!activation) failures.push(`${scope.name}: missing fail-closed activation`);
  if (!active) failures.push(`${scope.name}: missing successful active gate`);
  if (!watcher) {
    failures.push(`${scope.name}: missing bounded scope-correct journal watcher`);
  } else {
    const pipelineAt = watcher.text.indexOf("|");
    const journalCommand = pipelineAt === -1 ? watcher.text : watcher.text.slice(0, pipelineAt);
    const pipeline = pipelineAt === -1 ? "" : watcher.text.slice(pipelineAt);
    const bound = scope.watcherBound.test(journalCommand);
    if (!bound) failures.push(`${scope.name}: missing watcher after-cursor bound`);
    if (!/[ \t]+--follow[ \t]*$/.test(journalCommand)) {
      failures.push(`${scope.name}: missing watcher follower`);
    }
    if (!/^\|\s*grep -m 1 '\"event\":\"server_ready\"'\s*\|\|\s*\{/.test(pipeline)) {
      failures.push(`${scope.name}: missing server_ready pipeline gate`);
    } else {
      const blockEnd = fence.indexOf("}", watcher.index);
      const watcherBlock = blockEnd === -1 ? fence.slice(watcher.index) : fence.slice(watcher.index, blockEnd + 1);
      const failureBlock = /\|\|\s*\{([^}]*)\}/.exec(watcherBlock);
      if (!failureBlock || !hasExecutableExit(failureBlock[1])) {
        failures.push(`${scope.name}: missing readiness failure exit`);
      }
    }
  }

  const sequence = [cursor, cursorNonempty, activation, active, watcher];
  if (sequence.every(Boolean) && sequence.some((item, index) => index > 0 && item.index <= sequence[index - 1].index)) {
    failures.push(`${scope.name}: recovery commands are out of order`);
  }
}

const upgradeSection = headingSection("##", "Upgrade and roll back");
const upgradeScopes = [
  {
    name: "system",
    body: tab(upgradeSection, "NixOS system scope"),
    cursor: /server_cursor="\$\(sudo journalctl -n 0 --show-cursor \| sed -n 's\/\^-- cursor: \/\/p'\)"/,
    activation: "sudo nixos-rebuild switch\\b[^\\n]*?",
    watcher: /^[ \t]*sudo timeout --signal=TERM 30s[ \t]+journalctl -u pi-messaging-relay\.service -o cat[ \t]+--after-cursor="\$server_cursor" --follow[ \t]*\|/m,
  },
  {
    name: "user",
    body: tab(upgradeSection, "Home Manager user scope"),
    cursor: /server_cursor="\$\(journalctl --user -n 0 --show-cursor \| sed -n 's\/\^-- cursor: \/\/p'\)"/,
    activation: "home-manager switch\\b[^\\n]*?",
    watcher: /^[ \t]*timeout --signal=TERM 30s[ \t]+journalctl --user -u pi-messaging-relay\.service -o cat[ \t]+--after-cursor="\$server_cursor" --follow[ \t]*\|/m,
  },
];

for (const scope of upgradeScopes) {
  const fence = bashFence(scope.body);
  if (!fence) {
    failures.push(`${scope.name}: missing upgrade Bash fence`);
    continue;
  }

  const cursor = matchAt(fence, scope.cursor);
  const activation = failClosedAt(fence, scope.activation);
  const watcher = matchAt(fence, scope.watcher);

  if (!cursor) failures.push(`${scope.name}: missing upgrade journal cursor capture`);
  if (!activation) failures.push(`${scope.name}: missing fail-closed upgrade activation`);
  if (!watcher) failures.push(`${scope.name}: missing upgrade readiness watcher`);

  const sequence = [cursor, activation, watcher];
  if (sequence.every(Boolean) && sequence.some((item, index) => index > 0 && item.index <= sequence[index - 1].index)) {
    failures.push(`${scope.name}: upgrade commands are out of order`);
  }
}

if (failures.length > 0) {
  console.error("Nix recovery procedure check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log("Nix recovery procedure check passed.");
}
