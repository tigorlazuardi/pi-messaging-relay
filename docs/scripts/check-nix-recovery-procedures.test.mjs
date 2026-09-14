import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import test from "node:test";

const checker = new URL("./check-nix-recovery-procedures.mjs", import.meta.url);

const validProcedure = `
## Upgrade and roll back

<Tabs>
  <TabItem label="NixOS system scope">
    \`\`\`bash
    server_cursor="$(sudo journalctl -n 0 --show-cursor | sed -n 's/^-- cursor: //p')"
    test -n "$server_cursor" || { printf 'cursor failure\\n' >&2; exit 1; }
    sudo nixos-rebuild switch --flake '.#HOST' || { printf 'upgrade activation failure\\n' >&2; exit 1; }
    sudo timeout --signal=TERM 30s \\
      journalctl -u pi-messaging-relay.service -o cat \\
        --after-cursor="$server_cursor" --follow |
      grep -m 1 '"event":"server_ready"' || { printf 'timeout\\n' >&2; exit 1; }
    \`\`\`
  </TabItem>
  <TabItem label="Home Manager user scope">
    \`\`\`bash
    server_cursor="$(journalctl --user -n 0 --show-cursor | sed -n 's/^-- cursor: //p')"
    test -n "$server_cursor" || { printf 'cursor failure\\n' >&2; exit 1; }
    home-manager switch --flake '.#USER@HOST' || { printf 'upgrade activation failure\\n' >&2; exit 1; }
    timeout --signal=TERM 30s \\
      journalctl --user -u pi-messaging-relay.service -o cat \\
        --after-cursor="$server_cursor" --follow |
      grep -m 1 '"event":"server_ready"' || { printf 'timeout\\n' >&2; exit 1; }
    \`\`\`
  </TabItem>
</Tabs>

### System service recovery

\`\`\`bash
recovery_cursor="$(sudo journalctl -u pi-messaging-relay.service -n 0 --show-cursor)" || { printf 'capture failure\\n' >&2; exit 1; }
recovery_cursor="\${recovery_cursor#-- cursor: }"
test -n "$recovery_cursor" || { printf 'cursor failure\\n' >&2; exit 1; }
sudo nixos-rebuild switch --flake '.#HOST' || { printf 'activation failure\\n' >&2; exit 1; }
sudo systemctl is-active pi-messaging-relay.service >/dev/null || { printf 'inactive\\n' >&2; exit 1; }
sudo timeout --signal=TERM 30s \\
  journalctl -u pi-messaging-relay.service -o cat \\
    --after-cursor="$recovery_cursor" --follow |
  grep -m 1 '"event":"server_ready"' || { printf 'timeout\\n' >&2; exit 1; }
\`\`\`

### User service recovery

\`\`\`bash
recovery_cursor="$(journalctl --user -u pi-messaging-relay.service -n 0 --show-cursor)" || { printf 'capture failure\\n' >&2; exit 1; }
recovery_cursor="\${recovery_cursor#-- cursor: }"
test -n "$recovery_cursor" || { printf 'cursor failure\\n' >&2; exit 1; }
home-manager switch --flake '.#USER@HOST' || { printf 'activation failure\\n' >&2; exit 1; }
systemctl --user is-active pi-messaging-relay.service >/dev/null || { printf 'inactive\\n' >&2; exit 1; }
timeout --signal=TERM 30s \\
  journalctl --user -u pi-messaging-relay.service -o cat \\
    --after-cursor="$recovery_cursor" --follow |
  grep -m 1 '"event":"server_ready"' || { printf 'timeout\\n' >&2; exit 1; }
\`\`\`

## Next section
`;

const scopeFixtures = {
  system: {
    cursor: "sudo journalctl -u pi-messaging-relay.service -n 0",
    cursorWrongScope: "sudo journalctl -n 0",
    activation: "sudo nixos-rebuild switch --flake '.#HOST' || { printf 'activation failure\\n' >&2; exit 1; }",
    activationOpen: "sudo nixos-rebuild switch --flake '.#HOST' || { printf 'activation failure\\n' >&2; }",
    active: "sudo systemctl is-active pi-messaging-relay.service >/dev/null || { printf 'inactive\\n' >&2; exit 1; }",
    activeWrong: "sudo systemctl status pi-messaging-relay.service >/dev/null || { printf 'inactive\\n' >&2; exit 1; }",
    timeout: "sudo timeout --signal=TERM 30s",
    timeoutWrong: "sudo timeout --signal=TERM 60s",
    watcherBound: '--after-cursor="$recovery_cursor" --follow |',
    watcherUnbound: '--since="today" --follow |',
  },
  user: {
    cursor: "journalctl --user -u pi-messaging-relay.service -n 0",
    cursorWrongScope: "journalctl -u pi-messaging-relay.service -n 0",
    activation: "home-manager switch --flake '.#USER@HOST' || { printf 'activation failure\\n' >&2; exit 1; }",
    activationOpen: "home-manager switch --flake '.#USER@HOST' || { printf 'activation failure\\n' >&2; }",
    active: "systemctl --user is-active pi-messaging-relay.service >/dev/null || { printf 'inactive\\n' >&2; exit 1; }",
    activeWrong: "systemctl --user status pi-messaging-relay.service >/dev/null || { printf 'inactive\\n' >&2; exit 1; }",
    timeout: "timeout --signal=TERM 30s \\\n  journalctl --user",
    timeoutWrong: "timeout --signal=TERM 60s \\\n  journalctl --user",
    watcherBound: '--after-cursor="$recovery_cursor" --follow |',
    watcherUnbound: '--since="today" --follow |',
  },
};

const failureGates = [
  { name: "cursor capture", anchor: "--show-cursor)", diagnostic: "missing cursor capture failure gate" },
  { name: "cursor nonempty", anchor: 'test -n "$recovery_cursor"', diagnostic: "missing cursor failure gate" },
  { name: "activation", anchor: "switch --flake", diagnostic: "missing fail-closed activation" },
  { name: "active", anchor: "is-active pi-messaging-relay.service", diagnostic: "missing successful active gate" },
  { name: "readiness", anchor: "grep -m 1", diagnostic: "missing readiness failure exit" },
];

const exitDecoys = [
  { name: "commented", replacement: "# exit 1\\n" },
  { name: "commented after separator", replacement: "#; exit 1\\n" },
  { name: "single-quoted", replacement: "printf '%s' 'exit 1';" },
  { name: "double-quoted", replacement: 'printf \'%s\' "exit 1";' },
];

function replaceOnce(source, token, replacement) {
  assert.equal(source.split(token).length, 2, `fixture token must occur once: ${token}`);
  return source.replace(token, replacement);
}

function mutateScope(scope, mutate) {
  const heading = `### ${scope === "system" ? "System" : "User"} service recovery`;
  const start = validProcedure.indexOf(heading);
  const end = validProcedure.indexOf("\n### ", start + heading.length);
  const sectionEnd = end === -1 ? validProcedure.length : end;
  return validProcedure.slice(0, start) + mutate(validProcedure.slice(start, sectionEnd)) + validProcedure.slice(sectionEnd);
}

function replaceGateExit(section, anchor, replacement) {
  const lines = section.split("\n");
  const matching = lines.map((line, index) => ({ line, index })).filter(({ line }) => line.includes(anchor));
  assert.equal(matching.length, 1, `gate anchor must occur once: ${anchor}`);
  lines[matching[0].index] = replaceOnce(matching[0].line, "exit 1;", replacement);
  return lines.join("\n");
}

function mutateUpgradeScope(scope, mutate) {
  const label = scope === "system" ? "NixOS system scope" : "Home Manager user scope";
  const opening = `<TabItem label="${label}">`;
  const start = validProcedure.indexOf(opening);
  const end = validProcedure.indexOf("</TabItem>", start) + "</TabItem>".length;
  assert.notEqual(start, -1);
  assert.notEqual(end, "</TabItem>".length - 1);
  return validProcedure.slice(0, start) + mutate(validProcedure.slice(start, end)) + validProcedure.slice(end);
}

async function runChecker(source = validProcedure) {
  const fixture = await mkdtemp(join(tmpdir(), "pi-relay-recovery-check-"));
  const file = join(fixture, "nix-deployment.mdx");
  try {
    await writeFile(file, source, { encoding: "utf8", mode: 0o600 });
    return spawnSync(process.execPath, [checker.pathname, file], {
      encoding: "utf8",
      timeout: 10_000,
    });
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
}

async function assertRejected(source, diagnostic) {
  const result = await runChecker(source);
  assert.equal(result.status, 1);
  assert.equal(result.signal, null);
  assert.equal(result.stderr, `Nix recovery procedure check failed:\n- ${diagnostic}\n`);
}

test("accepts ordered fail-closed system and user recovery and upgrade Bash fences", async () => {
  const result = await runChecker();

  assert.equal(result.status, 0);
  assert.equal(result.signal, null);
  assert.equal(result.stdout, "Nix recovery procedure check passed.\n");
  assert.equal(result.stderr, "");
});

test("accepts production recovery and upgrade procedures", () => {
  const production = new URL("../src/content/docs/user/nix-deployment.mdx", import.meta.url);
  const result = spawnSync(process.execPath, [checker.pathname, production.pathname], {
    encoding: "utf8",
    timeout: 10_000,
  });

  assert.equal(result.status, 0);
  assert.equal(result.signal, null);
  assert.equal(result.stdout, "Nix recovery procedure check passed.\n");
  assert.equal(result.stderr, "");
});

for (const scope of ["system", "user"]) {
  const fixture = scopeFixtures[scope];

  const upgradeActivation = scope === "system"
    ? "sudo nixos-rebuild switch --flake '.#HOST' || { printf 'upgrade activation failure\\n' >&2; exit 1; }"
    : "home-manager switch --flake '.#USER@HOST' || { printf 'upgrade activation failure\\n' >&2; exit 1; }";

  test(`rejects ${scope} upgrade activation without exit 1`, async () => {
    const source = mutateUpgradeScope(scope, (section) =>
      replaceOnce(section, upgradeActivation, upgradeActivation.replace("exit 1;", "")));
    await assertRejected(source, `${scope}: missing fail-closed upgrade activation`);
  });

  test(`rejects ${scope} upgrade activation after readiness watcher starts`, async () => {
    const readinessGate = "      grep -m 1 '\"event\":\"server_ready\"' || { printf 'timeout\\n' >&2; exit 1; }";
    const source = mutateUpgradeScope(scope, (section) => {
      const withoutActivation = replaceOnce(section, `    ${upgradeActivation}\n`, "");
      return replaceOnce(withoutActivation, readinessGate, `${readinessGate}\n    ${upgradeActivation}`);
    });
    await assertRejected(source, `${scope}: upgrade commands are out of order`);
  });

  for (const decoy of exitDecoys) {
    test(`rejects ${scope} upgrade activation with ${decoy.name} exit decoy`, async () => {
      const source = mutateUpgradeScope(scope, (section) =>
        replaceGateExit(section, "switch --flake", decoy.replacement));
      await assertRejected(source, `${scope}: missing fail-closed upgrade activation`);
    });
  }

  test(`rejects ${scope} watcher without its cursor bound despite a decoy token`, async () => {
    const source = mutateScope(scope, (section) => {
      const unbound = replaceOnce(section, fixture.watcherBound, fixture.watcherUnbound);
      return replaceOnce(unbound, fixture.timeout, `printf '%s\\n' '--after-cursor="$recovery_cursor"'\n${fixture.timeout}`);
    });
    await assertRejected(source, `${scope}: missing watcher after-cursor bound`);
  });

  test(`rejects out-of-order ${scope} recovery commands`, async () => {
    const source = mutateScope(scope, (section) => {
      const withoutActivation = replaceOnce(section, `${fixture.activation}\n`, "");
      return replaceOnce(withoutActivation, `${fixture.active}\n`, `${fixture.active}\n${fixture.activation}\n`);
    });
    await assertRejected(source, `${scope}: recovery commands are out of order`);
  });

  for (const gate of failureGates) {
    for (const decoy of exitDecoys) {
      test(`rejects ${scope} ${gate.name} gate with ${decoy.name} exit decoy`, async () => {
        const source = mutateScope(scope, (section) => replaceGateExit(section, gate.anchor, decoy.replacement));
        await assertRejected(source, `${scope}: ${gate.diagnostic}`);
      });
    }
  }

  test(`rejects ${scope} activation without a nonzero failure exit`, async () => {
    const source = mutateScope(scope, (section) => replaceOnce(section, fixture.activation, fixture.activationOpen));
    await assertRejected(source, `${scope}: missing fail-closed activation`);
  });

  test(`rejects ${scope} cursor nonempty gate without a nonzero failure exit`, async () => {
    const source = mutateScope(scope, (section) =>
      replaceOnce(section, 'test -n "$recovery_cursor" || { printf \'cursor failure\\n\' >&2; exit 1; }', 'test -n "$recovery_cursor" || { printf \'cursor failure\\n\' >&2; }'));
    await assertRejected(source, `${scope}: missing cursor failure gate`);
  });

  test(`rejects ${scope} watcher without follow`, async () => {
    const source = mutateScope(scope, (section) => replaceOnce(section, " --follow |", " |"));
    await assertRejected(source, `${scope}: missing watcher follower`);
  });

  test(`rejects ${scope} readiness gate without a nonzero failure exit`, async () => {
    const source = mutateScope(scope, (section) =>
      replaceOnce(section, "|| { printf 'timeout\\n' >&2; exit 1; }", "|| { printf 'timeout\\n' >&2; }"));
    await assertRejected(source, `${scope}: missing readiness failure exit`);
  });

  test(`rejects a wrong-scope ${scope} cursor with a stable diagnostic`, async () => {
    const source = mutateScope(scope, (section) => replaceOnce(section, fixture.cursor, fixture.cursorWrongScope));
    await assertRejected(source, `${scope}: missing matching journal cursor`);
  });

  test(`rejects a wrong ${scope} active gate with a stable diagnostic`, async () => {
    const source = mutateScope(scope, (section) => replaceOnce(section, fixture.active, fixture.activeWrong));
    await assertRejected(source, `${scope}: missing successful active gate`);
  });

  test(`rejects a non-30-second ${scope} watcher with a stable diagnostic`, async () => {
    const source = mutateScope(scope, (section) => replaceOnce(section, fixture.timeout, fixture.timeoutWrong));
    await assertRejected(source, `${scope}: missing bounded scope-correct journal watcher`);
  });
}
