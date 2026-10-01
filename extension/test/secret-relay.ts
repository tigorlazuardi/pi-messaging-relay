import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { clientConfigurationPath, ENDPOINT_ENV } from "../internal/client-config.ts";

/** One shared secret for v2 acceptance tests that boot the real server binary. */
export const SHARED_RELAY_SECRET = "v2-shared-relay-secret";

/** Prepare an isolated test root with mode 0700. */
export async function createTestRoot(
  context: { after(callback: () => Promise<void>): void },
  prefix: string,
): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o700);
  return root;
}

/** Write the operator-owned server secret file inside the prepared state directory. */
export async function writeServerSecretFile(
  stateDirectory: string,
  secret = SHARED_RELAY_SECRET,
): Promise<string> {
  await mkdir(stateDirectory, { recursive: true, mode: 0o700 });
  await chmod(stateDirectory, 0o700);
  const path = join(stateDirectory, "relay.secret");
  await writeFile(path, secret, { mode: 0o600 });
  return path;
}

export async function writeClientConfig(
  home: string,
  configuration: { url: string; secret?: string },
): Promise<void> {
  await mkdir(join(home, ".config", "pi"), { recursive: true, mode: 0o700 });
  await writeFile(clientConfigurationPath(home), JSON.stringify(configuration), { mode: 0o600 });
}

/** Point the extension process at one isolated home containing only the test config. */
export function installIsolatedHome(home: string): { restore(): void } {
  const previousHome = process.env.HOME;
  const previousXDG = process.env.XDG_CONFIG_HOME;
  const previousEndpoint = process.env[ENDPOINT_ENV];
  process.env.HOME = home;
  delete process.env.XDG_CONFIG_HOME;
  delete process.env[ENDPOINT_ENV];
  return {
    restore: () => {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
      if (previousXDG === undefined) delete process.env.XDG_CONFIG_HOME;
      else process.env.XDG_CONFIG_HOME = previousXDG;
      if (previousEndpoint === undefined) delete process.env[ENDPOINT_ENV];
      else process.env[ENDPOINT_ENV] = previousEndpoint;
    },
  };
}
