import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { AsyncLocalStorage } from "node:async_hooks";
import { resolve } from "node:path";

type DirectorySyncObserver = {
  afterDirectorySync?: (path: string) => Promise<void> | void;
};

const testObserver = new AsyncLocalStorage<DirectorySyncObserver>();

export async function syncDirectory(path: string): Promise<void> {
  const absolutePath = resolve(path);
  const handle = await open(
    absolutePath,
    constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    const info = await handle.stat();
    if (!info.isDirectory()) throw new Error("directory sync target is not a directory");
    await handle.sync();
    await testObserver.getStore()?.afterDirectorySync?.(absolutePath);
  } finally {
    await handle.close();
  }
}

// Internal command-test harness only. Async scoping prevents observers from entering the Pi factory contract.
export function withDirectorySyncObserverForTest<T>(
  observer: DirectorySyncObserver,
  operation: () => Promise<T>,
): Promise<T> {
  return testObserver.run(observer, operation);
}
