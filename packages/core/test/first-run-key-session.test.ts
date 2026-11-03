import { describe, expect, it } from "vitest";
import { wrapMasterKey, type WrappedMasterKey } from "../src/keywrap.js";
import { createFirstRunKeySession, VaultLockedError } from "../src/key-session.js";

const FAST = { params: { N: 2 ** 12, r: 8, p: 1 }, allowWeakParams: true } as const;
const PASS = "first run passphrase 01";

function memoryFiles(): {
  files: Map<string, WrappedMasterKey>;
  readWrapped: (path: string) => WrappedMasterKey | null;
  writeWrapped: (path: string, wrapped: WrappedMasterKey) => void;
  wrap: (key: Buffer, passphrase: string) => Promise<WrappedMasterKey>;
} {
  const files = new Map<string, WrappedMasterKey>();
  return {
    files,
    readWrapped: (path) => files.get(path) ?? null,
    writeWrapped: (path, wrapped) => {
      files.set(path, wrapped);
    },
    wrap: (key, passphrase) => wrapMasterKey(key, passphrase, FAST),
  };
}

describe("first-run key session", () => {
  it("reports uninitialized and locked, and refuses key() and unlock before setup", async () => {
    const io = memoryFiles();
    const s = createFirstRunKeySession({ wrappedKeyPath: "/v/metavault.key.json", sweepMs: 0, ...io });
    expect(s.mode).toBe("uninitialized");
    expect(s.isLocked()).toBe(true);
    expect(s.status()).toMatchObject({ mode: "uninitialized", locked: true });
    expect(() => s.key()).toThrow(VaultLockedError);
    expect(await s.unlock(PASS)).toBe("not-initialized");
    s.lock();
    s.dispose();
  });

  it("rejects a short passphrase and writes nothing", async () => {
    const io = memoryFiles();
    const s = createFirstRunKeySession({ wrappedKeyPath: "/v/k.json", sweepMs: 0, ...io });
    expect(await s.setup?.("short")).toBe("too-short");
    expect(io.files.size).toBe(0);
    expect(s.mode).toBe("uninitialized");
  });

  it("creates a wrapped key, comes up unlocked, then locks and unlocks with the same passphrase", async () => {
    const io = memoryFiles();
    const s = createFirstRunKeySession({ wrappedKeyPath: "/v/k.json", sweepMs: 0, ...io });
    expect(await s.setup?.(PASS)).toBe("initialized");
    expect(io.files.has("/v/k.json")).toBe(true);
    expect(s.mode).toBe("passphrase");
    expect(s.isLocked()).toBe(false);
    const key = Buffer.from(s.key());
    expect(key.length).toBe(32);
    s.lock();
    expect(s.isLocked()).toBe(true);
    expect(await s.unlock("wrong passphrase 999")).toBe("wrong-passphrase");
    expect(await s.unlock(PASS)).toBe("unlocked");
    expect(Buffer.from(s.key()).equals(key)).toBe(true);
    expect(await s.setup?.(PASS)).toBe("already-initialized");
    s.dispose();
  });

  it("picks up a key file written by another tool and refuses a second setup", async () => {
    const io = memoryFiles();
    const s = createFirstRunKeySession({ wrappedKeyPath: "/v/k.json", sweepMs: 0, ...io });
    io.files.set("/v/k.json", await wrapMasterKey(Buffer.alloc(32, 9), PASS, FAST));
    expect(s.mode).toBe("passphrase");
    expect(s.isLocked()).toBe(true);
    expect(await s.setup?.(PASS)).toBe("already-initialized");
    expect(await s.unlock(PASS)).toBe("unlocked");
    expect(Buffer.from(s.key()).equals(Buffer.alloc(32, 9))).toBe(true);
    s.dispose();
  });
});
