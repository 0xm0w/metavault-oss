import { describe, expect, it } from "vitest";
import { wrapMasterKey } from "../src/keywrap.js";
import {
  autoLockMsFromEnv,
  createKeySession,
  envMasterKeyIfAllowed,
  UNLOCK_FREE_ATTEMPTS,
  VaultLockedError,
} from "../src/key-session.js";

const KEY = Buffer.alloc(32, 3);
const PASS = "session passphrase 01";
const FAST = { params: { N: 2 ** 12, r: 8, p: 1 }, allowWeakParams: true } as const;

describe("key session", () => {
  it("starts locked in passphrase mode, unlocks, and auto-locks after idle", async () => {
    let t = 0;
    const s = createKeySession({ mode: "passphrase", wrapped: await wrapMasterKey(KEY, PASS, FAST), autoLockMs: 1000, now: () => t, sweepMs: 0 });
    expect(s.isLocked()).toBe(true);
    expect(() => s.key()).toThrow(VaultLockedError);
    expect(await s.unlock(PASS)).toBe("unlocked");
    expect(s.key().equals(KEY)).toBe(true);
    t = 999;
    expect(s.isLocked()).toBe(false);
    s.key(); // use resets the idle timer
    t = 1998;
    expect(s.isLocked()).toBe(false);
    t = 3000;
    expect(s.isLocked()).toBe(true);
    expect(() => s.key()).toThrow(VaultLockedError);
    s.dispose();
  });
  it("does not accept or retain a key rejected by database validation", async () => {
    let rejected: Buffer | undefined;
    const s = createKeySession({ mode: "passphrase", wrapped: await wrapMasterKey(KEY, PASS, FAST), sweepMs: 0, validateKey: (key) => { rejected = key; throw new Error("mismatch"); } });
    expect(await s.unlock(PASS)).toBe("key-mismatch");
    expect(rejected?.every((b) => b === 0)).toBe(true);
    expect(s.status().fingerprint).toBeNull();
    expect(() => s.key()).toThrow(VaultLockedError);
    s.dispose();
  });
  it("zero-fills the key buffer when it locks", async () => {
    const s = createKeySession({ mode: "passphrase", wrapped: await wrapMasterKey(KEY, PASS, FAST), sweepMs: 0 });
    await s.unlock(PASS);
    const held = s.key();
    s.lock();
    expect(held.every((b) => b === 0)).toBe(true);
    expect(s.isLocked()).toBe(true);
    s.dispose();
  });
  it("throttles after repeated wrong passphrases", async () => {
    let t = 0;
    const s = createKeySession({ mode: "passphrase", wrapped: await wrapMasterKey(KEY, PASS, FAST), now: () => t, sweepMs: 0 });
    for (let i = 0; i < UNLOCK_FREE_ATTEMPTS; i++) expect(await s.unlock("wrong passphrase!!")).toBe("wrong-passphrase");
    expect(await s.unlock(PASS)).toBe("throttled");
    expect(s.status().lockedUntilRetryMs).toBeGreaterThan(0);
    t += 31_000;
    expect(await s.unlock(PASS)).toBe("unlocked");
    s.dispose();
  });
  it("legacy modes never auto-lock and cannot be relocked", () => {
    let t = 0;
    const s = createKeySession({ mode: "env", key: KEY, now: () => t, sweepMs: 0 });
    t = 10 ** 9;
    expect(s.isLocked()).toBe(false);
    s.lock();
    expect(s.key().equals(KEY)).toBe(true);
    expect(s.status().autoLockMs).toBeNull();
  });
  it("refuses an env master key without the explicit opt-in", () => {
    const k = KEY.toString("base64");
    expect(envMasterKeyIfAllowed({})).toBeUndefined();
    expect(() => envMasterKeyIfAllowed({ METAVAULT_MASTER_KEY: k })).toThrow("METAVAULT_ALLOW_ENV_MASTER_KEY");
    expect(envMasterKeyIfAllowed({ METAVAULT_MASTER_KEY: k, METAVAULT_ALLOW_ENV_MASTER_KEY: "1" })?.equals(KEY)).toBe(true);
  });
  it("reads the auto-lock window from env within bounds", () => {
    expect(autoLockMsFromEnv({ METAVAULT_AUTO_LOCK_MINUTES: "5" })).toBe(300_000);
    expect(() => autoLockMsFromEnv({ METAVAULT_AUTO_LOCK_MINUTES: "0" })).toThrow("between 1 and 1440");
    expect(autoLockMsFromEnv({})).toBeUndefined();
  });
});
