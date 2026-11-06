import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Effect } from "effect";
import {
  generatePinSalt,
  hashPin,
  verifyPin,
  DEFAULT_LOCAL_AUTH_RECORD,
  type LocalAuthRecord,
} from "../src/settings.js";
import { VaultStore, VaultStoreTest } from "../src/storage.js";

const MASTER_KEY = Buffer.alloc(32, 1);

describe("Local Authentication & Biometric Gates (#19)", () => {
  it("hashes and verifies PINs securely with timing-safe comparison", () => {
    const salt = generatePinSalt();
    const pin = "123456";
    const hashed = hashPin(pin, salt);

    expect(hashed.startsWith("scrypt-v1:")).toBe(true);
    expect(verifyPin("123456", salt, hashed)).toBe(true);
    expect(verifyPin("654321", salt, hashed)).toBe(false);
    expect(verifyPin("", salt, hashed)).toBe(false);
    expect(verifyPin("123456", salt, "abcd")).toBe(false);
  });

  it("still accepts a legacy single-round SHA-256 pin hash", () => {
    const salt = generatePinSalt();
    const pin = "123456";
    const legacy = createHash("sha256").update(`${salt}:${pin}`).digest("hex");
    expect(legacy.startsWith("scrypt-v1:")).toBe(false);
    expect(verifyPin(pin, salt, legacy)).toBe(true);
    expect(verifyPin("000000", salt, legacy)).toBe(false);
  });

  it("guarantees all local protection layers are strictly OFF by default", () => {
    expect(DEFAULT_LOCAL_AUTH_RECORD.enabled).toBe(false);
    expect(DEFAULT_LOCAL_AUTH_RECORD.requireOnApproval).toBe(false);
    expect(DEFAULT_LOCAL_AUTH_RECORD.requireOnLaunch).toBe(false);
    expect(DEFAULT_LOCAL_AUTH_RECORD.requireOnSettings).toBe(false);
    expect(DEFAULT_LOCAL_AUTH_RECORD.biometricEnabled).toBe(false);
    expect(DEFAULT_LOCAL_AUTH_RECORD.autoLockMinutes).toBe(0);
  });

  it("persists and updates local authentication settings in VaultStore", () => {
    const salt = generatePinSalt();
    const pinHash = hashPin("9876", salt);

    const record: LocalAuthRecord = {
      enabled: true,
      pinHash,
      salt,
      biometricEnabled: true,
      requireOnApproval: true,
      requireOnLaunch: true,
      requireOnSettings: true,
      autoLockMinutes: 15,
    };

    Effect.runSync(
      Effect.gen(function* () {
        const store = yield* VaultStore;
        // Default record initially
        const initial = yield* store.getLocalAuthRecord();
        expect(initial).toEqual(DEFAULT_LOCAL_AUTH_RECORD);

        // Save new record
        yield* store.setLocalAuthRecord(record);

        // Verify persisted record
        const loaded = yield* store.getLocalAuthRecord();
        expect(loaded).toEqual(record);
      }).pipe(Effect.provide(VaultStoreTest(MASTER_KEY))),
    );
  });
});
