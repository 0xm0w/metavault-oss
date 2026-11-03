import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  argon2Available,
  checkPassphraseStrength,
  readWrappedKeyFile,
  unwrapMasterKey,
  WrongPassphrase,
  wrapMasterKey,
  writeWrappedKeyFile,
} from "../src/keywrap.js";

const KEY = Buffer.alloc(32, 9);
const PASS = "a long enough passphrase";
const FAST = { params: { N: 2 ** 12, r: 8, p: 1 }, allowWeakParams: true } as const;

describe("passphrase key wrapping", () => {
  it("round-trips the master key and never stores it in the clear", async () => {
    const w = await wrapMasterKey(KEY, PASS, FAST);
    expect(w.kdf).toBe("scrypt");
    expect(JSON.stringify(w)).not.toContain(KEY.toString("base64"));
    expect((await unwrapMasterKey(w, PASS)).equals(KEY)).toBe(true);
  });
  it("rejects a wrong passphrase with WrongPassphrase", async () => {
    const w = await wrapMasterKey(KEY, PASS, FAST);
    await expect(unwrapMasterKey(w, "not the right passphrase")).rejects.toBeInstanceOf(WrongPassphrase);
  });
  it("binds the KDF parameters: tampering with them fails closed", async () => {
    const w = await wrapMasterKey(KEY, PASS, FAST);
    await expect(unwrapMasterKey({ ...w, params: { N: 2 ** 11, r: 8, p: 1 } }, PASS)).rejects.toBeInstanceOf(
      WrongPassphrase,
    );
  });
  it("refuses parameters below the OWASP floor unless explicitly allowed", async () => {
    await expect(wrapMasterKey(KEY, PASS, { params: { N: 2 ** 12, r: 8, p: 1 } })).rejects.toThrow("OWASP");
  });
  it("refuses absurd parameters from a tampered key file (DoS guard)", async () => {
    const w = await wrapMasterKey(KEY, PASS, FAST);
    await expect(unwrapMasterKey({ ...w, params: { N: 2 ** 24, r: 8, p: 1 } }, PASS)).rejects.toThrow("maximum");
  });
  it("enforces a minimum passphrase length", async () => {
    expect(checkPassphraseStrength("short")).toBe("too-short");
    expect(checkPassphraseStrength(PASS)).toBe("ok");
    await expect(wrapMasterKey(KEY, "short", FAST)).rejects.toThrow("at least");
  });
  it.runIf(argon2Available())("supports argon2id", async () => {
    const w = await wrapMasterKey(KEY, PASS, {
      kdf: "argon2id",
      params: { memoryKiB: 1024, passes: 1, parallelism: 1 },
      allowWeakParams: true,
    });
    expect((await unwrapMasterKey(w, PASS)).equals(KEY)).toBe(true);
  });
  it("writes the key file atomically with owner-only permissions and reads it back", async () => {
    const dir = mkdtempSync(join(tmpdir(), "metavault-keywrap-"));
    try {
      const path = join(dir, "metavault.key.json");
      const w = await wrapMasterKey(KEY, PASS, FAST);
      writeWrappedKeyFile(path, w);
      if (process.platform !== "win32") expect(statSync(path).mode & 0o777).toBe(0o600);
      expect(readWrappedKeyFile(path)).toEqual(w);
      expect(readFileSync(path, "utf8")).not.toContain(KEY.toString("hex"));
      expect(readWrappedKeyFile(join(dir, "missing.json"))).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
