// Passphrase-wrapped master key.
//
// The vault master key (32 random bytes, the AES-256-GCM key for every
// stored secret) is sealed with a key-encryption key (KEK) derived from a
// passphrase the human types. The wrapped blob is safe to keep on disk: a
// thief who copies it must still guess the passphrase through the KDF.
//
// KDF choices follow the OWASP Password Storage Cheat Sheet minimums:
//   scrypt   N=2^17, r=8, p=1 (default: built into every Node runtime)
//   argon2id m=19 MiB, t=2, p=1 (opt-in: needs node:crypto argon2, Node >= 24.7)
// The KDF name and parameters are bound into the AES-GCM additional data,
// so editing them in the file makes unwrap fail instead of weakening it.

import * as nodeCrypto from "node:crypto";
import { createCipheriv, createDecipheriv, randomBytes, scrypt } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export type KdfName = "scrypt" | "argon2id";

export interface ScryptParams {
  readonly N: number;
  readonly r: number;
  readonly p: number;
}

export interface Argon2idParams {
  readonly memoryKiB: number;
  readonly passes: number;
  readonly parallelism: number;
}

export interface WrappedMasterKey {
  readonly v: 1;
  readonly kdf: KdfName;
  readonly params: ScryptParams | Argon2idParams;
  readonly salt: string;
  readonly iv: string;
  readonly tag: string;
  readonly ct: string;
  readonly createdAt: string;
}

export const SCRYPT_DEFAULT_PARAMS: ScryptParams = { N: 2 ** 17, r: 8, p: 1 };
export const ARGON2ID_DEFAULT_PARAMS: Argon2idParams = { memoryKiB: 19_456, passes: 2, parallelism: 1 };
export const MIN_PASSPHRASE_LENGTH = 12;
export const WRAPPED_KEY_FILE = "metavault.key.json";

// Floors for wrapping. Tests may go lower only through allowWeakParams.
const SCRYPT_FLOOR_N = 2 ** 17;
const ARGON2_FLOOR_MEMORY_KIB = 19_456;
// Ceilings for unwrapping, so a tampered file cannot make unlock hang.
const SCRYPT_MAX_N = 2 ** 20;
const ARGON2_MAX_MEMORY_KIB = 1_048_576;

export class WrongPassphrase extends Error {
  constructor() {
    super("wrong passphrase or corrupted key file");
    this.name = "WrongPassphrase";
  }
}

export function wrappedKeyFilePath(dbPath: string): string {
  return join(dirname(dbPath), WRAPPED_KEY_FILE);
}

export function argon2Available(): boolean {
  return typeof (nodeCrypto as { argon2?: unknown }).argon2 === "function";
}

function normalizePassphrase(passphrase: string): Buffer {
  return Buffer.from(passphrase.normalize("NFKC"), "utf8");
}

function aadFor(kdf: KdfName, params: ScryptParams | Argon2idParams): Buffer {
  return Buffer.from(`metavault-master-key-v1|${kdf}|${JSON.stringify(params)}`, "utf8");
}

function isScryptParams(p: ScryptParams | Argon2idParams): p is ScryptParams {
  return "N" in p;
}

type Argon2Fn = (
  algorithm: string,
  parameters: {
    message: Buffer;
    nonce: Buffer;
    parallelism: number;
    tagLength: number;
    memory: number;
    passes: number;
  },
  callback: (err: Error | null, derivedKey: Buffer) => void,
) => void;

export function deriveKek(
  passphrase: string,
  kdf: KdfName,
  params: ScryptParams | Argon2idParams,
  salt: Buffer,
): Promise<Buffer> {
  const secret = normalizePassphrase(passphrase);
  return new Promise((resolve, reject) => {
    const done = (err: Error | null, key: Buffer): void => {
      secret.fill(0);
      if (err !== null) reject(err);
      else resolve(key);
    };
    if (kdf === "scrypt" && isScryptParams(params)) {
      const maxmem = 128 * params.N * params.r * 2;
      scrypt(secret, salt, 32, { N: params.N, r: params.r, p: params.p, maxmem }, done);
      return;
    }
    if (kdf === "argon2id" && !isScryptParams(params)) {
      const argon2 = (nodeCrypto as { argon2?: Argon2Fn }).argon2;
      if (argon2 === undefined) {
        secret.fill(0);
        reject(new Error("argon2id is not available in this Node runtime"));
        return;
      }
      argon2(
        "argon2id",
        {
          message: secret,
          nonce: salt,
          parallelism: params.parallelism,
          tagLength: 32,
          memory: params.memoryKiB,
          passes: params.passes,
        },
        done,
      );
      return;
    }
    secret.fill(0);
    reject(new Error("KDF name and parameters do not match"));
  });
}

export interface WrapOptions {
  readonly kdf?: KdfName;
  readonly params?: ScryptParams | Argon2idParams;
  // Test-only escape hatch for fast unit tests. Never set in product code.
  readonly allowWeakParams?: boolean;
}

export function checkPassphraseStrength(passphrase: string): "ok" | "too-short" {
  return Array.from(new Intl.Segmenter().segment(passphrase.normalize("NFKC"))).length >= MIN_PASSPHRASE_LENGTH ? "ok" : "too-short";
}

export async function wrapMasterKey(
  masterKey: Buffer,
  passphrase: string,
  options: WrapOptions = {},
): Promise<WrappedMasterKey> {
  if (masterKey.length !== 32) throw new Error("master key must be 32 bytes");
  if (checkPassphraseStrength(passphrase) !== "ok") {
    throw new Error(`passphrase must be at least ${String(MIN_PASSPHRASE_LENGTH)} characters`);
  }
  const kdf = options.kdf ?? "scrypt";
  const params = options.params ?? (kdf === "scrypt" ? SCRYPT_DEFAULT_PARAMS : ARGON2ID_DEFAULT_PARAMS);
  if (options.allowWeakParams !== true) {
    if (isScryptParams(params) && params.N < SCRYPT_FLOOR_N) throw new Error("scrypt N below the OWASP floor");
    if (!isScryptParams(params) && params.memoryKiB < ARGON2_FLOOR_MEMORY_KIB) {
      throw new Error("argon2id memory below the OWASP floor");
    }
  }
  const salt = randomBytes(16);
  const kek = await deriveKek(passphrase, kdf, params, salt);
  try {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", kek, iv);
    cipher.setAAD(aadFor(kdf, params));
    const ct = Buffer.concat([cipher.update(masterKey), cipher.final()]);
    return {
      v: 1,
      kdf,
      params,
      salt: salt.toString("base64"),
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      ct: ct.toString("base64"),
      createdAt: new Date().toISOString(),
    };
  } finally {
    kek.fill(0);
  }
}

export async function unwrapMasterKey(wrapped: WrappedMasterKey, passphrase: string): Promise<Buffer> {
  const { kdf, params } = wrapped;
  if (isScryptParams(params) ? params.N > SCRYPT_MAX_N : params.memoryKiB > ARGON2_MAX_MEMORY_KIB) {
    throw new Error("key file KDF parameters exceed the allowed maximum");
  }
  const kek = await deriveKek(passphrase, kdf, params, Buffer.from(wrapped.salt, "base64"));
  try {
    const decipher = createDecipheriv("aes-256-gcm", kek, Buffer.from(wrapped.iv, "base64"));
    decipher.setAAD(aadFor(kdf, params));
    decipher.setAuthTag(Buffer.from(wrapped.tag, "base64"));
    const key = Buffer.concat([decipher.update(Buffer.from(wrapped.ct, "base64")), decipher.final()]);
    if (key.length !== 32) {
      key.fill(0);
      throw new WrongPassphrase();
    }
    return key;
  } catch (err) {
    if (err instanceof WrongPassphrase) throw err;
    throw new WrongPassphrase();
  } finally {
    kek.fill(0);
  }
}

function isWrapped(value: unknown): value is WrappedMasterKey {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  const params = v["params"] as Record<string, unknown> | undefined;
  const paramsOk =
    typeof params === "object" &&
    ((v["kdf"] === "scrypt" && typeof params["N"] === "number" && typeof params["r"] === "number" && typeof params["p"] === "number") ||
      (v["kdf"] === "argon2id" &&
        typeof params["memoryKiB"] === "number" &&
        typeof params["passes"] === "number" &&
        typeof params["parallelism"] === "number"));
  return (
    v["v"] === 1 &&
    paramsOk &&
    typeof v["salt"] === "string" &&
    typeof v["iv"] === "string" &&
    typeof v["tag"] === "string" &&
    typeof v["ct"] === "string"
  );
}

export function readWrappedKeyFile(path: string): WrappedMasterKey | null {
  if (!existsSync(path)) return null;
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!isWrapped(parsed)) throw new Error("key file is not a MetaVault wrapped key");
  return parsed;
}

// Atomic write with owner-only permissions (POSIX). On Windows the file
// inherits the user profile ACL.
export function writeWrappedKeyFile(path: string, wrapped: WrappedMasterKey): void {
  const tmp = `${path}.tmp-${randomBytes(4).toString("hex")}`;
  writeFileSync(tmp, `${JSON.stringify(wrapped, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  renameSync(tmp, path);
}
