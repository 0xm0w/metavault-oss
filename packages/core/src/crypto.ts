// packages/core/src/crypto.ts — encryptSecret/decryptSecret live here;
// storage.ts imports them and wires SQLite (credentials + audit tables).
//
// v2 blobs bind alias and kind as AES-256-GCM additional authenticated data
// so a ciphertext copied onto another alias fails authentication. v1 blobs
// (three base64 parts, no prefix) still decrypt so existing vaults open.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export interface SecretAadContext {
  readonly alias: string;
  readonly kind?: string;
}

const V2_PREFIX = "v2.";
const GCM_IV_LENGTH = 12;
const GCM_TAG_LENGTH = 16;

export function buildSecretAad(ctx: SecretAadContext): Buffer {
  return Buffer.from(`metavault-cred-v2|${ctx.alias}|${ctx.kind ?? "secret"}`, "utf8");
}

export function encryptSecret(key: Buffer, plaintext: string, ctx?: SecretAadContext): string {
  const iv = randomBytes(GCM_IV_LENGTH);
  const c = createCipheriv("aes-256-gcm", key, iv, { authTagLength: GCM_TAG_LENGTH });
  if (ctx !== undefined) {
    c.setAAD(buildSecretAad(ctx));
  }
  const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
  const body = [iv, c.getAuthTag(), ct].map((b) => b.toString("base64")).join(".");
  return ctx !== undefined ? `${V2_PREFIX}${body}` : body;
}

export function decryptSecret(key: Buffer, blob: string, ctx?: SecretAadContext): string {
  const isV2 = blob.startsWith(V2_PREFIX);
  const raw = isV2 ? blob.slice(V2_PREFIX.length) : blob;
  const parts = raw.split(".").map((s) => Buffer.from(s, "base64"));
  const iv = parts[0];
  const tag = parts[1];
  const ct = parts[2];
  if (iv === undefined || tag === undefined || ct === undefined) {
    throw new Error("Invalid ciphertext blob");
  }
  if (iv.length !== GCM_IV_LENGTH || tag.length !== GCM_TAG_LENGTH) {
    throw new Error("Invalid ciphertext blob");
  }
  const d = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: GCM_TAG_LENGTH });
  if (isV2) {
    if (ctx === undefined) {
      throw new Error("Missing AAD context for v2 ciphertext");
    }
    d.setAAD(buildSecretAad(ctx));
  }
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}
