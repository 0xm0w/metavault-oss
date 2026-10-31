// packages/core/src/crypto.ts — encryptSecret/decryptSecret live here;
// storage.ts imports them and wires SQLite (credentials + audit tables).
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
export function encryptSecret(key: Buffer, plaintext: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
  return [iv, c.getAuthTag(), ct].map(b => b.toString("base64")).join(".");
}
export function decryptSecret(key: Buffer, blob: string): string {
  const parts = blob.split(".").map(s => Buffer.from(s, "base64"));
  const iv = parts[0];
  const tag = parts[1];
  const ct = parts[2];
  if (iv === undefined || tag === undefined || ct === undefined) {
    throw new Error("Invalid ciphertext blob");
  }
  const d = createDecipheriv("aes-256-gcm", key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}
