import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { ml_kem768_x25519 } from "@noble/post-quantum/hybrid.js";

export const PQC_ENVELOPE_MAGIC = "OV-PQC-v1";
const HKDF_INFO = "metavault-pqc-v1-hybrid-kdf";

export interface HybridKeyPair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
}

export interface EncapsulatedResult {
  readonly cipherText: Uint8Array;
  readonly sharedSecret: Uint8Array;
}

/**
 * Generates an ML-KEM-768 + X25519 post-quantum hybrid keypair.
 * Combines NIST FIPS 203 lattice-based key encapsulation with classical X25519 Diffie-Hellman.
 */
export function generateHybridKeyPair(): HybridKeyPair {
  const keys = ml_kem768_x25519.keygen();
  return {
    publicKey: keys.publicKey,
    secretKey: keys.secretKey,
  };
}

/**
 * Encapsulates a shared secret using the recipient's hybrid public key.
 */
export function encapsulateHybridSecret(publicKey: Uint8Array): EncapsulatedResult {
  const res = ml_kem768_x25519.encapsulate(publicKey);
  return {
    cipherText: res.cipherText,
    sharedSecret: res.sharedSecret,
  };
}

/**
 * Decapsulates the shared secret using the recipient's hybrid secret key.
 */
export function decapsulateHybridSecret(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ml_kem768_x25519.decapsulate(cipherText, secretKey);
}

/**
 * Derives a 256-bit symmetric key from the hybrid shared secret using HKDF-SHA384.
 */
function deriveSymmetricKey(sharedSecret: Uint8Array, salt: Buffer): Buffer {
  return Buffer.from(
    hkdfSync(
      "sha384",
      Buffer.from(sharedSecret),
      salt,
      Buffer.from(HKDF_INFO, "utf8"),
      32,
    ),
  );
}

/**
 * Seals arbitrary plaintext into a post-quantum hybrid encrypted envelope.
 * Uses ML-KEM-768 + X25519 for key encapsulation, HKDF-SHA384 for key derivation,
 * and AES-256-GCM for authenticated payload encryption.
 */
export function sealWithHybridKEM(recipientPublicKey: Uint8Array, plaintext: string | Buffer): string {
  const { cipherText, sharedSecret } = encapsulateHybridSecret(recipientPublicKey);
  const salt = randomBytes(16);
  const aesKey = deriveSymmetricKey(sharedSecret, salt);

  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
  const payloadBuf = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : plaintext;
  const encrypted = Buffer.concat([cipher.update(payloadBuf), cipher.final()]);
  const tag = cipher.getAuthTag();

  return [
    PQC_ENVELOPE_MAGIC,
    salt.toString("base64url"),
    Buffer.from(cipherText).toString("base64url"),
    iv.toString("base64url"),
    tag.toString("base64url"),
    encrypted.toString("base64url"),
  ].join(".");
}

/**
 * Unseals an envelope previously sealed with `sealWithHybridKEM`.
 * Decapsulates the shared secret using ML-KEM-768 + X25519 and decrypts with AES-256-GCM.
 */
export function unsealWithHybridKEM(recipientSecretKey: Uint8Array, envelope: string): Buffer {
  const parts = envelope.split(".");
  if (parts.length !== 6 || parts[0] !== PQC_ENVELOPE_MAGIC) {
    throw new Error(`Invalid PQC envelope: expected ${PQC_ENVELOPE_MAGIC} envelope`);
  }

  const saltStr = parts[1];
  const cipherTextStr = parts[2];
  const ivStr = parts[3];
  const tagStr = parts[4];
  const encryptedStr = parts[5];

  if (!saltStr || !cipherTextStr || !ivStr || !tagStr || !encryptedStr) {
    throw new Error("Malformed PQC envelope parts");
  }

  const salt = Buffer.from(saltStr, "base64url");
  const cipherText = new Uint8Array(Buffer.from(cipherTextStr, "base64url"));
  const iv = Buffer.from(ivStr, "base64url");
  const tag = Buffer.from(tagStr, "base64url");
  const encrypted = Buffer.from(encryptedStr, "base64url");

  const sharedSecret = decapsulateHybridSecret(cipherText, recipientSecretKey);
  const aesKey = deriveSymmetricKey(sharedSecret, salt);

  const decipher = createDecipheriv("aes-256-gcm", aesKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}
