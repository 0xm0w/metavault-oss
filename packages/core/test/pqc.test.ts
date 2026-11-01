import { describe, expect, it } from "vitest";
import {
  PQC_ENVELOPE_MAGIC,
  decapsulateHybridSecret,
  encapsulateHybridSecret,
  generateHybridKeyPair,
  sealWithHybridKEM,
  unsealWithHybridKEM,
} from "../src/pqc.js";

describe("Post-Quantum Cryptography Hybrid ML-KEM-768 + X25519 (#27)", () => {
  it("generates hybrid post-quantum keypairs with correct structure", () => {
    const keyPair = generateHybridKeyPair();
    expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
    expect(keyPair.secretKey).toBeInstanceOf(Uint8Array);
    // ML-KEM-768 (1184 bytes) + X25519 (32 bytes) = 1216 bytes public key
    expect(keyPair.publicKey.length).toBe(1216);
    // Secret key is compact 32-byte seed deterministically expanded per FIPS 203
    expect(keyPair.secretKey.length).toBe(32);
  });

  it("encapsulates and decapsulates identical shared secret between two parties", () => {
    const aliceKeys = generateHybridKeyPair();
    const bob = encapsulateHybridSecret(aliceKeys.publicKey);

    expect(bob.cipherText.length).toBeGreaterThan(1000);
    expect(bob.sharedSecret.length).toBe(32);

    const aliceSecret = decapsulateHybridSecret(bob.cipherText, aliceKeys.secretKey);
    expect(Buffer.from(aliceSecret)).toEqual(Buffer.from(bob.sharedSecret));
  });

  it("fails or implicitly rejects when decapsulated with the wrong secret key", () => {
    const aliceKeys = generateHybridKeyPair();
    const charlieKeys = generateHybridKeyPair();
    const bob = encapsulateHybridSecret(aliceKeys.publicKey);

    const charlieSecret = decapsulateHybridSecret(bob.cipherText, charlieKeys.secretKey);
    // Implicit rejection in ML-KEM: derives pseudo-random secret, never matches Bob's
    expect(Buffer.from(charlieSecret)).not.toEqual(Buffer.from(bob.sharedSecret));
  });

  it("seals and unseals arbitrary secrets into authenticated post-quantum envelopes", () => {
    const recipient = generateHybridKeyPair();
    const secretMessage = "sk_live_post_quantum_super_secure_token_12345";

    const envelope = sealWithHybridKEM(recipient.publicKey, secretMessage);
    expect(envelope.startsWith(`${PQC_ENVELOPE_MAGIC}.`)).toBe(true);

    const unsealed = unsealWithHybridKEM(recipient.secretKey, envelope);
    expect(unsealed.toString("utf8")).toBe(secretMessage);
  });

  it("handles binary buffer payloads in hybrid envelope sealing", () => {
    const recipient = generateHybridKeyPair();
    const binarySecret = Buffer.from([0x00, 0xff, 0x42, 0x13, 0x37, 0xde, 0xad, 0xbe, 0xef]);

    const envelope = sealWithHybridKEM(recipient.publicKey, binarySecret);
    const unsealed = unsealWithHybridKEM(recipient.secretKey, envelope);
    expect(unsealed).toEqual(binarySecret);
  });

  it("fails closed when the ciphertext or auth tag in the envelope is tampered with", () => {
    const recipient = generateHybridKeyPair();
    const envelope = sealWithHybridKEM(recipient.publicKey, "my-confidential-credential");

    const parts = envelope.split(".");
    // Tamper with encrypted ciphertext segment
    const tamperedPayload = Buffer.from(parts[5] ?? "", "base64url");
    const corruptedByte = (tamperedPayload[0] ?? 0) ^ 0xff;
    tamperedPayload[0] = corruptedByte;
    parts[5] = tamperedPayload.toString("base64url");

    const tamperedEnvelope = parts.join(".");
    expect(() => unsealWithHybridKEM(recipient.secretKey, tamperedEnvelope)).toThrow();
  });

  it("rejects envelopes with invalid headers or malformed formatting", () => {
    const recipient = generateHybridKeyPair();
    expect(() => unsealWithHybridKEM(recipient.secretKey, "CORRUPT.header.data")).toThrow(
      /Invalid PQC envelope/,
    );
    expect(() => unsealWithHybridKEM(recipient.secretKey, "OV-PQC-v1.incomplete")).toThrow(
      /Invalid PQC envelope/,
    );
  });
});
