// Local Vault CA and X.509 leaf issuance for remote Connections.
//
// Scope discipline: node-forge is used ONLY to assemble and sign X.509
// certificates (a one-time administrative operation). Every remote session
// is terminated by Node's native TLS 1.3 stack (OpenSSL) - handshake,
// record crypto, replay protection and exportKeyingMaterial are never
// implemented here. Keys are generated with node:crypto.
//
// The CA private key never leaves the vault machine and is stored next to
// the wrapped master key with mode 0600, like metavault.token.

import { createHash, generateKeyPairSync } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { hardenOwnerOnly } from "./owner-acl.js";
import * as forge from "node-forge";

export const VAULT_CA_KEY_FILE = "metavault-ca.key.pem";
export const VAULT_CA_CERT_FILE = "metavault-ca.cert.pem";
export const GATEWAY_KEY_FILE = "metavault-gateway.key.pem";
export const GATEWAY_CERT_FILE = "metavault-gateway.cert.pem";

export interface VaultCa {
  readonly keyPem: string;
  readonly certPem: string;
  readonly fingerprint: string;
}

export interface KeyPairPem {
  readonly publicKeyPem: string;
  readonly privateKeyPem: string;
}

export function generateRsaKeyPairPem(): KeyPairPem {
  const pair = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKeyPem: pair.publicKey, privateKeyPem: pair.privateKey };
}

// SHA-256 over the DER SubjectPublicKeyInfo. This is the device identity
// pinned in the devices table and displayed (truncated) in the UI.
export function spkiFingerprintFromPublicKeyPem(publicKeyPem: string): string {
  const key = forge.pki.publicKeyFromPem(publicKeyPem);
  const der = forge.asn1.toDer(forge.pki.publicKeyToAsn1(key)).getBytes();
  return createHash("sha256").update(Buffer.from(der, "binary")).digest("hex");
}

export function spkiFingerprintFromCertPem(certPem: string): string {
  const cert = forge.pki.certificateFromPem(certPem);
  const der = forge.asn1.toDer(forge.pki.publicKeyToAsn1(cert.publicKey)).getBytes();
  return createHash("sha256").update(Buffer.from(der, "binary")).digest("hex");
}

function writeSecretFile(path: string, contents: string): void {
  writeFileSync(path, contents, { encoding: "utf8", mode: 0o600 });
  hardenOwnerOnly(path, false);
}

// Loads the vault CA from the vault directory, creating it on first use.
// Creation is local-only and explicit (remote access enablement).
export function ensureVaultCa(vaultDir: string): VaultCa {
  const keyPath = join(vaultDir, VAULT_CA_KEY_FILE);
  const certPath = join(vaultDir, VAULT_CA_CERT_FILE);
  if (existsSync(keyPath) && existsSync(certPath)) {
    const keyPem = readFileSync(keyPath, "utf8");
    const certPem = readFileSync(certPath, "utf8");
    return { keyPem, certPem, fingerprint: spkiFingerprintFromCertPem(certPem) };
  }
  const { publicKeyPem, privateKeyPem } = generateRsaKeyPairPem();
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000);
  const attrs = [{ name: "commonName", value: "MetaVault Vault CA" }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, critical: true },
  ]);
  cert.sign(forge.pki.privateKeyFromPem(privateKeyPem), forge.md.sha256.create());
  const certPem = forge.pki.certificateToPem(cert);
  writeSecretFile(keyPath, privateKeyPem);
  writeFileSync(certPath, certPem, { encoding: "utf8", mode: 0o644 });
  return { keyPem: privateKeyPem, certPem, fingerprint: spkiFingerprintFromCertPem(certPem) };
}

export interface LeafCertOptions {
  readonly caKeyPem: string;
  readonly caCertPem: string;
  readonly publicKeyPem: string;
  readonly commonName: string;
  readonly serialNumber: string;
  readonly validityDays: number;
  readonly usage: "server" | "client";
}

// Signs a short-lived leaf for the gateway (server) or a paired device
// (client). No pathlen, no CA flag, EKU restricted to the one usage.
export function signLeafCertificate(options: LeafCertOptions): string {
  const caCert = forge.pki.certificateFromPem(options.caCertPem);
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(options.publicKeyPem);
  cert.serialNumber = options.serialNumber;
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + options.validityDays * 24 * 60 * 60 * 1000);
  cert.setSubject([{ name: "commonName", value: options.commonName }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { name: "basicConstraints", cA: false, critical: true },
    {
      name: "keyUsage",
      digitalSignature: true,
      keyEncipherment: options.usage === "server",
      critical: true,
    },
    {
      name: "extKeyUsage",
      serverAuth: options.usage === "server",
      clientAuth: options.usage === "client",
      critical: true,
    },
  ]);
  cert.sign(forge.pki.privateKeyFromPem(options.caKeyPem), forge.md.sha256.create());
  return forge.pki.certificateToPem(cert);
}

// Ensures the gateway's own server certificate exists, signed by the vault
// CA. Rotating the CA or deleting the gateway cert re-mints on next enable.
export function ensureGatewayCertificate(vaultDir: string, ca: VaultCa): { keyPem: string; certPem: string } {
  const keyPath = join(vaultDir, GATEWAY_KEY_FILE);
  const certPath = join(vaultDir, GATEWAY_CERT_FILE);
  if (existsSync(keyPath) && existsSync(certPath)) {
    return { keyPem: readFileSync(keyPath, "utf8"), certPem: readFileSync(certPath, "utf8") };
  }
  const { publicKeyPem, privateKeyPem } = generateRsaKeyPairPem();
  const certPem = signLeafCertificate({
    caKeyPem: ca.keyPem,
    caCertPem: ca.certPem,
    publicKeyPem,
    commonName: "metavault-gateway",
    serialNumber: "02",
    validityDays: 825,
    usage: "server",
  });
  writeSecretFile(keyPath, privateKeyPem);
  writeFileSync(certPath, certPem, { encoding: "utf8", mode: 0o644 });
  return { keyPem: privateKeyPem, certPem };
}
