// Pairing SAS (short authentication string) computation, shared by the
// gateway and the remote client so both screens derive the identical
// string from the identical inputs.
//
// Binding analysis:
// - exporterSecret comes from TLS exportKeyingMaterial on the pairing
//   connection. A MITM terminates two DIFFERENT TLS sessions, so its two
//   exporters differ and the two screens show different strings: the human
//   rejects. This is the transcript binding; the SAS is never transmitted.
// - Both peers' public identities (server cert SPKI, client key SPKI) are
//   bound, so the confirmation covers both directions.
// - The pairing code is bound so a code observed after the fact cannot be
//   re-presented inside a different session, and both nonces bind the
//   specific attempt (replay resistance).
// - The gateway's announced strict-mTLS device port is bound, so a MITM
//   that rewrites the announcement to redirect the pinned post-pairing
//   transport breaks the human comparison.
// The SAS is a truncated SHA-256: 16 hex chars (64 bits) is the comparison
// surface a human verifies; it is a detection mechanism chained to the
// authenticated channel, never a standalone guarantee.
import { createHash } from "node:crypto";

export const PAIRING_EXPORTER_LABEL = "metavault-pairing-v1";
export const PAIRING_EXPORTER_LENGTH = 32;

export interface PairingSasInputs {
  readonly exporterSecret: Buffer;
  readonly serverCertFingerprint: string;
  readonly clientPublicKeyFingerprint: string;
  readonly code: string;
  readonly serverNonce: string;
  readonly clientNonce: string;
  // Strict-mTLS device port announced by the gateway at /pair/begin.
  readonly devicePort: number;
}

export function computePairingSas(inputs: PairingSasInputs): string {
  const hash = createHash("sha256");
  hash.update(inputs.exporterSecret);
  hash.update("\0");
  hash.update(inputs.serverCertFingerprint, "utf8");
  hash.update("\0");
  hash.update(inputs.clientPublicKeyFingerprint, "utf8");
  hash.update("\0");
  hash.update(inputs.code.trim().toUpperCase(), "utf8");
  hash.update("\0");
  hash.update(inputs.serverNonce, "utf8");
  hash.update("\0");
  hash.update(inputs.clientNonce, "utf8");
  hash.update("\0");
  hash.update(String(inputs.devicePort), "utf8");
  const hex = hash.digest("hex").slice(0, 16).toUpperCase();
  return `${hex.slice(0, 4)}-${hex.slice(4, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}`;
}
