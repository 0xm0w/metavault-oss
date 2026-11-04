// MetaVault remote device client (WP5 / DD7): the device side of pairing,
// on-disk device credentials, and the loopback MCP-channel shim.
//
// Trust model:
// - The pairing leg is intentionally unauthenticated at the TLS layer
//   (rejectUnauthorized: false): no trust anchor exists yet. Authenticity
//   comes ONLY from the human comparing the SAS shown here with the SAS on
//   the vault screen, and the vault-side human confirming there. Nothing is
//   issued before that comparison happens.
// - After pairing, all traffic is pinned: the vault CA is the only trust
//   anchor and the gateway server certificate's SPKI fingerprint must match
//   the fingerprint captured during pairing. There is no silent trust reset
//   and no persistent rejectUnauthorized: false.
// - Pairing codes, SAS values and session identifiers are never written to
//   logs or persisted; only the issued certificate, CA, key and fingerprint
//   land on disk, owner-only.
import { createHash, randomBytes, X509Certificate } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { request as httpsRequest } from "node:https";
import { join } from "node:path";
import type { TLSSocket } from "node:tls";
import { computePairingSas, PAIRING_EXPORTER_LABEL, PAIRING_EXPORTER_LENGTH } from "../../core/src/pairing.js";
import { generateRsaKeyPairPem, spkiFingerprintFromPublicKeyPem } from "../../core/src/vault-ca.js";
import { isAllowlisted } from "./server.js";

export class PairingError extends Error {
  readonly reason: "rejected" | "expired" | "timeout" | "transport";
  constructor(reason: PairingError["reason"], message: string) {
    super(message);
    this.reason = reason;
  }
}

export interface PairingResult {
  // dev-<first 12 hex of the client key fingerprint>, matching the
  // vault-side device record created at confirmation.
  readonly deviceId: string;
  readonly keyPem: string;
  readonly certPem: string;
  readonly caCertPem: string;
  readonly serverCertFingerprint: string;
}

interface GatewayTlsResponse {
  status: number;
  body: string;
  exporter?: Buffer;
}

function gatewayPost(options: {
  host: string;
  port: number;
  path: string;
  body: unknown;
  // Pairing leg only: no trust anchor exists yet. Everything after
  // pairing goes through pinnedRequest below.
  trustOnFirstUse: boolean;
  ca?: string;
  cert?: string;
  key?: string;
  expectedServerFingerprint?: string;
}): Promise<GatewayTlsResponse> {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      {
        host: options.host,
        port: options.port,
        method: "POST",
        path: options.path,
        ca: options.ca,
        cert: options.cert,
        key: options.key,
        rejectUnauthorized: !options.trustOnFirstUse,
        headers: { "content-type": "application/json" },
      },
      (res) => {
        const socket = res.socket as TLSSocket | null;
        let exporter: Buffer | undefined;
        try {
          exporter = socket?.exportKeyingMaterial(PAIRING_EXPORTER_LENGTH, PAIRING_EXPORTER_LABEL, Buffer.alloc(0));
        } catch {
          exporter = undefined;
        }
        if (options.expectedServerFingerprint !== undefined) {
          try {
            const peerRaw = socket?.getPeerCertificate(true).raw as Buffer | undefined;
            const fp =
              peerRaw === undefined
                ? undefined
                : spkiFingerprintFromDerCert(peerRaw);
            if (fp !== options.expectedServerFingerprint) {
              reject(new PairingError("transport", "gateway certificate fingerprint mismatch: refusing to talk to an unpinned peer"));
              req.destroy();
              return;
            }
          } catch {
            reject(new PairingError("transport", "could not verify the pinned gateway certificate"));
            req.destroy();
            return;
          }
        }
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
            ...(exporter !== undefined ? { exporter } : {}),
          });
        });
      },
    );
    req.on("error", (err) => {
      reject(new PairingError("transport", `gateway connection failed: ${err.message}`));
    });
    req.write(JSON.stringify(options.body));
    req.end();
  });
}

function spkiFingerprintFromDerCert(raw: Buffer): string {
  // The pairing fingerprint pins the server SPKI, not the certificate
  // bytes, so re-issuance of the same key stays pinned.
  const cert = new X509Certificate(raw);
  const spki = cert.publicKey.export({ format: "der", type: "spki" });
  return createHash("sha256").update(spki).digest("hex");
}

// Runs the device side of the pairing handshake. onSas is called exactly
// once with the SAS this device computed; the human MUST compare it with
// the vault screen and confirm on the vault side. This function never
// confirms anything itself and never prints the code or SAS.
export async function runPairingHandshake(options: {
  host: string;
  port: number;
  code: string;
  deviceName: string;
  platform: string;
  onSas: (sas: string) => void;
  pollIntervalMs?: number;
  timeoutMs?: number;
}): Promise<PairingResult> {
  const keys = generateRsaKeyPairPem();
  const clientNonce = randomBytes(16).toString("hex");
  const begin = await gatewayPost({
    host: options.host,
    port: options.port,
    path: "/pair/begin",
    trustOnFirstUse: true,
    body: {
      code: options.code,
      deviceName: options.deviceName,
      platform: options.platform,
      clientPublicKeyPem: keys.publicKeyPem,
      clientNonce,
    },
  });
  if (begin.status !== 200 || begin.exporter === undefined) {
    throw new PairingError("rejected", `the vault rejected pairing (wrong/expired code or pairing not open) [${String(begin.status)}]`);
  }
  const info = JSON.parse(begin.body) as { pairingId: string; serverNonce: string; serverCertFingerprint: string };
  const sas = computePairingSas({
    exporterSecret: begin.exporter,
    serverCertFingerprint: info.serverCertFingerprint,
    clientPublicKeyFingerprint: spkiFingerprintFromPublicKeyPem(keys.publicKeyPem),
    code: options.code,
    serverNonce: info.serverNonce,
    clientNonce,
  });
  options.onSas(sas);

  const deadline = Date.now() + (options.timeoutMs ?? 5 * 60_000);
  const pollMs = options.pollIntervalMs ?? 2_000;
  for (;;) {
    if (Date.now() > deadline) {
      throw new PairingError("timeout", "pairing was not confirmed on the vault in time");
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs));
    const status = await gatewayPost({
      host: options.host,
      port: options.port,
      path: "/pair/status",
      trustOnFirstUse: true,
      body: { pairingId: info.pairingId },
    });
    if (status.status !== 200) {
      throw new PairingError("expired", "the pairing session is gone (canceled or replaced on the vault)");
    }
    const body = JSON.parse(status.body) as { status: string; certificatePem?: string; caCertPem?: string };
    if (body.status === "unknown") {
      // Canceled, replaced by a newer session, or expired on the vault.
      throw new PairingError("expired", "the pairing session is gone (canceled or replaced on the vault)");
    }
    if (body.status === "confirmed") {
      if (typeof body.certificatePem !== "string" || typeof body.caCertPem !== "string") {
        throw new PairingError("transport", "vault issued a malformed certificate bundle");
      }
      return {
        deviceId: `dev-${spkiFingerprintFromPublicKeyPem(keys.publicKeyPem).slice(0, 12)}`,
        keyPem: keys.privateKeyPem,
        certPem: body.certificatePem,
        caCertPem: body.caCertPem,
        serverCertFingerprint: info.serverCertFingerprint,
      };
    }
  }
}

export interface DeviceProfile {
  readonly deviceId: string;
  readonly host: string;
  readonly port: number;
  readonly pairedAt: string;
  readonly serverCertFingerprint: string;
}

export function saveDeviceProfile(dir: string, profile: DeviceProfile, material: PairingResult): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(join(dir, "key.pem"), material.keyPem, { mode: 0o600 });
  writeFileSync(join(dir, "cert.pem"), material.certPem, { mode: 0o600 });
  writeFileSync(join(dir, "ca.pem"), material.caCertPem, { mode: 0o600 });
  writeFileSync(join(dir, "device.json"), JSON.stringify(profile, null, 2) + "\n", { mode: 0o600 });
}

export interface LoadedDevice {
  readonly profile: DeviceProfile;
  readonly keyPem: string;
  readonly certPem: string;
  readonly caCertPem: string;
}

export function loadDeviceProfile(dir: string): LoadedDevice {
  const profile = JSON.parse(readFileSync(join(dir, "device.json"), "utf8")) as DeviceProfile;
  return {
    profile,
    keyPem: readFileSync(join(dir, "key.pem"), "utf8"),
    certPem: readFileSync(join(dir, "cert.pem"), "utf8"),
    caCertPem: readFileSync(join(dir, "ca.pem"), "utf8"),
  };
}

// Pinned request after enrollment: vault CA is the only anchor and the
// server SPKI fingerprint must match the pinned one.
function pinnedRequest(device: LoadedDevice, options: {
  method: string;
  path: string;
  bodyText?: string;
  agentToken?: string;
}): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      {
        host: device.profile.host,
        port: device.profile.port,
        method: options.method,
        path: options.path,
        ca: device.caCertPem,
        cert: device.certPem,
        key: device.keyPem,
        rejectUnauthorized: true,
        // The gateway certificate carries no hostname SANs; identity comes
        // from CA pinning plus the SPKI fingerprint check below.
        checkServerIdentity: () => undefined,
        headers: {
          "content-type": "application/json",
          ...(options.agentToken !== undefined ? { "x-metavault-agent-token": options.agentToken } : {}),
        },
      },
      (res) => {
        const socket = res.socket as TLSSocket | null;
        try {
          const peerRaw = socket?.getPeerCertificate(true).raw as Buffer | undefined;
          const fp = peerRaw === undefined ? undefined : spkiFingerprintFromDerCert(peerRaw);
          if (fp !== device.profile.serverCertFingerprint) {
            reject(new Error("pinned gateway fingerprint mismatch"));
            req.destroy();
            return;
          }
        } catch {
          reject(new Error("could not verify the pinned gateway certificate"));
          req.destroy();
          return;
        }
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => { resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }); });
      },
    );
    req.on("error", reject);
    if (options.bodyText !== undefined) req.write(options.bodyText);
    req.end();
  });
}

export interface ShimHandle {
  readonly port: number;
  readonly close: () => Promise<void>;
}

// DD7: the loopback MCP channel. Local IDE/agent processes point their
// ordinary MetaVault MCP/agent config at http://127.0.0.1:<port>; the shim
// forwards ONLY the gateway-allowlisted routes over the pinned mTLS device
// session. The agent token is supplied per request by the local client and
// forwarded; every other client header is dropped.
export function startShim(options: {
  profileDir: string;
  port: number;
  host?: string;
}): Promise<ShimHandle> {
  const host = options.host ?? "127.0.0.1";
  if (host !== "127.0.0.1" && host !== "::1" && host !== "localhost") {
    return Promise.reject(new Error("shim host must be loopback"));
  }
  const device = loadDeviceProfile(options.profileDir);
  const server: HttpServer = createHttpServer((req, res) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? "/", "http://127.0.0.1");
        const method = req.method ?? "GET";
        if (!isAllowlisted(method, url.pathname)) {
          res.writeHead(403, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: { _tag: "Forbidden", message: "route not exposed to remote devices" } }));
          return;
        }
        const chunks: Buffer[] = [];
        for await (const chunk of req) {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
        }
        const bodyText = chunks.length > 0 ? Buffer.concat(chunks).toString("utf8") : undefined;
        const tokenHeader = req.headers["x-metavault-agent-token"];
        const agentToken = Array.isArray(tokenHeader) ? tokenHeader[0] : tokenHeader;
        const upstream = await pinnedRequest(device, {
          method,
          path: url.pathname,
          ...(bodyText !== undefined ? { bodyText } : {}),
          ...(agentToken !== undefined && agentToken !== "" ? { agentToken } : {}),
        });
        res.writeHead(upstream.status, { "content-type": "application/json" });
        res.end(upstream.body);
      } catch {
        if (!res.headersSent) {
          res.writeHead(502, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: { _tag: "BadGateway", message: "remote vault unreachable" } }));
        } else {
          res.end();
        }
      }
    })();
  });
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(options.port, host, () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("shim failed to bind"));
        return;
      }
      resolve({
        port: address.port,
        close: () => new Promise<void>((done) => { server.close(() => { done(); }); }),
      });
    });
  });
}
