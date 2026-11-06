// MetaVault remote device client (WP5 / DD7): the device side of pairing,
// on-disk device credentials, and the loopback MCP-channel shim.
//
// Trust model:
// - The pairing leg runs on the gateway's dedicated pairing listener
//   (server-only TLS 1.3, no client certificate requested). The client
//   CANNOT validate the vault's identity on this leg: no trust anchor
//   exists yet and the certificate presented is not yet authenticated.
//   Authenticity comes ONLY from the human comparing the SAS shown here
//   with the SAS on the vault screen, and the vault-side human confirming
//   there. Nothing is issued before that comparison happens.
// - After pairing, all traffic is pinned: the vault CA is the only trust
//   anchor and the gateway server certificate's SPKI fingerprint must match
//   the fingerprint captured during pairing. There is no silent trust reset
//   and no persistent rejectUnauthorized: false.
// - Pairing codes, SAS values and session identifiers are never written to
//   logs or persisted; only the issued certificate, CA, key and fingerprint
//   land on disk, owner-only.
import { createHash, randomBytes, timingSafeEqual, X509Certificate } from "node:crypto";
import { tmpdir } from "node:os";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { Agent, request as httpsRequest } from "node:https";
import { basename, dirname, join, resolve, sep } from "node:path";
import type { TLSSocket } from "node:tls";
import { computePairingSas, PAIRING_EXPORTER_LABEL, PAIRING_EXPORTER_LENGTH } from "../../core/src/pairing.js";
import {
  canonicalPath,
  currentWindowsUserSid,
  defaultListAclSids,
  hardenOwnerOnly,
  type HardenOptions,
} from "../../core/src/owner-acl.js";
export {
  canonicalPath,
  currentWindowsUserSid,
  defaultListAclSids,
  defaultReadAclSddl,
  hardenOwnerOnly,
  type AclSidList,
  type HardenOptions,
  type IcaclsRun,
} from "../../core/src/owner-acl.js";
import { generateRsaKeyPairPem, spkiFingerprintFromPublicKeyPem } from "../../core/src/vault-ca.js";
import { isAllowlisted } from "./server.js";

// The client poll cadence: 1s, 2s, 4s, then a 5s cap. Exported so tests
// can prove the request budget against production gateway limits over a
// long human comparison without wall-clock sleeps.
export function nextPollDelay(currentMs: number, capMs: number): number {
  return Math.min(currentMs * 2, capMs);
}

export const PAIRING_POLL_START_MS = 1_000;
export const PAIRING_POLL_CAP_MS = 5_000;

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
  // Strict-mTLS device listener port announced by the gateway in
  // /pair/status. Required: after pairing, traffic never goes back to
  // the pairing port.
  readonly devicePort: number;
}

interface GatewayTlsResponse {
  status: number;
  body: string;
  exporter?: Buffer;
  peerFingerprint?: string;
}

// A fresh handshake every time. Session resumption can omit the peer
// certificate and the exporter the SAS is bound to.
const pairingAgent = new Agent({ keepAlive: false, maxCachedSessions: 0 });

function capturePairingTls(socket: TLSSocket | null | undefined): { exporter?: Buffer; peerFingerprint?: string } {
  if (socket === null || socket === undefined || typeof socket.getPeerCertificate !== "function") return {};
  let exporter: Buffer | undefined;
  try {
    exporter = socket.exportKeyingMaterial(PAIRING_EXPORTER_LENGTH, PAIRING_EXPORTER_LABEL, Buffer.alloc(0));
  } catch {
    exporter = undefined;
  }
  let peerFingerprint: string | undefined;
  try {
    const peer = socket.getPeerCertificate(false) as { raw?: Buffer };
    if (peer.raw !== undefined && peer.raw.length > 0) peerFingerprint = spkiFingerprintFromDerCert(peer.raw);
  } catch {
    peerFingerprint = undefined;
  }
  return {
    ...(exporter !== undefined ? { exporter } : {}),
    ...(peerFingerprint !== undefined ? { peerFingerprint } : {}),
  };
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
        agent: pairingAgent,
        headers: { "content-type": "application/json" },
      },
      (res) => {
        const captured = capturePairingTls((req.socket ?? res.socket) as TLSSocket | null);
        const exporter = captured.exporter;
        const peerFingerprint = captured.peerFingerprint;
        if (options.expectedServerFingerprint !== undefined && peerFingerprint !== options.expectedServerFingerprint) {
          reject(new PairingError("transport", "gateway certificate fingerprint mismatch: refusing to talk to an unpinned peer"));
          req.destroy();
          return;
        }
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
            ...(exporter !== undefined ? { exporter } : {}),
            ...(peerFingerprint !== undefined ? { peerFingerprint } : {}),
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
  if (begin.status !== 200 || begin.exporter === undefined || begin.peerFingerprint === undefined) {
    throw new PairingError("rejected", `the vault rejected pairing (wrong/expired code or pairing not open) [${String(begin.status)}]`);
  }
  const observedPeer = begin.peerFingerprint;
  const info = JSON.parse(begin.body) as { pairingId: string; serverNonce: string; serverCertFingerprint: string; devicePort?: number };
  if (info.serverCertFingerprint !== observedPeer) {
    throw new PairingError("transport", "gateway certificate fingerprint mismatch: refusing to talk to an unpinned peer");
  }
  if (typeof info.devicePort !== "number" || !Number.isInteger(info.devicePort) || info.devicePort < 1 || info.devicePort > 65535) {
    throw new PairingError("transport", "vault did not announce its mTLS device port");
  }
  const announcedDevicePort = info.devicePort;
  const sas = computePairingSas({
    exporterSecret: begin.exporter,
    serverCertFingerprint: info.serverCertFingerprint,
    clientPublicKeyFingerprint: spkiFingerprintFromPublicKeyPem(keys.publicKeyPem),
    code: options.code,
    serverNonce: info.serverNonce,
    clientNonce,
    // SAS-bound: a MITM rewriting the announced port breaks the human
    // comparison instead of redirecting the pinned transport.
    devicePort: announcedDevicePort,
  });
  options.onSas(sas);

  const deadline = Date.now() + (options.timeoutMs ?? 5 * 60_000);
  // Bounded backoff: gentle on the vault's pairing rate budget under
  // production limits, still responsive to a human comparison.
  let pollMs = options.pollIntervalMs ?? 1_000;
  const pollCap = options.pollIntervalMs ?? 5_000;
  for (;;) {
    if (Date.now() > deadline) {
      throw new PairingError("timeout", "pairing was not confirmed on the vault in time");
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs));
    pollMs = nextPollDelay(pollMs, pollCap);
    const status = await gatewayPost({
      host: options.host,
      port: options.port,
      path: "/pair/status",
      trustOnFirstUse: true,
      expectedServerFingerprint: observedPeer,
      body: { pairingId: info.pairingId },
    });
    if (status.status !== 200) {
      throw new PairingError("expired", "the pairing session is gone (canceled or replaced on the vault)");
    }
    const body = JSON.parse(status.body) as { status: string; certificatePem?: string; caCertPem?: string; devicePort?: number };
    if (body.status === "unknown") {
      // Canceled, replaced by a newer session, or expired on the vault.
      throw new PairingError("expired", "the pairing session is gone (canceled or replaced on the vault)");
    }
    if (body.status === "confirmed") {
      if (typeof body.certificatePem !== "string" || typeof body.caCertPem !== "string") {
        throw new PairingError("transport", "vault issued a malformed certificate bundle");
      }
      if (body.devicePort !== announcedDevicePort) {
        // The issuance-time port must equal the SAS-bound announcement
        // from /pair/begin; anything else is a tampered transcript.
        throw new PairingError("transport", "gateway changed its announced mTLS device port mid-pairing");
      }
      return {
        deviceId: `dev-${spkiFingerprintFromPublicKeyPem(keys.publicKeyPem).slice(0, 12)}`,
        keyPem: keys.privateKeyPem,
        certPem: body.certificatePem,
        caCertPem: body.caCertPem,
        serverCertFingerprint: info.serverCertFingerprint,
        devicePort: announcedDevicePort,
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


// Files this module manages inside a device credential directory. Anything
// else in a preexisting directory means the directory is not ours.
const KNOWN_DEVICE_FILES = new Set(["key.pem", "cert.pem", "ca.pem", "device.json", "shim-token"]);

export function saveDeviceProfile(dir: string, profile: DeviceProfile, material: PairingResult, shimToken: string): void {
  // Ownership/scope guard BEFORE any ACL change: the caller must pass the
  // dedicated app-owned credential directory. A preexisting directory with
  // unrelated contents is refused outright - we never re-ACL an arbitrary
  // user-selected folder.
  if (existsSync(dir)) {
    const foreign = readdirSync(dir).filter((entry) => !KNOWN_DEVICE_FILES.has(entry));
    if (foreign.length > 0) {
      throw new Error(`refusing to store device credentials in a directory with unrelated contents: ${dir}`);
    }
  }
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const opts: HardenOptions = { allowedRoots: [canonicalPath(dir)] };
  if (process.platform === "win32") {
    const sid = currentWindowsUserSid();
    if (sid === undefined) {
      throw new Error("cannot store device credentials on Windows: current user SID is unavailable");
    }
    opts.userSid = sid;
  }
  hardenOwnerOnly(dir, true, process.platform, undefined, opts);
  writeFileSync(join(dir, "key.pem"), material.keyPem, { mode: 0o600 });
  writeFileSync(join(dir, "cert.pem"), material.certPem, { mode: 0o600 });
  writeFileSync(join(dir, "ca.pem"), material.caCertPem, { mode: 0o600 });
  writeFileSync(join(dir, "device.json"), JSON.stringify(profile, null, 2) + "\n", { mode: 0o600 });
  writeFileSync(join(dir, "shim-token"), shimToken + "\n", { mode: 0o600 });
  for (const file of KNOWN_DEVICE_FILES) {
    hardenOwnerOnly(join(dir, file), false, process.platform, undefined, opts);
  }
  // Parent path is verified, never re-ACLed: it may be a user-selected
  // existing directory, so only fail closed when it grants broad access.
  verifyOwnerOnlyParent(dir, opts);
}

// Principals permitted on the credential PARENT directory (verify-only):
// the owner plus the platform-standard SYSTEM/Administrators found on
// standard profile locations. Everyone, Authenticated Users, Users,
// Guests and any other principal fail the check.
const ALLOWED_PARENT_SIDS = new Set(["S-1-5-18", "S-1-5-32-544"]);

export function isParentAclSafe(sids: readonly string[], userSid: string): boolean {
  if (sids.length === 0) return false;
  const owner = userSid.toUpperCase();
  return sids.every((sid) => {
    const normalized = sid.toUpperCase();
    return normalized === owner || ALLOWED_PARENT_SIDS.has(normalized);
  });
}

function verifyOwnerOnlyParent(dir: string, opts: HardenOptions): void {
  const parent = dirname(resolve(dir));
  if (process.platform !== "win32") {
    // A 0700 credential dir is a hard boundary on POSIX; the parent only
    // matters for delete/rename rights. Reject group/world-writable parents
    // unless sticky (e.g. /tmp 1777, where only the owner can unlink).
    const mode = statSync(parent).mode & 0o1777;
    const groupOrOtherWrite = (mode & 0o022) !== 0;
    const sticky = (mode & 0o1000) !== 0;
    if (groupOrOtherWrite && !sticky) {
      throw new Error(`refusing to store device credentials: parent directory ${parent} is writable by others`);
    }
    return;
  }
  const sid = opts.userSid ?? "";
  const listSids = opts.listSids ?? defaultListAclSids;
  const parentSids = listSids(parent);
  if (!isParentAclSafe(parentSids, sid)) {
    throw new Error(`refusing to store device credentials: parent directory ${parent} grants broad access (effective ACL SIDs: ${parentSids.join(", ") || "none"})`);
  }
}

export function generateShimToken(): string {
  return `mvshim_${randomBytes(24).toString("hex")}`;
}

export interface LoadedDevice {
  readonly profile: DeviceProfile;
  readonly keyPem: string;
  readonly certPem: string;
  readonly caCertPem: string;
  readonly shimToken: string;
}

export function loadDeviceProfile(dir: string): LoadedDevice {
  const profile = JSON.parse(readFileSync(join(dir, "device.json"), "utf8")) as DeviceProfile;
  return {
    profile,
    keyPem: readFileSync(join(dir, "key.pem"), "utf8"),
    certPem: readFileSync(join(dir, "cert.pem"), "utf8"),
    caCertPem: readFileSync(join(dir, "ca.pem"), "utf8"),
    shimToken: readFileSync(join(dir, "shim-token"), "utf8").trim(),
  };
}

// Pinned request after enrollment: vault CA is the only anchor and the
// server SPKI fingerprint must match the pinned one.
function pinnedRequest(device: LoadedDevice, options: {
  method: string;
  path: string;
  bodyText?: string;
  agentToken?: string;
  grantReceipt?: string;
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
          ...(options.grantReceipt !== undefined ? { "x-metavault-grant-receipt": options.grantReceipt } : {}),
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
  // Loopback is not an authentication boundary: any local process (or a
  // browser page, via DNS rebinding) can reach this port. Every request
  // must carry the owner-only shim token, present a loopback Host header,
  // and must not look like a cross-site browser request.
  const shimToken = device.shimToken;
  const server: HttpServer = createHttpServer((req, res) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? "/", "http://127.0.0.1");
        const method = req.method ?? "GET";
        const hostHeader = req.headers.host ?? "";
        const hostOk = /^\s*(127\.0\.0\.1|localhost|\[::1\])(:\d+)?\s*$/i.test(hostHeader);
        const origin = req.headers["origin"];
        const fetchSite = req.headers["sec-fetch-site"];
        const shimTokenHeader = req.headers["x-metavault-shim-token"];
        const presented = Array.isArray(shimTokenHeader) ? shimTokenHeader[0] : shimTokenHeader;
        if (!hostOk || origin !== undefined || (fetchSite !== undefined && fetchSite !== "none")) {
          res.writeHead(403, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: { _tag: "Forbidden", message: "not a local shim client" } }));
          return;
        }
        const presentedBuf = Buffer.from(presented ?? "", "utf8");
        const expectedBuf = Buffer.from(shimToken, "utf8");
        if (presentedBuf.length !== expectedBuf.length || !timingSafeEqual(presentedBuf, expectedBuf)) {
          res.writeHead(401, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: { _tag: "Unauthorized", message: "shim token required" } }));
          return;
        }
        if (!isAllowlisted(method, url.pathname)) {
          res.writeHead(403, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: { _tag: "Forbidden", message: "route not exposed to remote devices" } }));
          return;
        }
        const chunks: Buffer[] = [];
        let received = 0;
        for await (const chunk of req) {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
          received += buf.length;
          if (received > 65_536) {
            res.writeHead(413, { "content-type": "application/json" });
            res.end(JSON.stringify({ error: { _tag: "PayloadTooLarge", message: "request body too large" } }));
            return;
          }
          chunks.push(buf);
        }
        const bodyText = chunks.length > 0 ? Buffer.concat(chunks).toString("utf8") : undefined;
        const tokenHeader = req.headers["x-metavault-agent-token"];
        const agentToken = Array.isArray(tokenHeader) ? tokenHeader[0] : tokenHeader;
        const receiptHeader = req.headers["x-metavault-grant-receipt"];
        const grantReceipt = Array.isArray(receiptHeader) ? receiptHeader[0] : receiptHeader;
        const upstream = await pinnedRequest(device, {
          method,
          path: `${url.pathname}${url.search}`,
          ...(bodyText !== undefined ? { bodyText } : {}),
          ...(agentToken !== undefined && agentToken !== "" ? { agentToken } : {}),
          ...(grantReceipt !== undefined && grantReceipt !== "" ? { grantReceipt } : {}),
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
