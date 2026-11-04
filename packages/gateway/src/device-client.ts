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
import { createHash, randomBytes, timingSafeEqual, X509Certificate } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { request as httpsRequest } from "node:https";
import { join, resolve, sep } from "node:path";
import type { TLSSocket } from "node:tls";
import { computePairingSas, PAIRING_EXPORTER_LABEL, PAIRING_EXPORTER_LENGTH } from "../../core/src/pairing.js";
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

// Owner-only enforcement. POSIX mode bits are real protection there; on
// Windows they are a no-op, so owner-only ACLs are applied with icacls and
// then VERIFIED by parsing the effective ACL: inheritance stripping alone
// does not remove another principal's preexisting explicit grant, and an
// icacls exit code alone is never accepted as proof.
export interface IcaclsRun {
  (args: readonly string[]): string;
}

const defaultIcaclsRun: IcaclsRun = (args) =>
  execFileSync("icacls", [...args], { encoding: "utf8" });

// Parses icacls output into (principal, permissions) ACE entries. The
// first ACE line carries the queried path as a prefix; continuation ACE
// lines are indented. Anything unrecognized is kept as an opaque principal
// so verification fails closed rather than silently ignoring an ACE.
export function parseIcaclsAces(output: string, path?: string): { principal: string; permissions: string }[] {
  const aces: { principal: string; permissions: string }[] = [];
  for (const rawLine of output.split("\n")) {
    let line = rawLine;
    if (path !== undefined && line.startsWith(`${path} `)) {
      line = line.slice(path.length + 1);
    }
    line = line.trim();
    if (line === "" || !line.includes(":")) continue;
    const match = line.match(/^(.+?):(\([^)]*\)(?:\([^)]*\))*)\s*$/);
    if (match === null) {
      aces.push({ principal: line, permissions: "" });
      continue;
    }
    const principal = match[1] ?? "";
    const permissions = match[2] ?? "";
    if (principal !== "") {
      aces.push({ principal, permissions });
    }
  }
  return aces;
}

// Well-known principals that must never appear on device credential
// material, whatever name the locale gives them.
const WELL_KNOWN_FOREIGN_SIDS = new Set(["S-1-5-18", "S-1-5-32-544", "S-1-1-0", "S-1-5-11"]);

// True only when every ACE in the output belongs to the expected user.
// Identity is matched by exact name, DOMAIN\\name suffix, or SID when
// provided (localized/domain account names can defeat name matching).
export function isOwnerOnlyAcl(
  icaclsOutput: string,
  expectedUser: string,
  path?: string,
  userSid?: string,
): boolean {
  const aces = parseIcaclsAces(icaclsOutput, path);
  if (aces.length === 0) return false;
  const expected = expectedUser.toLowerCase();
  const sid = userSid?.toUpperCase();
  return aces.every((ace) => {
    const principal = ace.principal.toLowerCase();
    if (WELL_KNOWN_FOREIGN_SIDS.has(ace.principal.toUpperCase())) return false;
    if (sid !== undefined && ace.principal.toUpperCase() === sid) return true;
    return principal === expected || principal.endsWith(`\\${expected}`);
  });
}

export interface HardenOptions {
  // SID of the current user (from `whoami /user`); matched in addition to
  // the account name so localized or domain-qualified names cannot slip by.
  userSid?: string | undefined;
  // Resolved absolute roots the path must live under. ACL-reset operations
  // are never applied outside these roots, so an arbitrary user-selected
  // existing directory cannot be silently re-ACLed.
  allowedRoots: string[];
}

function assertWithinRoots(path: string, allowedRoots: string[]): void {
  const resolved = resolve(path).toLowerCase();
  const inside = allowedRoots.some((root) => {
    const r = resolve(root).toLowerCase();
    return resolved === r || resolved.startsWith(r.endsWith(sep) ? r : r + sep);
  });
  if (!inside) {
    throw new Error(`refusing to modify ACLs outside the device credential root: ${path}`);
  }
}

export function hardenOwnerOnly(
  path: string,
  isDir: boolean,
  platform: NodeJS.Platform = process.platform,
  run: IcaclsRun = defaultIcaclsRun,
  user: string = process.env["USERNAME"] ?? "",
  opts?: HardenOptions,
): void {
  if (opts !== undefined) {
    assertWithinRoots(path, opts.allowedRoots);
  }
  if (platform === "win32") {
    if (user === "") {
      throw new Error("cannot harden device credentials: USERNAME is unknown");
    }
    // Reset to inherited defaults (drops stray explicit grants), strip
    // inheritance, grant the current user alone - then verify the result.
    // NOTE: exit codes are never trusted; the effective ACE list decides.
    run([path, "/reset"]);
    run([path, "/inheritance:r"]);
    run([path, "/grant:r", `${user}:(F)`]);
    const verified = run([path]);
    if (!isOwnerOnlyAcl(verified, user, path, opts?.userSid)) {
      throw new Error(`refusing to store device credentials: could not make ${path} owner-only`);
    }
    return;
  }
  chmodSync(path, isDir ? 0o700 : 0o600);
  const mode = statSync(path).mode & 0o777;
  const expected = isDir ? 0o700 : 0o600;
  if (mode !== expected) {
    throw new Error(`refusing to store device credentials without owner-only permissions on ${path}`);
  }
}

// Best-effort current-user SID for SID-aware ACL matching. Returns
// undefined when unavailable (non-Windows or whoami failed); name matching
// still applies, and docs label the gate pending on-Windows validation.
export function currentWindowsUserSid(): string | undefined {
  if (process.platform !== "win32") return undefined;
  try {
    const out = execFileSync("whoami", ["/user", "/fo", "csv", "/nh"], { encoding: "utf8" });
    const match = out.match(/"(S-1-5-21-[0-9-]+)"/);
    return match?.[1];
  } catch {
    return undefined;
  }
}

export function saveDeviceProfile(dir: string, profile: DeviceProfile, material: PairingResult, shimToken: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const sid = currentWindowsUserSid();
  const opts: HardenOptions = sid === undefined ? { allowedRoots: [resolve(dir)] } : { allowedRoots: [resolve(dir)], userSid: sid };
  hardenOwnerOnly(dir, true, process.platform, undefined, undefined, opts);
  writeFileSync(join(dir, "key.pem"), material.keyPem, { mode: 0o600 });
  writeFileSync(join(dir, "cert.pem"), material.certPem, { mode: 0o600 });
  writeFileSync(join(dir, "ca.pem"), material.caCertPem, { mode: 0o600 });
  writeFileSync(join(dir, "device.json"), JSON.stringify(profile, null, 2) + "\n", { mode: 0o600 });
  writeFileSync(join(dir, "shim-token"), shimToken + "\n", { mode: 0o600 });
  for (const file of ["key.pem", "cert.pem", "ca.pem", "device.json", "shim-token"]) {
    hardenOwnerOnly(join(dir, file), false, process.platform, undefined, undefined, opts);
  }
  // Parent path is verified, never re-ACLed: it may be a user-selected
  // existing directory, so only fail closed when it is not owner-only.
  verifyOwnerOnlyParent(dir);
}

// Broad principals that must never appear on a credential parent directory,
// by SID (locale-proof). Well-known names are also rejected because icacls
// prints names, not SIDs, when the SID maps to an account.
const BROAD_PARENT_SIDS = new Set(["S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546", "S-1-5-7"]);
const BROAD_PARENT_NAMES = new Set(["everyone", "authenticated users", "builtin\\users", "builtin\\guests", "anonymous logon"]);

// The credential directory and its files are strictly owner-only; the
// parent is verify-only (we never re-ACL a directory we did not create) and
// may legitimately carry SYSTEM/Administrators grants on standard profile
// locations - but never broad principals like Everyone.
export function isParentAclSafe(icaclsOutput: string, path?: string): boolean {
  const aces = parseIcaclsAces(icaclsOutput, path);
  if (aces.length === 0) return false;
  return aces.every((ace) => {
    if (BROAD_PARENT_SIDS.has(ace.principal.toUpperCase())) return false;
    return !BROAD_PARENT_NAMES.has(ace.principal.toLowerCase());
  });
}

function verifyOwnerOnlyParent(dir: string): void {
  const parent = resolve(dir, "..");
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
  const out = defaultIcaclsRun([parent]);
  if (!isParentAclSafe(out, parent)) {
    throw new Error(`refusing to store device credentials: parent directory ${parent} grants broad access`);
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
