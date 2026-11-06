// MetaVault remote access gateway (WP4): a small sibling process that
// terminates mTLS 1.3 device sessions and forwards ONLY an allowlisted,
// safe-direction subset of agent routes to the loopback daemon. It fails
// closed: no valid, active, known device certificate means no forwarding,
// and every forwarded request is stamped with the authenticated device
// identity plus the loopback gateway secret so the daemon can tell a real
// gateway stamp from a local spoof.
//
// Human-decision routes (approve/deny/unlock/settings/credentials/agents/
// policies/audit/pending and everything not on the allowlist) are rejected
// here with 403 before any daemon contact. A compromised remote machine
// can therefore never approve its own requests or read vault metadata.
import { createHash, createHmac, randomBytes } from "node:crypto";
import { X509Certificate } from "node:crypto";
import { type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import type { TLSSocket } from "node:tls";
import {
  PAIRING_EXPORTER_LABEL,
  PAIRING_EXPORTER_LENGTH,
  computePairingSas,
} from "../../core/src/pairing.js";
import { spkiFingerprintFromPublicKeyPem } from "../../core/src/vault-ca.js";

export const GATEWAY_ALLOWLIST: readonly { method: string; pattern: RegExp }[] = [
  { method: "GET", pattern: /^\/health$/ },
  { method: "GET", pattern: /^\/aliases$/ },
  { method: "POST", pattern: /^\/request$/ },
  { method: "GET", pattern: /^\/grants\/[^/]+$/ },
  { method: "POST", pattern: /^\/grants\/[^/]+\/result$/ },
  { method: "POST", pattern: /^\/enrollments$/ },
  { method: "GET", pattern: /^\/enrollments\/[^/]+$/ },
  { method: "POST", pattern: /^\/agent-registrations$/ },
  { method: "POST", pattern: /^\/agent-registrations\/[^/]+\/claim$/ },
  { method: "POST", pattern: /^\/revoke$/ },
];

export function isAllowlisted(method: string, path: string): boolean {
  return GATEWAY_ALLOWLIST.some((entry) => entry.method === method && entry.pattern.test(path));
}

export interface DeviceStatus {
  readonly known: boolean;
  readonly revoked: boolean;
  readonly deviceId?: string;
  readonly name?: string;
}

export interface GatewayBackend {
  readonly deviceStatus: (fingerprint: string) => Promise<DeviceStatus>;
  // True only while a live, unconfirmed, unexpired vault-side pairing
  // session exists. The pairing listener is inert otherwise.
  readonly pairingActive: () => Promise<boolean>;
  readonly pairBegin: (input: {
    code: string;
    deviceName: string;
    platform: string;
    clientPublicKeyPem: string;
    clientNonce: string;
  }) => Promise<{ pairingId: string; serverNonce: string }>;
  readonly pairSas: (pairingId: string, sas: string) => Promise<void>;
  readonly pairStatus: (
    pairingId: string,
  ) => Promise<{ status: string; certificatePem?: string; caCertPem?: string }>;
}

export interface GatewayOptions {
  readonly caCertPem: string;
  readonly serverCertPem: string;
  readonly serverKeyPem: string;
  readonly backend: GatewayBackend;
  // Loopback daemon base URL the gateway proxies to.
  readonly daemonBaseUrl: string;
  // Shared loopback secret stamped on every forwarded request.
  readonly gatewaySecret: string;
  // Transport label recorded in the daemon audit trail (e.g. "loopback"
  // or "overlay"). A single word, never interface inventory.
  readonly transport: string;
  readonly maxRequestsPerMinutePerDevice?: number;
  readonly maxPairingAttemptsPerMinutePerAddress?: number;
  // Global cap on pairing attempts across all source addresses, so a
  // distributed code brute-force cannot scale with address count.
  readonly maxPairingAttemptsPerMinuteGlobal?: number;
  // /pair/status carries no secret (the 128-bit pairingId comes from a
  // successful begin), so it gets its own, looser budget: a human-paced
  // comparison with backoff polling must never exhaust the brute-force
  // budget that guards code entry.
  readonly maxPairStatusPerMinutePerAddress?: number;
}

interface RateBucket {
  count: number;
  windowStartMs: number;
}

function makeRateLimiter(limitPerMinute: number): (key: string) => boolean {
  const buckets = new Map<string, RateBucket>();
  return (key: string): boolean => {
    const now = Date.now();
    const bucket = buckets.get(key);
    if (bucket === undefined || now - bucket.windowStartMs >= 60_000) {
      buckets.set(key, { count: 1, windowStartMs: now });
      return true;
    }
    bucket.count += 1;
    return bucket.count <= limitPerMinute;
  };
}

function spkiFingerprintFromCert(cert: X509Certificate): string {
  const spki = cert.publicKey.export({ format: "der", type: "spki" });
  return createHash("sha256").update(spki).digest("hex");
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(payload);
}

function readBody(req: IncomingMessage, limit = 64 * 1024): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error("payload too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => { resolve(Buffer.concat(chunks).toString("utf8")); });
    req.on("error", reject);
  });
}

export interface GatewayServers {
  // Server-authenticated TLS 1.3, pairing routes only. No client
  // certificate is requested: the pairing leg has no trust anchor yet, so
  // authenticity comes ONLY from the human SAS comparison bound to this
  // exact TLS session via the exporter secret.
  readonly pairing: HttpsServer;
  // Strict mutual TLS 1.3: client certificates chaining to the vault CA
  // are required at the TLS handshake itself, so certificate-less and
  // foreign-CA connections are refused before any HTTP exists.
  readonly device: HttpsServer;
}

export function createGatewayServers(options: GatewayOptions): GatewayServers {
  const serverCert = new X509Certificate(options.serverCertPem);
  const serverCertFingerprint = spkiFingerprintFromCert(serverCert);
  const deviceLimiter = makeRateLimiter(options.maxRequestsPerMinutePerDevice ?? 60);
  const pairingLimiter = makeRateLimiter(options.maxPairingAttemptsPerMinutePerAddress ?? 10);
  const globalPairingLimiter = makeRateLimiter(options.maxPairingAttemptsPerMinuteGlobal ?? 30);
  const pairStatusLimiter = makeRateLimiter(options.maxPairStatusPerMinutePerAddress ?? 60);
  const daemonBase = options.daemonBaseUrl.replace(/\/+$/, "");

  async function handlePairingRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const socket = req.socket as TLSSocket;
    const url = new URL(req.url ?? "/", "https://gateway");
    const method = req.method ?? "GET";
    const path = url.pathname;
    const remoteAddress = socket.remoteAddress ?? "unknown";
    try {
      // Exactly two routes exist on this listener; every other path
      // fails closed, including allowlisted device routes.
      if (method !== "POST" || (path !== "/pair/begin" && path !== "/pair/status")) {
        json(res, 401, {
          error: { _tag: "Unauthorized", message: "pairing routes only on this listener" },
        });
        return;
      }
      if (path === "/pair/status") {
        if (!pairStatusLimiter(remoteAddress)) {
          json(res, 429, { error: { _tag: "RateLimited", message: "too many pairing status polls" } });
          return;
        }
      } else {
        if (!globalPairingLimiter("global")) {
          json(res, 429, { error: { _tag: "RateLimited", message: "too many pairing attempts (global)" } });
          return;
        }
        if (!pairingLimiter(remoteAddress)) {
          json(res, 429, { error: { _tag: "RateLimited", message: "too many pairing attempts (address)" } });
          return;
        }
        // Inert outside an explicit pairing window: without a live,
        // unconfirmed, unexpired vault-side session, /pair/begin refuses
        // before any body is read or code is compared.
        if (!(await options.backend.pairingActive())) {
          json(res, 403, {
            error: { _tag: "PairingFailed", message: "pairing is not open on the vault" },
          });
          return;
        }
      }
      const bodyText = await readBody(req);
      let body: Record<string, unknown>;
      try {
        body = JSON.parse(bodyText === "" ? "{}" : bodyText) as Record<string, unknown>;
      } catch {
        json(res, 400, { error: { _tag: "BadRequest", message: "invalid JSON" } });
        return;
      }
      if (path === "/pair/begin") {
        const code = body["code"];
        const deviceName = body["deviceName"];
        const platform = body["platform"];
        const clientPublicKeyPem = body["clientPublicKeyPem"];
        const clientNonce = body["clientNonce"];
        if (
          typeof code !== "string" ||
          typeof deviceName !== "string" ||
          typeof clientPublicKeyPem !== "string" ||
          typeof clientNonce !== "string" ||
          code === "" ||
          clientPublicKeyPem.length > 4096
        ) {
          json(res, 400, { error: { _tag: "BadRequest", message: "missing pairing fields" } });
          return;
        }
        let clientFingerprint: string;
        try {
          clientFingerprint = spkiFingerprintFromPublicKeyPem(clientPublicKeyPem);
        } catch {
          json(res, 400, { error: { _tag: "BadRequest", message: "invalid client public key" } });
          return;
        }
        const announcedAddress = device.address();
        const announcedDevicePort =
          announcedAddress !== null && typeof announcedAddress === "object" ? announcedAddress.port : 0;
        if (announcedDevicePort === 0) {
          // The strict-mTLS device listener must exist before any pairing
          // is answered: a certificate could otherwise be issued for a
          // transport that does not exist yet.
          json(res, 502, { error: { _tag: "BadGateway", message: "device listener is not bound" } });
          return;
        }
        try {
          const begun = await options.backend.pairBegin({
            code,
            deviceName,
            platform: typeof platform === "string" ? platform : "",
            clientPublicKeyPem,
            clientNonce,
          });
          // SAS: bound to this exact TLS session via the exporter,
          // both public identities, the code and both nonces. It is
          // shown on both screens and never transmitted.
          const exporter = socket.exportKeyingMaterial(
            PAIRING_EXPORTER_LENGTH,
            PAIRING_EXPORTER_LABEL,
            Buffer.alloc(0),
          );
          const sas = computePairingSas({
            exporterSecret: exporter,
            serverCertFingerprint,
            clientPublicKeyFingerprint: clientFingerprint,
            code,
            serverNonce: begun.serverNonce,
            clientNonce,
            devicePort: announcedDevicePort,
          });
          await options.backend.pairSas(begun.pairingId, sas);
          json(res, 200, {
            pairingId: begun.pairingId,
            serverNonce: begun.serverNonce,
            serverCertFingerprint,
            devicePort: announcedDevicePort,
          });
        } catch {
          json(res, 403, {
            error: { _tag: "PairingFailed", message: "pairing unavailable or code invalid" },
          });
        }
        return;
      }
      // /pair/status
      const pairingId = body["pairingId"];
      if (typeof pairingId !== "string" || pairingId.length > 64) {
        json(res, 400, { error: { _tag: "BadRequest", message: "missing pairingId" } });
        return;
      }
      const status = await options.backend.pairStatus(pairingId);
      // Announce the strict-mTLS device port so the freshly paired device
      // knows where its certificate is required. The port is learned at
      // runtime so ephemeral test ports work unchanged.
      const deviceAddress = device.address();
      const devicePort = deviceAddress !== null && typeof deviceAddress === "object" ? deviceAddress.port : undefined;
      json(res, 200, devicePort === undefined ? status : { ...status, devicePort });
      return;
    } catch (err) {
      if (!res.headersSent) {
        json(res, 502, {
          error: {
            _tag: "BadGateway",
            message:
              err instanceof Error && err.message === "payload too large"
                ? "payload too large"
                : "gateway upstream failure",
          },
        });
      } else {
        res.end();
      }
    }
  }

  async function handleDeviceRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const socket = req.socket as TLSSocket;
    const url = new URL(req.url ?? "/", "https://gateway");
    const method = req.method ?? "GET";
    const path = url.pathname;
    try {
      // Unreachable under rejectUnauthorized: the handshake already
      // refused certificate-less and foreign-CA clients. Kept fail-closed.
      if (!socket.authorized) {
        json(res, 401, {
          error: { _tag: "Unauthorized", message: "a paired device certificate is required" },
        });
        return;
      }
      // Authenticated device session: the certificate chained to the
      // vault CA. Device identity is the SPKI fingerprint, re-checked
      // against the daemon's device table on EVERY request so
      // revocation takes effect immediately.
      const peerCert = new X509Certificate(socket.getPeerCertificate(true).raw);
      const fingerprint = spkiFingerprintFromCert(peerCert);
      const deviceStatus = await options.backend.deviceStatus(fingerprint);
      if (!deviceStatus.known || deviceStatus.revoked || deviceStatus.deviceId === undefined) {
        json(res, 403, { error: { _tag: "Forbidden", message: "device unknown or revoked" } });
        return;
      }
      const deviceId = deviceStatus.deviceId;
      if (!deviceLimiter(deviceId)) {
        json(res, 429, { error: { _tag: "RateLimited", message: "device rate limit exceeded" } });
        return;
      }
      if (!isAllowlisted(method, path)) {
        // Every non-allowlisted route fails closed here, including all
        // human-decision routes, /policies, /audit and /pending.
        json(res, 403, {
          error: { _tag: "Forbidden", message: "route not exposed to remote devices" },
        });
        return;
      }

      const bodyText = method === "POST" ? await readBody(req) : undefined;
      // Stamp the forwarded request: HMAC over device identity, method,
      // path, exact body bytes, timestamp and a single-use nonce. The
      // secret itself never crosses the wire, and the daemon rejects
      // stale, replayed or tampered stamps.
      const stampTs = Math.floor(Date.now() / 1000).toString();
      const stampNonce = randomBytes(16).toString("hex");
      const stampMac = createHmac("sha256", options.gatewaySecret)
        .update(
          [
            deviceId,
            options.transport,
            method,
            path,
            createHash("sha256").update(bodyText ?? "", "utf8").digest("hex"),
            stampTs,
            stampNonce,
          ].join("\n"),
          "utf8",
        )
        .digest("hex");
      const headers: Record<string, string> = {
        "content-type": "application/json",
        "x-metavault-device-id": deviceId,
        "x-metavault-transport": options.transport,
        "x-metavault-gateway-ts": stampTs,
        "x-metavault-gateway-nonce": stampNonce,
        "x-metavault-gateway-mac": stampMac,
      };
      // Only the agent token header is forwarded from the client. The
      // daemon token, client PID and any device headers the client sent
      // are stripped here, never passed through.
      const agentToken = req.headers["x-metavault-agent-token"];
      if (typeof agentToken === "string" && agentToken !== "") {
        headers["x-metavault-agent-token"] = agentToken;
      }
      // Grant outcome routes are receipt-gated on the daemon. The receipt
      // is not a vault secret; it is the single-request capability returned
      // with that agent's own /request answer.
      const grantReceipt = req.headers["x-metavault-grant-receipt"];
      if (typeof grantReceipt === "string" && grantReceipt !== "") {
        headers["x-metavault-grant-receipt"] = grantReceipt;
      }
      const upstream = await fetch(`${daemonBase}${path}${url.search}`, {
        method,
        headers,
        ...(bodyText !== undefined ? { body: bodyText } : {}),
      });
      const text = await upstream.text();
      res.writeHead(upstream.status, { "content-type": "application/json" });
      res.end(text);
    } catch (err) {
      if (!res.headersSent) {
        json(res, 502, {
          error: {
            _tag: "BadGateway",
            message:
              err instanceof Error && err.message === "payload too large"
                ? "payload too large"
                : "gateway upstream failure",
          },
        });
      } else {
        res.end();
      }
    }
  }

  // The device listener exists before the pairing listener so the pairing
  // handler can announce its bound port from /pair/status.
  const device = createHttpsServer(
    {
      cert: options.serverCertPem,
      key: options.serverKeyPem,
      ca: options.caCertPem,
      minVersion: "TLSv1.3",
      requestCert: true,
      rejectUnauthorized: true,
    },
    (req, res) => {
      void handleDeviceRequest(req, res);
    },
  );
  const pairing = createHttpsServer(
    {
      cert: options.serverCertPem,
      key: options.serverKeyPem,
      minVersion: "TLSv1.3",
    },
    (req, res) => {
      void handlePairingRequest(req, res);
    },
  );
  return { pairing, device };
}
