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
import { createHash } from "node:crypto";
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
  { method: "POST", pattern: /^\/enrollments$/ },
  { method: "GET", pattern: /^\/enrollments\/[^/]+$/ },
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

export function createGatewayServer(options: GatewayOptions): HttpsServer {
  const serverCert = new X509Certificate(options.serverCertPem);
  const serverCertFingerprint = spkiFingerprintFromCert(serverCert);
  const deviceLimiter = makeRateLimiter(options.maxRequestsPerMinutePerDevice ?? 60);
  const pairingLimiter = makeRateLimiter(options.maxPairingAttemptsPerMinutePerAddress ?? 10);
  const daemonBase = options.daemonBaseUrl.replace(/\/+$/, "");

  const server = createHttpsServer(
    {
      cert: options.serverCertPem,
      key: options.serverKeyPem,
      ca: options.caCertPem,
      // TLS 1.3 only, mutual authentication requested. Rejection is done at
      // the application layer so pairing clients (no cert yet) can still
      // establish an encrypted session for the pairing handshake only.
      minVersion: "TLSv1.3",
      requestCert: true,
      rejectUnauthorized: false,
    },
    (req, res) => {
      void (async () => {
        const socket = req.socket as TLSSocket;
        const url = new URL(req.url ?? "/", "https://gateway");
        const method = req.method ?? "GET";
        const path = url.pathname;
        const remoteAddress = socket.remoteAddress ?? "unknown";

        try {
          if (!socket.authorized) {
            // No valid device certificate: pairing routes only, strictly
            // rate-limited. Every other path fails closed.
            if (method !== "POST" || (path !== "/pair/begin" && path !== "/pair/status")) {
              json(res, 401, {
                error: { _tag: "Unauthorized", message: "a paired device certificate is required" },
              });
              return;
            }
            if (!pairingLimiter(remoteAddress)) {
              json(res, 429, { error: { _tag: "RateLimited", message: "too many pairing attempts" } });
              return;
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
                });
                await options.backend.pairSas(begun.pairingId, sas);
                json(res, 200, {
                  pairingId: begun.pairingId,
                  serverNonce: begun.serverNonce,
                  serverCertFingerprint,
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
            json(res, 200, status);
            return;
          }

          // Authenticated device session: the certificate chained to the
          // vault CA. Device identity is the SPKI fingerprint, re-checked
          // against the daemon's device table on EVERY request so
          // revocation takes effect immediately.
          const peerCert = new X509Certificate(socket.getPeerCertificate(true).raw);
          const fingerprint = spkiFingerprintFromCert(peerCert);
          const device = await options.backend.deviceStatus(fingerprint);
          if (!device.known || device.revoked || device.deviceId === undefined) {
            json(res, 403, { error: { _tag: "Forbidden", message: "device unknown or revoked" } });
            return;
          }
          if (!deviceLimiter(device.deviceId)) {
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
          const headers: Record<string, string> = {
            "content-type": "application/json",
            "x-metavault-gateway-secret": options.gatewaySecret,
            "x-metavault-device-id": device.deviceId,
            "x-metavault-transport": options.transport,
          };
          // Only the agent token header is forwarded from the client. The
          // daemon token, client PID and any device headers the client sent
          // are stripped here, never passed through.
          const agentToken = req.headers["x-metavault-agent-token"];
          if (typeof agentToken === "string" && agentToken !== "") {
            headers["x-metavault-agent-token"] = agentToken;
          }
          const upstream = await fetch(`${daemonBase}${path}`, {
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
      })();
    },
  );
  return server;
}
