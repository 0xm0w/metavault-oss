// End-to-end gateway + daemon security tests (WP4/WP5/WP6 core):
// allowlist completeness, fail-closed device authentication, spoof
// resistance, device-bound tokens, device ceilings, pairing handshake
// (single-use codes, SAS transcript binding, revocation).
import { mkdtempSync, rmSync } from "node:fs";
import { createServer as createHttpsServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import type { TLSSocket } from "node:tls";
import type { Server } from "node:http";
import type { Server as HttpsServer } from "node:https";
import { Effect, Layer } from "effect";
import { expect } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import {
  ensureGatewayCertificate,
  ensureVaultCa,
  generateRsaKeyPairPem,
  signLeafCertificate,
  spkiFingerprintFromPublicKeyPem,
} from "../../core/src/vault-ca.js";
import { computePairingSas, PAIRING_EXPORTER_LABEL, PAIRING_EXPORTER_LENGTH } from "../../core/src/pairing.js";
import { createVaultHttpServer } from "../../daemon/src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../../daemon/src/service.js";
import { makeDaemonBackend } from "../src/daemon-backend.js";
import { createGatewayServer, GATEWAY_ALLOWLIST } from "../src/server.js";

export const MASTER_KEY = Buffer.alloc(32, 7);
export const GATEWAY_SECRET = "test-gateway-secret";
export const DAEMON_TOKEN = "test-daemon-token";

export const BrainLowRisk = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({
      risk: "low" as const,
      recommendedScope: "charges.read",
      requireApproval: true,
      explanation: "safe test read",
    }),
});
export const FakeConnector = Layer.succeed(Connector, {
  execute: (_alias, scope) => Effect.succeed({ scope }),
});

export interface GwResponse {
  status: number;
  body: string;
  exporter?: Buffer;
  localPort?: number;
}

export function gwRequest(options: {
  port: number;
  method: string;
  path: string;
  body?: unknown;
  cert?: string;
  key?: string;
  ca?: string;
  agentToken?: string;
  tlsRejectUnauthorized?: boolean;
  agent?: HttpsAgent;
}): Promise<GwResponse> {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      {
        host: "127.0.0.1",
        port: options.port,
        method: options.method,
        path: options.path,
        ca: options.ca,
        cert: options.cert,
        key: options.key,
        rejectUnauthorized: options.tlsRejectUnauthorized ?? false,
        ...(options.agent !== undefined ? { agent: options.agent } : {}),
        headers: {
          "content-type": "application/json",
          ...(options.agentToken !== undefined ? { "x-metavault-agent-token": options.agentToken } : {}),
        },
      },
      (res) => {
        // Capture the socket now: it may already be detached ("null") by
        // the time the body "end" event fires.
        const socket = res.socket as TLSSocket | null;
        let exporter: Buffer | undefined;
        let localPort: number | undefined;
        try {
          exporter = socket?.exportKeyingMaterial(PAIRING_EXPORTER_LENGTH, PAIRING_EXPORTER_LABEL, Buffer.alloc(0));
          localPort = socket?.localPort;
        } catch {
          exporter = undefined;
          localPort = undefined;
        }
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
            ...(exporter !== undefined ? { exporter } : {}),
            ...(localPort !== undefined ? { localPort } : {}),
          });
        });
      },
    );
    req.on("error", reject);
    if (options.body !== undefined) req.write(JSON.stringify(options.body));
    req.end();
  });
}

export function stampHeaders(fields: {
  deviceId: string;
  method: string;
  path: string;
  bodyText?: string;
  secret?: string;
  transport?: string;
  ts?: string;
  nonce?: string;
}): Record<string, string> {
  const ts = fields.ts ?? Math.floor(Date.now() / 1000).toString();
  const nonce = fields.nonce ?? randomBytes(16).toString("hex");
  const transport = fields.transport ?? "loopback";
  const bodyHash = createHash("sha256").update(fields.bodyText ?? "", "utf8").digest("hex");
  const mac = createHmac("sha256", fields.secret ?? GATEWAY_SECRET)
    .update([fields.deviceId, transport, fields.method, fields.path, bodyHash, ts, nonce].join("\n"), "utf8")
    .digest("hex");
  return {
    "x-metavault-device-id": fields.deviceId,
    "x-metavault-transport": transport,
    "x-metavault-gateway-ts": ts,
    "x-metavault-gateway-nonce": nonce,
    "x-metavault-gateway-mac": mac,
  };
}

export interface Stack {
  daemon: Server;
  gateway: HttpsServer;
  service: VaultServiceService;
  daemonBase: string;
  gatewayPort: number;
  ca: { keyPem: string; certPem: string };
  gwCert: { keyPem: string; certPem: string };
  dir: string;
  cursorToken: string;
}

export async function makeStack(): Promise<Stack> {
  const dir = mkdtempSync(join(tmpdir(), "mv-gw-test-"));
  const ca = ensureVaultCa(dir);
  const gwCert = ensureGatewayCertificate(dir, ca);
  const service = await Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* VaultService;
      yield* svc.seedCredential("stripe", "charges.read", "sk_test_123");
      yield* svc.seedCredential("stripe-write", "charges.write", "sk_test_456");
      return svc;
    }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: MASTER_KEY, vaultCa: ca })),
      Effect.provide(Layer.mergeAll(VaultStoreTest(MASTER_KEY), BrainLowRisk, FakeConnector)),
    ),
  );
  const cursor = await Effect.runPromise(service.registerAgent("cursor", "Cursor"));
  const daemon = createVaultHttpServer(service, { daemonToken: DAEMON_TOKEN, gatewaySecret: GATEWAY_SECRET, vaultDir: dir });
  await new Promise<void>((resolve) => daemon.listen(0, "127.0.0.1", resolve));
  const daemonAddress = daemon.address();
  if (daemonAddress === null || typeof daemonAddress === "string") throw new Error("no daemon port");
  const daemonBase = `http://127.0.0.1:${String(daemonAddress.port)}`;
  const gateway = createGatewayServer({
    caCertPem: ca.certPem,
    serverCertPem: gwCert.certPem,
    serverKeyPem: gwCert.keyPem,
    backend: makeDaemonBackend(daemonBase, GATEWAY_SECRET),
    daemonBaseUrl: daemonBase,
    gatewaySecret: GATEWAY_SECRET,
    transport: "loopback",
    maxRequestsPerMinutePerDevice: 1000,
    maxPairingAttemptsPerMinutePerAddress: 1000,
    maxPairingAttemptsPerMinuteGlobal: 1000,
  });
  await new Promise<void>((resolve) => gateway.listen(0, "127.0.0.1", resolve));
  const gwAddress = gateway.address();
  if (gwAddress === null || typeof gwAddress === "string") throw new Error("no gateway port");
  return {
    daemon,
    gateway,
    service,
    daemonBase,
    gatewayPort: gwAddress.port,
    ca: { keyPem: ca.keyPem, certPem: ca.certPem },
    gwCert: { keyPem: gwCert.keyPem, certPem: gwCert.certPem },
    dir,
    cursorToken: cursor.token,
  };
}

export async function pairDevice(stack: Stack, name: string): Promise<{ deviceId: string; keyPem: string; certPem: string; sasFromApp: string }> {
  const sessionRes = await fetch(`${stack.daemonBase}/devices/pair`, {
    method: "POST",
    headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
    body: "{}",
  });
  const session = (await sessionRes.json()) as { pairingId: string; code: string };
  const deviceKeys = generateRsaKeyPairPem();
  const clientNonce = "nonce-" + name;
  const begin = await gwRequest({
    port: stack.gatewayPort,
    method: "POST",
    path: "/pair/begin",
    body: {
      code: session.code,
      deviceName: name,
      platform: "linux",
      clientPublicKeyPem: deviceKeys.publicKeyPem,
      clientNonce,
    },
  });
  expect(begin.status).toBe(200);
  // The vault-side screen now shows the SAS.
  const viewRes = await fetch(`${stack.daemonBase}/devices/pairing`, {
    headers: { "x-metavault-token": DAEMON_TOKEN },
  });
  const view = (await viewRes.json()) as { session: { sas?: string; status: string } | null };
  expect(view.session?.status).toBe("joined");
  expect(view.session?.sas).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/);
  // Human confirms on the vault machine.
  const confirm = await fetch(`${stack.daemonBase}/devices/pairing/confirm`, {
    method: "POST",
    headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
    body: JSON.stringify({ pairingId: session.pairingId }),
  });
  expect(confirm.status).toBe(200);
  const confirmed = (await confirm.json()) as { deviceId: string };
  // The device fetches its issued certificate once.
  const status = await gwRequest({
    port: stack.gatewayPort,
    method: "POST",
    path: "/pair/status",
    body: { pairingId: session.pairingId },
  });
  expect(status.status).toBe(200);
  const statusBody = JSON.parse(status.body) as { status: string; certificatePem?: string };
  expect(statusBody.status).toBe("confirmed");
  expect(statusBody.certificatePem).toBeDefined();
  return {
    deviceId: confirmed.deviceId,
    keyPem: deviceKeys.privateKeyPem,
    certPem: statusBody.certificatePem as string,
    sasFromApp: view.session?.sas ?? "",
  };
}

