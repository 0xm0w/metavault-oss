// End-to-end gateway + daemon security tests (WP4/WP5/WP6 core):
// allowlist completeness, fail-closed device authentication, spoof
// resistance, device-bound tokens, device ceilings, pairing handshake
// (single-use codes, SAS transcript binding, revocation).
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpsRequest } from "node:https";
import type { Server } from "node:http";
import type { Server as HttpsServer } from "node:https";
import { Effect, Layer } from "effect";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import {
  ensureGatewayCertificate,
  ensureVaultCa,
  generateRsaKeyPairPem,
  signLeafCertificate,
} from "../../core/src/vault-ca.js";
import { createVaultHttpServer } from "../../daemon/src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../../daemon/src/service.js";
import { makeDaemonBackend } from "../src/daemon-backend.js";
import { createGatewayServer, GATEWAY_ALLOWLIST } from "../src/server.js";

const MASTER_KEY = Buffer.alloc(32, 7);
const GATEWAY_SECRET = "test-gateway-secret";
const DAEMON_TOKEN = "test-daemon-token";

const BrainLowRisk = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({
      risk: "low" as const,
      recommendedScope: "charges.read",
      requireApproval: true,
      explanation: "safe test read",
    }),
});
const FakeConnector = Layer.succeed(Connector, {
  execute: (_alias, scope) => Effect.succeed({ scope }),
});

interface GwResponse {
  status: number;
  body: string;
}

function gwRequest(options: {
  port: number;
  method: string;
  path: string;
  body?: unknown;
  cert?: string;
  key?: string;
  ca?: string;
  agentToken?: string;
  tlsRejectUnauthorized?: boolean;
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
        headers: {
          "content-type": "application/json",
          ...(options.agentToken !== undefined ? { "x-metavault-agent-token": options.agentToken } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => { resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }); });
      },
    );
    req.on("error", reject);
    if (options.body !== undefined) req.write(JSON.stringify(options.body));
    req.end();
  });
}

interface Stack {
  daemon: Server;
  gateway: HttpsServer;
  service: VaultServiceService;
  daemonBase: string;
  gatewayPort: number;
  ca: { keyPem: string; certPem: string };
  dir: string;
  cursorToken: string;
}

async function makeStack(): Promise<Stack> {
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
    dir,
    cursorToken: cursor.token,
  };
}

async function pairDevice(stack: Stack, name: string): Promise<{ deviceId: string; keyPem: string; certPem: string; sasFromApp: string }> {
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

describe("gateway", () => {
  let stack: Stack;
  beforeAll(async () => {
    stack = await makeStack();
  }, 120_000);
  afterAll(async () => {
    await new Promise<void>((resolve) => stack.gateway.close(() => { resolve(); }));
    await new Promise<void>((resolve) => stack.daemon.close(() => { resolve(); }));
    rmSync(stack.dir, { recursive: true, force: true });
  });

  it("pairs a device end-to-end and forwards allowlisted calls over mTLS", async () => {
    const device = await pairDevice(stack, "laptop-1");
    expect(device.deviceId).toMatch(/^dev-[0-9a-f]{12}$/);
    const res = await gwRequest({
      port: stack.gatewayPort,
      method: "GET",
      path: "/health",
      cert: device.certPem,
      key: device.keyPem,
    });
    expect(res.status).toBe(200);
    const aliases = await gwRequest({
      port: stack.gatewayPort,
      method: "GET",
      path: "/aliases",
      cert: device.certPem,
      key: device.keyPem,
    });
    expect(aliases.status).toBe(200);
    expect(aliases.body).toContain("stripe");
  }, 120_000);

  it("fails closed without a client certificate", async () => {
    const res = await gwRequest({ port: stack.gatewayPort, method: "GET", path: "/aliases" });
    expect(res.status).toBe(401);
  });

  it("rejects a certificate from a foreign CA", async () => {
    const foreignDir = mkdtempSync(join(tmpdir(), "mv-gw-foreign-"));
    const foreignCa = ensureVaultCa(foreignDir);
    const keys = generateRsaKeyPairPem();
    const foreignCert = signLeafCertificate({
      caKeyPem: foreignCa.keyPem,
      caCertPem: foreignCa.certPem,
      publicKeyPem: keys.publicKeyPem,
      commonName: "evil",
      serialNumber: "09",
      validityDays: 30,
      usage: "client",
    });
    const res = await gwRequest({
      port: stack.gatewayPort,
      method: "GET",
      path: "/aliases",
      cert: foreignCert,
      key: keys.privateKeyPem,
    });
    expect(res.status).toBe(401);
    rmSync(foreignDir, { recursive: true, force: true });
  }, 120_000);

  it("rejects every non-allowlisted route at the gateway", async () => {
    const device = await pairDevice(stack, "route-matrix");
    const blocked: { method: string; path: string }[] = [
      { method: "GET", path: "/policies" },
      { method: "GET", path: "/audit" },
      { method: "GET", path: "/pending" },
      { method: "POST", path: "/approve" },
      { method: "POST", path: "/approve-always" },
      { method: "POST", path: "/deny" },
      { method: "POST", path: "/unlock" },
      { method: "POST", path: "/setup" },
      { method: "POST", path: "/lock" },
      { method: "GET", path: "/key/status" },
      { method: "GET", path: "/agents" },
      { method: "POST", path: "/agents" },
      { method: "POST", path: "/credentials" },
      { method: "POST", path: "/cards" },
      { method: "GET", path: "/settings/warden" },
      { method: "PATCH", path: "/settings/security" },
      { method: "GET", path: "/devices" },
      { method: "POST", path: "/devices/revoke" },
      { method: "GET", path: "/settings/remote" },
      { method: "POST", path: "/internal/device-status" },
      { method: "DELETE", path: "/credentials/stripe" },
    ];
    for (const route of blocked) {
      const res = await gwRequest({
        port: stack.gatewayPort,
        method: route.method,
        path: route.path,
        cert: device.certPem,
        key: device.keyPem,
        body: route.method === "POST" || route.method === "PATCH" ? {} : undefined,
      });
      expect(res.status, `${route.method} ${route.path}`).toBe(403);
    }
    // The allowlist is exactly six routes; nothing more exists to expose.
    expect(GATEWAY_ALLOWLIST.length).toBe(6);
  }, 120_000);

  it("enforces device-bound agent tokens in both directions", async () => {
    const device = await pairDevice(stack, "token-binding");
    // Human issues a token bound to this device.
    const bound = await Effect.runPromise(
      Effect.provide(
        Effect.flatMap(VaultService, (svc) => svc.registerAgent("remote-ide", "Remote IDE", false, device.deviceId)),
        Layer.succeed(VaultService, stack.service),
      ),
    );
    // Bound token works through its own device session.
    const okRes = await gwRequest({
      port: stack.gatewayPort,
      method: "POST",
      path: "/request",
      cert: device.certPem,
      key: device.keyPem,
      agentToken: bound.token,
      body: { agentId: "remote-ide", ide: "test", tool: "test", alias: "stripe", requestedScope: "charges.read", reason: "check" },
    });
    expect(okRes.status).toBe(200);
    expect(okRes.body).not.toContain("denied");
    // The same token presented locally is refused.
    const localRes = await fetch(`${stack.daemonBase}/request`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-metavault-agent-token": bound.token },
      body: JSON.stringify({ agentId: "remote-ide", ide: "test", tool: "test", alias: "stripe", requestedScope: "charges.read", reason: "check" }),
    });
    const localBody = (await localRes.json()) as { status?: string; reason?: string };
    expect(localBody.status).toBe("denied");
    expect(localBody.reason).toBe("agent-token-device-bound");
    // A local-only token presented from the device session is refused.
    const remoteLocal = await gwRequest({
      port: stack.gatewayPort,
      method: "POST",
      path: "/request",
      cert: device.certPem,
      key: device.keyPem,
      agentToken: stack.cursorToken,
      body: { agentId: "cursor", ide: "test", tool: "test", alias: "stripe", requestedScope: "charges.read", reason: "check" },
    });
    const remoteLocalBody = JSON.parse(remoteLocal.body) as { status?: string; reason?: string };
    expect(remoteLocalBody.status).toBe("denied");
    expect(remoteLocalBody.reason).toBe("agent-token-device-mismatch");
  }, 120_000);

  it("denies remote writes until the human opts the device in per alias", async () => {
    const device = await pairDevice(stack, "write-ceiling");
    const bound = await Effect.runPromise(
      Effect.provide(
        Effect.flatMap(VaultService, (svc) => svc.registerAgent("writer", "Writer", false, device.deviceId)),
        Layer.succeed(VaultService, stack.service),
      ),
    );
    const makeReq = () =>
      gwRequest({
        port: stack.gatewayPort,
        method: "POST",
        path: "/request",
        cert: device.certPem,
        key: device.keyPem,
        agentToken: bound.token,
        body: { agentId: "writer", ide: "test", tool: "test", alias: "stripe-write", requestedScope: "charges.write", reason: "move money" },
      });
    const denied = await makeReq();
    const deniedBody = JSON.parse(denied.body) as { status?: string; reason?: string };
    expect(deniedBody.status).toBe("denied");
    expect(deniedBody.reason).toBe("device-ceiling-readonly");
    // Opt the device into writes for this one alias on the vault machine.
    await Effect.runPromise(
      Effect.provide(
        Effect.flatMap(VaultService, (svc) => svc.setDeviceAliasPolicy(device.deviceId, "stripe-write", true)),
        Layer.succeed(VaultService, stack.service),
      ),
    );
    const allowed = await makeReq();
    const allowedBody = JSON.parse(allowed.body) as { status?: string };
    // Not auto-executed: remote writes always need a human decision.
    expect(allowedBody.status).toBe("awaiting-approval");
  }, 120_000);

  it("revokes a device completely: session, bound tokens, and forwarding all die", async () => {
    const device = await pairDevice(stack, "revoke-me");
    const bound = await Effect.runPromise(
      Effect.provide(
        Effect.flatMap(VaultService, (svc) => svc.registerAgent("doomed", "Doomed", false, device.deviceId)),
        Layer.succeed(VaultService, stack.service),
      ),
    );
    const before = await gwRequest({
      port: stack.gatewayPort,
      method: "GET",
      path: "/health",
      cert: device.certPem,
      key: device.keyPem,
    });
    expect(before.status).toBe(200);
    await Effect.runPromise(
      Effect.provide(
        Effect.flatMap(VaultService, (svc) => svc.revokeDevice(device.deviceId)),
        Layer.succeed(VaultService, stack.service),
      ),
    );
    const after = await gwRequest({
      port: stack.gatewayPort,
      method: "GET",
      path: "/health",
      cert: device.certPem,
      key: device.keyPem,
    });
    expect(after.status).toBe(403);
    const agent = await Effect.runPromise(
      Effect.provide(
        Effect.flatMap(VaultService, (svc) => svc.getAgentByToken(bound.token)),
        Layer.succeed(VaultService, stack.service),
      ),
    );
    expect(agent?.revoked).toBe(true);
  }, 120_000);

  it("rejects pairing with a wrong code and kills the session after repeated failures", async () => {
    const sessionRes = await fetch(`${stack.daemonBase}/devices/pair`, {
      method: "POST",
      headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
      body: "{}",
    });
    const session = (await sessionRes.json()) as { code: string };
    const keys = generateRsaKeyPairPem();
    for (let i = 0; i < 5; i++) {
      const res = await gwRequest({
        port: stack.gatewayPort,
        method: "POST",
        path: "/pair/begin",
        body: { code: "WRONGCODE", deviceName: "attacker", platform: "linux", clientPublicKeyPem: keys.publicKeyPem, clientNonce: "n" },
      });
      expect(res.status).toBe(403);
    }
    // Session is dead: even the correct code now fails, and the human must
    // start a fresh pairing session.
    const res = await gwRequest({
      port: stack.gatewayPort,
      method: "POST",
      path: "/pair/begin",
      body: { code: session.code, deviceName: "attacker", platform: "linux", clientPublicKeyPem: keys.publicKeyPem, clientNonce: "n" },
    });
    expect(res.status).toBe(403);
  }, 120_000);

  it("pairing codes are single-use", async () => {
    const sessionRes = await fetch(`${stack.daemonBase}/devices/pair`, {
      method: "POST",
      headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
      body: "{}",
    });
    const session = (await sessionRes.json()) as { code: string };
    const keys = generateRsaKeyPairPem();
    const first = await gwRequest({
      port: stack.gatewayPort,
      method: "POST",
      path: "/pair/begin",
      body: { code: session.code, deviceName: "first", platform: "linux", clientPublicKeyPem: keys.publicKeyPem, clientNonce: "n1" },
    });
    expect(first.status).toBe(200);
    const second = await gwRequest({
      port: stack.gatewayPort,
      method: "POST",
      path: "/pair/begin",
      body: { code: session.code, deviceName: "second", platform: "linux", clientPublicKeyPem: keys.publicKeyPem, clientNonce: "n2" },
    });
    expect(second.status).toBe(403);
  }, 120_000);

  it("binds the SAS to the TLS transcript: different sessions derive different strings", async () => {
    // Two independent pairing sessions must not produce the same SAS even
    // for identical device keys: exporter secrets and nonces differ. This
    // is the property that detects a MITM terminating two TLS sessions.
    const keys = generateRsaKeyPairPem();
    const sasValues: string[] = [];
    for (let i = 0; i < 2; i++) {
      const sessionRes = await fetch(`${stack.daemonBase}/devices/pair`, {
        method: "POST",
        headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
        body: "{}",
      });
      const session = (await sessionRes.json()) as { code: string };
      const begin = await gwRequest({
        port: stack.gatewayPort,
        method: "POST",
        path: "/pair/begin",
        body: { code: session.code, deviceName: "sas-check", platform: "linux", clientPublicKeyPem: keys.publicKeyPem, clientNonce: `n${String(i)}` },
      });
      expect(begin.status).toBe(200);
      const viewRes = await fetch(`${stack.daemonBase}/devices/pairing`, {
        headers: { "x-metavault-token": DAEMON_TOKEN },
      });
      const view = (await viewRes.json()) as { session: { sas?: string } | null };
      expect(view.session?.sas).toBeDefined();
      sasValues.push(view.session?.sas ?? "");
    }
    expect(new Set(sasValues).size).toBe(2);
  }, 120_000);

  it("refuses device stamps without a valid gateway secret at the daemon", async () => {
    // A local process stamping forged device headers is rejected.
    const forged = await fetch(`${stack.daemonBase}/request`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-metavault-device-id": "dev-forged",
        "x-metavault-transport": "loopback",
      },
      body: JSON.stringify({ agentId: "cursor", ide: "test", tool: "test", alias: "stripe", requestedScope: "charges.read", reason: "x" }),
    });
    expect(forged.status).toBe(403);
    const wrongSecret = await fetch(`${stack.daemonBase}/request`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-metavault-gateway-secret": "wrong",
        "x-metavault-device-id": "dev-forged",
      },
      body: JSON.stringify({ agentId: "cursor", ide: "test", tool: "test", alias: "stripe", requestedScope: "charges.read", reason: "x" }),
    });
    expect(wrongSecret.status).toBe(403);
    // Internal routes are not reachable with the daemon token or nothing.
    const internalNoAuth = await fetch(`${stack.daemonBase}/internal/device-status`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ fingerprint: "x" }),
    });
    expect(internalNoAuth.status).toBe(401);
    const internalDaemonToken = await fetch(`${stack.daemonBase}/internal/device-status`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-metavault-token": DAEMON_TOKEN },
      body: JSON.stringify({ fingerprint: "x" }),
    });
    expect(internalDaemonToken.status).toBe(401);
  });

  it("ignores the daemon token on device-stamped requests", async () => {
    // Even a leaked daemon token must not unlock human routes remotely:
    // stamped requests have the token ignored, so this hits 401 like an
    // unauthenticated local caller.
    const res = await fetch(`${stack.daemonBase}/pending`, {
      headers: {
        "x-metavault-token": DAEMON_TOKEN,
        "x-metavault-gateway-secret": GATEWAY_SECRET,
        "x-metavault-device-id": "dev-anything",
      },
    });
    expect(res.status).toBe(401);
  });

  it("records remote origin in the audit trail", async () => {
    const device = await pairDevice(stack, "audit-origin");
    await gwRequest({
      port: stack.gatewayPort,
      method: "POST",
      path: "/request",
      cert: device.certPem,
      key: device.keyPem,
      body: { agentId: "unverified-remote", ide: "test", tool: "test", alias: "stripe", requestedScope: "charges.read", reason: "audit" },
    });
    const events = await Effect.runPromise(
      Effect.provide(
        Effect.flatMap(VaultService, (svc) => svc.listAudit()),
        Layer.succeed(VaultService, stack.service),
      ),
    );
    const remote = events.filter((e) => e.origin === "remote" && e.deviceId === device.deviceId);
    expect(remote.length).toBeGreaterThan(0);
    expect(remote[0]?.transport).toBe("loopback");
  }, 120_000);
});
