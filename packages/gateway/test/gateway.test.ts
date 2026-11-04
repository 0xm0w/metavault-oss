// End-to-end gateway + daemon security tests (WP4/WP5/WP6 core):
// allowlist completeness, fail-closed device authentication, spoof
// resistance, device-bound tokens, device ceilings, pairing handshake
// (single-use codes, SAS transcript binding, revocation).
import { mkdtempSync, rmSync } from "node:fs";
import { createServer as createHttpServer, request as httpRequest } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Effect, Layer } from "effect";
import { VaultService } from "../../daemon/src/service.js";
import { ensureGatewayCertificate, ensureVaultCa, generateRsaKeyPairPem, signLeafCertificate, spkiFingerprintFromPublicKeyPem } from "../../core/src/vault-ca.js";
import { computePairingSas } from "../../core/src/pairing.js";
import { makeDaemonBackend } from "../src/daemon-backend.js";
import { createGatewayServer, GATEWAY_ALLOWLIST } from "../src/server.js";
import {
  DAEMON_TOKEN,
  GATEWAY_SECRET,
  makeStack,
  pairDevice,
  gwRequest,
  stampHeaders,
  type Stack,
} from "./stack.js";

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

  it("revocation is not retrospective: an in-flight request completes, the next one dies", async () => {
    // Slow proxy in front of the real daemon delays POST /request so the
    // device can be revoked while its already-authorized request is still
    // executing. Documented semantics: revocation kills the session, bound
    // tokens and every subsequent request, but does NOT retrospectively
    // cancel an execution that passed authorization before the revoke.
    const device = await pairDevice(stack, "in-flight");
    const proxy = createHttpServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const forward = () => {
          const upstream = httpRequest({
            hostname: "127.0.0.1",
            port: new URL(stack.daemonBase).port,
            path: req.url,
            method: req.method,
            headers: { ...req.headers, host: `127.0.0.1:${new URL(stack.daemonBase).port}` },
          }, (up) => {
            res.writeHead(up.statusCode ?? 502, up.headers);
            up.pipe(res);
          });
          upstream.on("error", () => { res.writeHead(502); res.end(); });
          upstream.end(Buffer.concat(chunks));
        };
        if (req.method === "POST" && req.url === "/request") {
          setTimeout(forward, 400);
        } else {
          forward();
        }
      });
    });
    await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
    const proxyAddr = proxy.address();
    if (proxyAddr === null || typeof proxyAddr === "string") throw new Error("no proxy port");
    const slowGateway = createGatewayServer({
      caCertPem: stack.ca.certPem,
      serverCertPem: stack.gwCert.certPem,
      serverKeyPem: stack.gwCert.keyPem,
      backend: makeDaemonBackend(`http://127.0.0.1:${String(proxyAddr.port)}`, GATEWAY_SECRET),
      daemonBaseUrl: `http://127.0.0.1:${String(proxyAddr.port)}`,
      gatewaySecret: GATEWAY_SECRET,
      transport: "loopback",
      maxRequestsPerMinutePerDevice: 1000,
      maxPairingAttemptsPerMinutePerAddress: 1000,
      maxPairingAttemptsPerMinuteGlobal: 1000,
    });
    await new Promise<void>((resolve) => slowGateway.listen(0, "127.0.0.1", resolve));
    const slowAddr = slowGateway.address();
    if (slowAddr === null || typeof slowAddr === "string") throw new Error("no gateway port");

    const inFlight = gwRequest({
      port: slowAddr.port,
      method: "POST",
      path: "/request",
      cert: device.certPem,
      key: device.keyPem,
      body: { agentId: "in-flight-agent", ide: "test", tool: "test", alias: "stripe", requestedScope: "charges.read", reason: "in-flight" },
    });
    // Give the request time to pass device auth and enter the delayed
    // upstream leg, then revoke mid-flight.
    await new Promise((resolve) => setTimeout(resolve, 150));
    await Effect.runPromise(
      Effect.provide(
        Effect.flatMap(VaultService, (svc) => svc.revokeDevice(device.deviceId)),
        Layer.succeed(VaultService, stack.service),
      ),
    );
    const completed = await inFlight;
    // The in-flight request was authorized before revocation: it is NOT
    // retrospectively cancelled (200 with the normal approval-flow body).
    expect(completed.status).toBe(200);
    // Every subsequent request from the revoked device is rejected.
    const after = await gwRequest({
      port: slowAddr.port,
      method: "GET",
      path: "/health",
      cert: device.certPem,
      key: device.keyPem,
    });
    expect(after.status).toBe(403);
    await new Promise<void>((resolve) => { slowGateway.close(() => { resolve(); }); });
    await new Promise<void>((resolve) => { proxy.close(() => { resolve(); }); });
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

  it("rejects forged, tampered, stale and replayed gateway stamps at the daemon", async () => {
    const requestBody = JSON.stringify({ agentId: "cursor", ide: "test", tool: "test", alias: "stripe", requestedScope: "charges.read", reason: "x" });
    const post = async (headers: Record<string, string>, body: string): Promise<number> =>
      (await fetch(`${stack.daemonBase}/request`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body })).status;

    // Device headers with no MAC at all: fail closed.
    expect(await post({ "x-metavault-device-id": "dev-forged", "x-metavault-transport": "loopback" }, requestBody)).toBe(403);
    // Legacy raw-secret header is not a stamp.
    expect(await post({ "x-metavault-gateway-secret": GATEWAY_SECRET, "x-metavault-device-id": "dev-forged" }, requestBody)).toBe(403);
    // MAC computed with the wrong secret.
    expect(await post(stampHeaders({ deviceId: "dev-forged", method: "POST", path: "/request", bodyText: requestBody, secret: "wrong" }), requestBody)).toBe(403);
    // Body tampered after stamping.
    const valid = stampHeaders({ deviceId: "dev-forged", method: "POST", path: "/request", bodyText: requestBody });
    expect(await post(valid, JSON.stringify({ agentId: "cursor", ide: "test", tool: "test", alias: "stripe", requestedScope: "charges.write", reason: "tampered" }))).toBe(403);
    // Path tampered after stamping: MAC over /health replayed against
    // /aliases is rejected.
    const healthStamp = stampHeaders({ deviceId: "dev-forged", method: "GET", path: "/health" });
    const tamperedPath = await fetch(`${stack.daemonBase}/aliases`, { headers: healthStamp });
    expect(tamperedPath.status).toBe(403);
    // Stale timestamp.
    const stale = stampHeaders({ deviceId: "dev-forged", method: "POST", path: "/request", bodyText: requestBody, ts: String(Math.floor(Date.now() / 1000) - 600) });
    expect(await post(stale, requestBody)).toBe(403);
    // Replay: the same authentic stamp twice is rejected the second time.
    // (GET /health is used as the positive control so only the stamp layer
    // decides: the first pass proves the stamp itself is accepted.)
    const replayStamp = stampHeaders({ deviceId: "dev-forged", method: "GET", path: "/health" });
    const first = await fetch(`${stack.daemonBase}/health`, { headers: replayStamp });
    const second = await fetch(`${stack.daemonBase}/health`, { headers: replayStamp });
    expect(first.status).toBe(200);
    expect(second.status).toBe(403);
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
        ...stampHeaders({ deviceId: "dev-anything", method: "GET", path: "/pending" }),
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

  it("never leaks pairing codes, SAS values, or session identifiers to errors or the audit trail", async () => {
    // Drive a full pairing flow, capturing the secret material.
    const sessionRes = await fetch(`${stack.daemonBase}/devices/pair`, {
      method: "POST",
      headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
      body: "{}",
    });
    const session = (await sessionRes.json()) as { pairingId: string; code: string };
    const deviceKeys = generateRsaKeyPairPem();
    const begin = await gwRequest({
      port: stack.gatewayPort,
      method: "POST",
      path: "/pair/begin",
      body: {
        code: session.code,
        deviceName: "redaction",
        platform: "linux",
        clientPublicKeyPem: deviceKeys.publicKeyPem,
        clientNonce: "nonce-redaction",
      },
    });
    const viewRes = await fetch(`${stack.daemonBase}/devices/pairing`, {
      headers: { "x-metavault-token": DAEMON_TOKEN },
    });
    const view = (await viewRes.json()) as { session: { sas?: string } | null };
    const sas = view.session?.sas ?? "";
    expect(sas).not.toBe("");

    // Fire a battery of failing requests at both pairing endpoints. The
    // legitimate begin response carries the pairingId to the pairing
    // client by design; errors, probes and the audit trail must not.
    expect(begin.status).toBe(200);
    const bodies: string[] = [];
    bodies.push((await gwRequest({ port: stack.gatewayPort, method: "POST", path: "/pair/begin", body: { code: "wrong-code", deviceName: "x", platform: "linux", clientPublicKeyPem: deviceKeys.publicKeyPem, clientNonce: "n2" } })).body);
    bodies.push((await gwRequest({ port: stack.gatewayPort, method: "POST", path: "/pair/status", body: { pairingId: "unknown-id" } })).body);
    bodies.push((await gwRequest({ port: stack.gatewayPort, method: "POST", path: "/pair/status", body: {} })).body);
    bodies.push((await gwRequest({ port: stack.gatewayPort, method: "POST", path: "/pair/begin", body: { garbage: true } })).body);

    // The daemon audit trail after all of the above.
    const events = await Effect.runPromise(
      Effect.provide(
        Effect.flatMap(VaultService, (svc) => svc.listAudit()),
        Layer.succeed(VaultService, stack.service),
      ),
    );
    const auditBlob = JSON.stringify(events);

    const haystack = bodies.join("\n") + "\n" + auditBlob;
    expect(haystack).not.toContain(session.code);
    expect(haystack).not.toContain(sas);
    expect(haystack).not.toContain(session.pairingId);
  }, 120_000);

  it("rejects requests on an already-open mTLS connection after revocation", async () => {
    const device = await pairDevice(stack, "keepalive");
    const agent = new HttpsAgent({
      keepAlive: true,
      maxSockets: 1,
      ca: stack.ca.certPem,
      cert: device.certPem,
      key: device.keyPem,
      rejectUnauthorized: false,
    });
    const first = await gwRequest({ port: stack.gatewayPort, method: "GET", path: "/health", agent });
    expect(first.status).toBe(200);
    const revoke = await fetch(`${stack.daemonBase}/devices/revoke`, {
      method: "POST",
      headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
      body: JSON.stringify({ target: device.deviceId }),
    });
    expect(revoke.status).toBe(200);
    // Same kept-alive socket: revocation is re-checked per request, not
    // only at the TLS handshake.
    const second = await gwRequest({ port: stack.gatewayPort, method: "GET", path: "/health", agent });
    expect(second.localPort).toBe(first.localPort);
    expect(second.status).toBe(403);
    agent.destroy();
  }, 120_000);

  it("caps pairing attempts globally against distributed code brute-force", async () => {
    const backend = makeDaemonBackend(stack.daemonBase, GATEWAY_SECRET);
    const gw2 = createGatewayServer({
      caCertPem: stack.ca.certPem,
      serverCertPem: stack.gwCert.certPem,
      serverKeyPem: stack.gwCert.keyPem,
      backend,
      daemonBaseUrl: stack.daemonBase,
      gatewaySecret: GATEWAY_SECRET,
      transport: "loopback",
      maxRequestsPerMinutePerDevice: 1000,
      maxPairingAttemptsPerMinutePerAddress: 1000,
      maxPairingAttemptsPerMinuteGlobal: 3,
    });
    await new Promise<void>((resolve) => { gw2.listen(0, "127.0.0.1", resolve); });
    const address = gw2.address();
    if (address === null || typeof address === "string") throw new Error("no port");
    const keys = generateRsaKeyPairPem();
    const statuses: number[] = [];
    for (let i = 0; i < 5; i += 1) {
      const res = await gwRequest({
        port: address.port,
        method: "POST",
        path: "/pair/begin",
        body: { code: "WRONGCODE", deviceName: "brute", platform: "linux", clientPublicKeyPem: keys.publicKeyPem, clientNonce: `n${String(i)}` },
      });
      statuses.push(res.status);
    }
    // First three reach the daemon and fail on the code; the global cap
    // rejects the rest before any daemon work.
    expect(statuses.slice(0, 3)).toEqual([403, 403, 403]);
    expect(statuses.slice(3)).toEqual([429, 429]);
    await new Promise<void>((resolve) => { gw2.close(() => { resolve(); }); });
  }, 120_000);

  it("keeps concurrent pairing attempts isolated to the single active session", async () => {
    // The vault holds exactly one active pairing session, created only by
    // the local human (daemon token). Starting a new session replaces the
    // old one: the old code dies, the old pairingId cannot be confirmed,
    // and no material crosses between sessions.
    const mkSession = async (): Promise<{ pairingId: string; code: string }> => {
      const res = await fetch(`${stack.daemonBase}/devices/pair`, {
        method: "POST",
        headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
        body: "{}",
      });
      return (await res.json()) as { pairingId: string; code: string };
    };
    const keysA = generateRsaKeyPairPem();
    const keysB = generateRsaKeyPairPem();
    const beginWith = async (code: string, keys: { publicKeyPem: string }, nonce: string): Promise<number> =>
      (await gwRequest({
        port: stack.gatewayPort, method: "POST", path: "/pair/begin",
        body: { code, deviceName: "conc", platform: "linux", clientPublicKeyPem: keys.publicKeyPem, clientNonce: nonce },
      })).status;

    const sessionA = await mkSession();
    expect(await beginWith(sessionA.code, keysA, "conc-a-nonce")).toBe(200);

    // The local human starts over: B replaces A.
    const sessionB = await mkSession();
    // A's code is dead immediately.
    expect(await beginWith(sessionA.code, keysA, "conc-a2-nonce")).toBe(403);
    // A's pairingId cannot be confirmed anymore.
    const confirmA = await fetch(`${stack.daemonBase}/devices/pairing/confirm`, {
      method: "POST",
      headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
      body: JSON.stringify({ pairingId: sessionA.pairingId }),
    });
    expect(confirmA.status).not.toBe(200);

    // B completes and its certificate binds only B's key.
    expect(await beginWith(sessionB.code, keysB, "conc-b-nonce")).toBe(200);
    const confirmB = await fetch(`${stack.daemonBase}/devices/pairing/confirm`, {
      method: "POST",
      headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
      body: JSON.stringify({ pairingId: sessionB.pairingId }),
    });
    expect(confirmB.status).toBe(200);
    const statusB = await gwRequest({ port: stack.gatewayPort, method: "POST", path: "/pair/status", body: { pairingId: sessionB.pairingId } });
    const bodyB = JSON.parse(statusB.body) as { status: string; certificatePem?: string };
    const certB = bodyB.certificatePem ?? "";
    expect(bodyB.status).toBe("confirmed");
    expect(certB).toContain("BEGIN CERTIFICATE");
    const health = await gwRequest({ port: stack.gatewayPort, method: "GET", path: "/health", cert: certB, key: keysB.privateKeyPem });
    expect(health.status).toBe(200);
    const wrongKey = await gwRequest({ port: stack.gatewayPort, method: "GET", path: "/health", cert: certB, key: keysA.privateKeyPem }).catch(() => ({ status: 0, body: "" }));
    expect(wrongKey.status).not.toBe(200);
  }, 120_000);

  it("exposes a split-session MITM through mismatched SAS values", async () => {
    // Direct session first: the SAS the client computes from its own TLS
    // exporter must equal the SAS the vault shows on its screen. That
    // equality is the comparison the pairing UX relies on.
    const mkSession = async (): Promise<{ pairingId: string; code: string }> => {
      const res = await fetch(`${stack.daemonBase}/devices/pair`, {
        method: "POST",
        headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
        body: "{}",
      });
      return (await res.json()) as { pairingId: string; code: string };
    };
    const directKeys = generateRsaKeyPairPem();
    const directSession = await mkSession();
    const directBegin = await gwRequest({
      port: stack.gatewayPort, method: "POST", path: "/pair/begin",
      body: { code: directSession.code, deviceName: "direct", platform: "linux", clientPublicKeyPem: directKeys.publicKeyPem, clientNonce: "direct-nonce" },
    });
    expect(directBegin.status).toBe(200);
    const directInfo = JSON.parse(directBegin.body) as { serverNonce: string; serverCertFingerprint: string };
    expect(directBegin.exporter).toBeDefined();
    const sasDirect = computePairingSas({
      exporterSecret: directBegin.exporter as Buffer,
      serverCertFingerprint: directInfo.serverCertFingerprint,
      clientPublicKeyFingerprint: spkiFingerprintFromPublicKeyPem(directKeys.publicKeyPem),
      code: directSession.code,
      serverNonce: directInfo.serverNonce,
      clientNonce: "direct-nonce",
    });
    const viewDirect = await (await fetch(`${stack.daemonBase}/devices/pairing`, { headers: { "x-metavault-token": DAEMON_TOKEN } })).json() as { session: { pairingId: string; sas?: string } | null };
    expect(viewDirect.session?.pairingId).toBe(directSession.pairingId);
    expect(viewDirect.session?.sas).toBe(sasDirect);
    await fetch(`${stack.daemonBase}/devices/pairing/cancel`, {
      method: "POST",
      headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
      body: JSON.stringify({ pairingId: directSession.pairingId }),
    });

    // Now an attacker relay that terminates the device TLS session with
    // its own certificate and re-originates a second session to the real
    // gateway, relaying /pair/begin verbatim.
    const attackerDir = mkdtempSync(join(tmpdir(), "mv-attacker-"));
    const attackerCa = ensureVaultCa(attackerDir);
    const attackerCert = ensureGatewayCertificate(attackerDir, attackerCa);
    const relay = createHttpsServer(
      { cert: attackerCert.certPem, key: attackerCert.keyPem, minVersion: "TLSv1.3" },
      (req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          const upstream = httpsRequest(
            { host: "127.0.0.1", port: stack.gatewayPort, method: "POST", path: "/pair/begin", rejectUnauthorized: false, headers: { "content-type": "application/json" } },
            (up) => {
              const upChunks: Buffer[] = [];
              up.on("data", (c: Buffer) => upChunks.push(c));
              up.on("end", () => {
                res.writeHead(up.statusCode ?? 502, { "content-type": "application/json" });
                res.end(Buffer.concat(upChunks));
              });
            },
          );
          upstream.on("error", () => { res.writeHead(502); res.end(); });
          upstream.write(Buffer.concat(chunks));
          upstream.end();
        });
      },
    );
    await new Promise<void>((resolve) => { relay.listen(0, "127.0.0.1", resolve); });
    const relayAddress = relay.address();
    if (relayAddress === null || typeof relayAddress === "string") throw new Error("no relay port");

    const victimKeys = generateRsaKeyPairPem();
    const victimSession = await mkSession();
    const mitmBegin = await gwRequest({
      port: relayAddress.port, method: "POST", path: "/pair/begin",
      body: { code: victimSession.code, deviceName: "victim", platform: "linux", clientPublicKeyPem: victimKeys.publicKeyPem, clientNonce: "victim-nonce" },
    });
    expect(mitmBegin.status).toBe(200);
    const mitmInfo = JSON.parse(mitmBegin.body) as { serverNonce: string; serverCertFingerprint: string };
    const sasVictim = computePairingSas({
      exporterSecret: mitmBegin.exporter as Buffer,
      serverCertFingerprint: mitmInfo.serverCertFingerprint,
      clientPublicKeyFingerprint: spkiFingerprintFromPublicKeyPem(victimKeys.publicKeyPem),
      code: victimSession.code,
      serverNonce: mitmInfo.serverNonce,
      clientNonce: "victim-nonce",
    });
    const viewMitm = await (await fetch(`${stack.daemonBase}/devices/pairing`, { headers: { "x-metavault-token": DAEMON_TOKEN } })).json() as { session: { pairingId: string; sas?: string } | null };
    expect(viewMitm.session?.pairingId).toBe(victimSession.pairingId);
    // The vault screen and the victim screen show different codes: the
    // exporter binds each SAS to its own TLS session, so the human
    // comparison catches the relay before any certificate is issued.
    expect(viewMitm.session?.sas).toBeDefined();
    expect(viewMitm.session?.sas).not.toBe(sasVictim);
    await fetch(`${stack.daemonBase}/devices/pairing/cancel`, {
      method: "POST",
      headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
      body: JSON.stringify({ pairingId: victimSession.pairingId }),
    });
    await new Promise<void>((resolve) => { relay.close(() => { resolve(); }); });
    rmSync(attackerDir, { recursive: true, force: true });
  }, 120_000);
});
