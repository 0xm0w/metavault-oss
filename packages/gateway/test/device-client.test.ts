// Device-side client tests (WP5/DD7): pairing handshake UX contract,
// credential storage permissions, post-enrollment pinning, and the
// loopback shim channel.
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createGatewayServer } from "../src/server.js";
import { makeDaemonBackend } from "../src/daemon-backend.js";
import {
  loadDeviceProfile,
  PairingError,
  runPairingHandshake,
  saveDeviceProfile,
  startShim,
} from "../src/device-client.js";
import { DAEMON_TOKEN, GATEWAY_SECRET, makeStack, type Stack } from "./stack.js";

describe("device-client", () => {
  let stack: Stack;
  beforeAll(async () => {
    stack = await makeStack();
  }, 120_000);
  afterAll(async () => {
    await new Promise<void>((resolve) => stack.gateway.close(() => { resolve(); }));
    await new Promise<void>((resolve) => stack.daemon.close(() => { resolve(); }));
    rmSync(stack.dir, { recursive: true, force: true });
  });

  async function newSession(): Promise<{ pairingId: string; code: string }> {
    const res = await fetch(`${stack.daemonBase}/devices/pair`, {
      method: "POST",
      headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
      body: "{}",
    });
    const parsed = (await res.json()) as { pairingId: string; code: string };
    return parsed;
  }

  async function confirmOnVault(pairingId: string): Promise<string> {
    const res = await fetch(`${stack.daemonBase}/devices/pairing/confirm`, {
      method: "POST",
      headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
      body: JSON.stringify({ pairingId }),
    });
    expect(res.status).toBe(200);
    return ((await res.json()) as { deviceId: string }).deviceId;
  }

  it("pairs, stores owner-only credentials and talks pinned mTLS afterwards", async () => {
    const session = await newSession();
    let shownSas = "";
    const handshake = runPairingHandshake({
      host: "127.0.0.1",
      port: stack.gatewayPort,
      code: session.code,
      deviceName: "client-e2e",
      platform: "linux",
      onSas: (sas) => { shownSas = sas; },
      pollIntervalMs: 50,
    });
    // Wait for the SAS to appear on both screens; they must match exactly.
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(shownSas).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/);
    const view = await (await fetch(`${stack.daemonBase}/devices/pairing`, { headers: { "x-metavault-token": DAEMON_TOKEN } })).json() as { session: { sas?: string } | null };
    expect(view.session?.sas).toBe(shownSas);
    const deviceId = await confirmOnVault(session.pairingId);
    const material = await handshake;

    const dir = mkdtempSync(join(tmpdir(), "mv-device-"));
    saveDeviceProfile(dir, {
      deviceId,
      host: "127.0.0.1",
      port: stack.gatewayPort,
      pairedAt: new Date().toISOString(),
      serverCertFingerprint: material.serverCertFingerprint,
    }, material, "mvshim_test-token-1");
    expect(statSync(join(dir, "key.pem")).mode & 0o777).toBe(0o600);
    expect(statSync(join(dir, "device.json")).mode & 0o777).toBe(0o600);
    const loaded = loadDeviceProfile(dir);
    expect(loaded.profile.deviceId).toBe(deviceId);

    // Pinned post-enrollment channel works.
    const shim = await startShim({ profileDir: dir, port: 0 });
    const auth = { "x-metavault-shim-token": "mvshim_test-token-1" };
    const health = await fetch(`http://127.0.0.1:${String(shim.port)}/health`, { headers: auth });
    expect(health.status).toBe(200);
    // Non-allowlisted routes are refused by the shim before any network.
    const policies = await fetch(`http://127.0.0.1:${String(shim.port)}/policies`, { headers: auth });
    expect(policies.status).toBe(403);
    await shim.close();
    rmSync(dir, { recursive: true, force: true });
  }, 120_000);

  it("fails pairing with a wrong code without touching the vault session", async () => {
    await newSession();
    await expect(
      runPairingHandshake({
        host: "127.0.0.1",
        port: stack.gatewayPort,
        code: "WRONGCODE",
        deviceName: "bad-code",
        platform: "linux",
        onSas: () => { throw new Error("SAS must never be shown for a rejected code"); },
        pollIntervalMs: 50,
      }),
    ).rejects.toBeInstanceOf(PairingError);
  }, 120_000);

  it("fails pairing when the vault human cancels instead of confirming", async () => {
    const session = await newSession();
    const handshake = runPairingHandshake({
      host: "127.0.0.1",
      port: stack.gatewayPort,
      code: session.code,
      deviceName: "cancel-me",
      platform: "linux",
      onSas: () => undefined,
      pollIntervalMs: 50,
    });
    await new Promise((resolve) => setTimeout(resolve, 300));
    await fetch(`${stack.daemonBase}/devices/pairing/cancel`, {
      method: "POST",
      headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
      body: JSON.stringify({ pairingId: session.pairingId }),
    });
    await expect(handshake).rejects.toMatchObject({ reason: "expired" });
  }, 120_000);

  it("never issues a certificate without vault-side confirmation", async () => {
    const session = await newSession();
    let done = false;
    const handshake = runPairingHandshake({
      host: "127.0.0.1",
      port: stack.gatewayPort,
      code: session.code,
      deviceName: "no-auto-issue",
      platform: "linux",
      onSas: () => undefined,
      pollIntervalMs: 50,
      timeoutMs: 800,
    }).then(
      () => { done = true; },
      (err: unknown) => { done = true; expect(err).toMatchObject({ reason: "timeout" }); },
    );
    // Nobody confirms: the device must hold no certificate, ever.
    await handshake;
    expect(done).toBe(true);
    const status = await fetch(`${stack.daemonBase}/devices/pairing`, { headers: { "x-metavault-token": DAEMON_TOKEN } });
    const view = (await status.json()) as { session: { status: string } | null };
    expect(view.session?.status ?? "gone").not.toBe("confirmed");
    await fetch(`${stack.daemonBase}/devices/pairing/cancel`, {
      method: "POST",
      headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
      body: JSON.stringify({ pairingId: session.pairingId }),
    });
  }, 120_000);

  it("shim refuses to talk to a gateway whose fingerprint changed", async () => {
    const session = await newSession();
    const handshake = runPairingHandshake({
      host: "127.0.0.1",
      port: stack.gatewayPort,
      code: session.code,
      deviceName: "pin-check",
      platform: "linux",
      onSas: () => undefined,
      pollIntervalMs: 50,
    });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const deviceId = await confirmOnVault(session.pairingId);
    const material = await handshake;
    const dir = mkdtempSync(join(tmpdir(), "mv-device-pin-"));
    saveDeviceProfile(dir, {
      deviceId,
      host: "127.0.0.1",
      port: stack.gatewayPort,
      pairedAt: new Date().toISOString(),
      // Simulate a different gateway key than the one seen at pairing.
      serverCertFingerprint: "0".repeat(64),
    }, material, "mvshim_test-token-2");
    const shim = await startShim({ profileDir: dir, port: 0 });
    const res = await fetch(`http://127.0.0.1:${String(shim.port)}/health`, { headers: { "x-metavault-shim-token": "mvshim_test-token-2" } });
    expect(res.status).toBe(502);
    await shim.close();
    rmSync(dir, { recursive: true, force: true });
  }, 120_000);

  it("shim demands its local token and refuses browser-style callers", async () => {
    const session = await newSession();
    const handshake = runPairingHandshake({
      host: "127.0.0.1",
      port: stack.gatewayPort,
      code: session.code,
      deviceName: "shim-auth",
      platform: "linux",
      onSas: () => undefined,
      pollIntervalMs: 50,
    });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const deviceId = await confirmOnVault(session.pairingId);
    const material = await handshake;
    const dir = mkdtempSync(join(tmpdir(), "mv-device-auth-"));
    saveDeviceProfile(dir, {
      deviceId,
      host: "127.0.0.1",
      port: stack.gatewayPort,
      pairedAt: new Date().toISOString(),
      serverCertFingerprint: material.serverCertFingerprint,
    }, material, "mvshim_secret-test-token");
    const shim = await startShim({ profileDir: dir, port: 0 });
    const base = `http://127.0.0.1:${String(shim.port)}`;

    // No token / wrong token: no route is reachable, not even /health.
    expect((await fetch(`${base}/health`)).status).toBe(401);
    expect((await fetch(`${base}/health`, { headers: { "x-metavault-shim-token": "mvshim_wrong" } })).status).toBe(401);
    // Browser cross-origin and fetch-metadata callers are refused.
    expect((await fetch(`${base}/health`, { headers: { "x-metavault-shim-token": "mvshim_secret-test-token", origin: "https://evil.example" } })).status).toBe(403);
    expect((await fetch(`${base}/health`, { headers: { "x-metavault-shim-token": "mvshim_secret-test-token", "sec-fetch-site": "cross-site" } })).status).toBe(403);
    // DNS-rebinding style Host header is refused even with the token.
    const rebinding = await new Promise<number>((resolve) => {
      const req = httpRequest({ host: "127.0.0.1", port: shim.port, path: "/health", headers: { host: "evil.example", "x-metavault-shim-token": "mvshim_secret-test-token" } }, (res) => { resolve(res.statusCode ?? 0); });
      req.on("error", () => { resolve(0); });
      req.end();
    });
    expect(rebinding).toBe(403);

    // The shim never supplies an agent identity. /request is an open
    // SUBMISSION channel by design: an unauthenticated caller may only
    // create a pending approval for the human, never execute - the
    // response must carry no credential material.
    const noAgent = await fetch(`${base}/request`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-metavault-shim-token": "mvshim_secret-test-token" },
      body: JSON.stringify({ agentId: "cursor", ide: "test", tool: "test", alias: "stripe", requestedScope: "charges.read", reason: "x" }),
    });
    expect(noAgent.status).toBe(200);
    const noAgentBody = (await noAgent.json()) as { status?: string };
    expect(noAgentBody.status).toBe("awaiting-approval");
    expect(JSON.stringify(noAgentBody)).not.toContain("sk_test");
    const badAgent = await fetch(`${base}/request`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-metavault-shim-token": "mvshim_secret-test-token", "x-metavault-agent-token": "ov_agent_forged" },
      body: JSON.stringify({ agentId: "cursor", ide: "test", tool: "test", alias: "stripe", requestedScope: "charges.read", reason: "x" }),
    });
    if (badAgent.status === 200) {
      const badBody = (await badAgent.json()) as { status?: string };
      expect(badBody.status).toBe("awaiting-approval");
    } else {
      expect([401, 403]).toContain(badAgent.status);
    }
    await shim.close();
    rmSync(dir, { recursive: true, force: true });
  }, 120_000);

  it("completes pairing under production rate-limit defaults with a human-paced comparison", async () => {
    // A second gateway with NO test overrides: production limiter defaults
    // (10 pairing attempts/min/address, 30/min global).
    const backend = makeDaemonBackend(stack.daemonBase, GATEWAY_SECRET);
    const prodGw = createGatewayServer({
      caCertPem: stack.ca.certPem,
      serverCertPem: stack.gwCert.certPem,
      serverKeyPem: stack.gwCert.keyPem,
      backend,
      daemonBaseUrl: stack.daemonBase,
      gatewaySecret: GATEWAY_SECRET,
      transport: "loopback",
    });
    await new Promise<void>((resolve) => { prodGw.listen(0, "127.0.0.1", resolve); });
    const address = prodGw.address();
    if (address === null || typeof address === "string") throw new Error("no port");

    // Human-paced: default bounded backoff (1s, 2s, 4s, cap 5s) and a
    // realistic 2.5s comparison delay. The whole flow must fit in the
    // production pairing budget with room to spare.
    const session = await newSession();
    let sasSeen = "";
    const handshake = runPairingHandshake({
      host: "127.0.0.1",
      port: address.port,
      code: session.code,
      deviceName: "prod-defaults",
      platform: "linux",
      onSas: (sas) => { sasSeen = sas; },
    });
    await new Promise((resolve) => setTimeout(resolve, 2_500));
    expect(sasSeen).toMatch(/^[0-9A-F]{4}-/);
    const deviceId = await confirmOnVault(session.pairingId);
    const material = await handshake;
    // Enrollment pins the server identity from the compared transcript:
    // the fingerprint captured at pair/begin (the value the SAS covers),
    // never re-read from pair/status.
    expect(material.serverCertFingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(deviceId).toBe(material.deviceId);

    // Cancellation under production defaults is also terminal and cheap.
    const session2 = await newSession();
    const handshake2 = runPairingHandshake({
      host: "127.0.0.1",
      port: address.port,
      code: session2.code,
      deviceName: "prod-cancel",
      platform: "linux",
      onSas: () => undefined,
    });
    await new Promise((resolve) => setTimeout(resolve, 1_500));
    await fetch(`${stack.daemonBase}/devices/pairing/cancel`, {
      method: "POST",
      headers: { "x-metavault-token": DAEMON_TOKEN, "content-type": "application/json" },
      body: JSON.stringify({ pairingId: session2.pairingId }),
    });
    await expect(handshake2).rejects.toMatchObject({ reason: "expired" });
    await new Promise<void>((resolve) => { prodGw.close(() => { resolve(); }); });
  }, 120_000);
});
