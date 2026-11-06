// Device-side client tests (WP5/DD7): pairing handshake UX contract,
// credential storage permissions, post-enrollment pinning, and the
// loopback shim channel.
import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { request as httpRequest } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createGatewayServers } from "../src/server.js";
import { makeDaemonBackend } from "../src/daemon-backend.js";
import {
  currentWindowsUserSid,
  defaultListAclSids,
  hardenOwnerOnly,
  isParentAclSafe,
  loadDeviceProfile,
  nextPollDelay,
  PairingError,
  PAIRING_POLL_CAP_MS,
  PAIRING_POLL_START_MS,
  runPairingHandshake,
  saveDeviceProfile,
  startShim,
} from "../src/device-client.js";
import { DAEMON_TOKEN, GATEWAY_SECRET, makeStack, type Stack } from "./stack.js";

// Windows Temp grants extra principals, so saveDeviceProfile refuses a
// profile whose parent is Temp. Harden a private parent first.
function profileDir(prefix: string): { root: string; dir: string } {
  const root = mkdtempSync(join(tmpdir(), prefix));
  hardenOwnerOnly(root, true);
  return { root, dir: mkdtempSync(join(root, "profile-")) };
}

/** Poll until the condition holds (fixed sleeps are racy on a loaded CI runner). */
async function until(cond: () => boolean, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() >= deadline) throw new Error("condition not met in time");
    await new Promise((r) => setTimeout(r, 25));
  }
}

describe("device-client", () => {
  let stack: Stack;
  beforeAll(async () => {
    stack = await makeStack();
  }, 120_000);
  afterAll(async () => {
    await new Promise<void>((resolve) => stack.gateway.close(() => { resolve(); }));
    await new Promise<void>((resolve) => stack.gatewayDevice.close(() => { resolve(); }));
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
    await until(() => shownSas !== "");
    expect(shownSas).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/);
    const view = await (await fetch(`${stack.daemonBase}/devices/pairing`, { headers: { "x-metavault-token": DAEMON_TOKEN } })).json() as { session: { sas?: string } | null };
    expect(view.session?.sas).toBe(shownSas);
    const deviceId = await confirmOnVault(session.pairingId);
    const material = await handshake;

    expect(material.devicePort).toBe(stack.gatewayDevicePort);
    const { root, dir } = profileDir("mv-device-");
    saveDeviceProfile(dir, {
      deviceId,
      host: "127.0.0.1",
      port: material.devicePort,
      pairedAt: new Date().toISOString(),
      serverCertFingerprint: material.serverCertFingerprint,
    }, material, "mvshim_test-token-1");
    // POSIX mode bits are the enforcement on POSIX. On Windows they are a
    // no-op (observed 0o666) and owner-only is enforced + verified via ACLs
    // inside saveDeviceProfile, so the mode assertion is POSIX-only.
    if (process.platform !== "win32") {
      expect(statSync(join(dir, "key.pem")).mode & 0o777).toBe(0o600);
      expect(statSync(join(dir, "device.json")).mode & 0o777).toBe(0o600);
    }
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
    rmSync(root, { recursive: true, force: true });
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
    let sasSeen = false;
    const handshake = runPairingHandshake({
      host: "127.0.0.1",
      port: stack.gatewayPort,
      code: session.code,
      deviceName: "cancel-me",
      platform: "linux",
      onSas: () => { sasSeen = true; },
      pollIntervalMs: 50,
    });
    await until(() => sasSeen);
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
    let sasSeen = false;
    const handshake = runPairingHandshake({
      host: "127.0.0.1",
      port: stack.gatewayPort,
      code: session.code,
      deviceName: "pin-check",
      platform: "linux",
      onSas: () => { sasSeen = true; },
      pollIntervalMs: 50,
    });
    await until(() => sasSeen);
    const deviceId = await confirmOnVault(session.pairingId);
    const material = await handshake;
    const { root, dir } = profileDir("mv-device-pin-");
    saveDeviceProfile(dir, {
      deviceId,
      host: "127.0.0.1",
      port: stack.gatewayDevicePort,
      pairedAt: new Date().toISOString(),
      // Simulate a different gateway key than the one seen at pairing.
      serverCertFingerprint: "0".repeat(64),
    }, material, "mvshim_test-token-2");
    const shim = await startShim({ profileDir: dir, port: 0 });
    const res = await fetch(`http://127.0.0.1:${String(shim.port)}/health`, { headers: { "x-metavault-shim-token": "mvshim_test-token-2" } });
    expect(res.status).toBe(502);
    await shim.close();
    rmSync(root, { recursive: true, force: true });
  }, 120_000);

  it("shim demands its local token and refuses browser-style callers", async () => {
    const session = await newSession();
    let sasSeen = false;
    const handshake = runPairingHandshake({
      host: "127.0.0.1",
      port: stack.gatewayPort,
      code: session.code,
      deviceName: "shim-auth",
      platform: "linux",
      onSas: () => { sasSeen = true; },
      pollIntervalMs: 50,
    });
    await until(() => sasSeen);
    const deviceId = await confirmOnVault(session.pairingId);
    const material = await handshake;
    const { root, dir } = profileDir("mv-device-auth-");
    saveDeviceProfile(dir, {
      deviceId,
      host: "127.0.0.1",
      port: stack.gatewayDevicePort,
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
    // response must carry no credential material. Note: an unverified
    // caller claiming an ENROLLED agent id ("cursor") is rejected outright
    // (unverified-enrolled-agent-spoof), so the pending-approval path is
    // exercised with an unenrolled id.
    const spoof = await fetch(`${base}/request`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-metavault-shim-token": "mvshim_secret-test-token" },
      body: JSON.stringify({ agentId: "cursor", ide: "test", tool: "test", alias: "stripe", requestedScope: "charges.read", reason: "x" }),
    });
    const spoofBody = (await spoof.json()) as { status?: string; reason?: string };
    expect(spoofBody.status).toBe("denied");
    expect(spoofBody.reason).toBe("unverified-enrolled-agent-spoof");
    const noAgent = await fetch(`${base}/request`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-metavault-shim-token": "mvshim_secret-test-token" },
      body: JSON.stringify({ agentId: "unenrolled-test-agent", ide: "test", tool: "test", alias: "stripe", requestedScope: "charges.read", reason: "x" }),
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
      const badBody = (await badAgent.json()) as { status?: string; reason?: string };
      expect(badBody.status).toBe("denied");
      expect(badBody.reason).toBe("unverified-enrolled-agent-spoof");
    } else {
      expect([401, 403]).toContain(badAgent.status);
    }
    await shim.close();
    rmSync(root, { recursive: true, force: true });
  }, 120_000);

  it("completes pairing under production rate-limit defaults with a human-paced comparison", async () => {
    // A second gateway with NO test overrides: production limiter defaults
    // (10 pairing attempts/min/address, 30/min global).
    const backend = makeDaemonBackend(stack.daemonBase, GATEWAY_SECRET);
    const prodGw = createGatewayServers({
      caCertPem: stack.ca.certPem,
      serverCertPem: stack.gwCert.certPem,
      serverKeyPem: stack.gwCert.keyPem,
      backend,
      daemonBaseUrl: stack.daemonBase,
      gatewaySecret: GATEWAY_SECRET,
      transport: "loopback",
    });
    await new Promise<void>((resolve) => { prodGw.pairing.listen(0, "127.0.0.1", resolve); });
    await new Promise<void>((resolve) => { prodGw.device.listen(0, "127.0.0.1", resolve); });
    const address = prodGw.pairing.address();
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
    await until(() => sasSeen !== "", 15_000);
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
    await new Promise<void>((resolve) => { prodGw.pairing.close(() => { resolve(); }); });
    await new Promise<void>((resolve) => { prodGw.device.close(() => { resolve(); }); });
  }, 120_000);

  it("verifies Windows ACLs from trustee SIDs, never names or exit codes", () => {
    const sid = "S-1-5-21-1000-2000-3000-1001";
    // Trustee SIDs are read via PowerShell SID translation in production
    // (covered by the win32 integration tests below against a real runner);
    // SDDL aliases like "LA" (machine-relative RID 500) can never be
    // resolved by string parsing, so parsing SDDL is not the mechanism.
    // hardenOwnerOnly grants by SID (*SID syntax) and verifies the
    // effective ACL contains ONLY that SID; the runner's exit output is
    // never consulted.
    const calls: string[][] = [];
    hardenOwnerOnly(
      "C:\\x",
      false,
      "win32",
      (args) => {
        calls.push([...args]);
        return "";
      },
      { allowedRoots: ["C:\\"], userSid: sid, listSids: () => [sid] },
    );
    expect(calls.map((c) => c.slice(1).join(" "))).toEqual(["/reset", "/inheritance:r", `/grant:r *${sid}:(F)`]);
    // A preexisting explicit grant to another principal fails closed.
    expect(() => {
      hardenOwnerOnly("C:\\x", false, "win32", () => "", {
        allowedRoots: ["C:\\"],
        userSid: sid,
        listSids: () => [sid, "S-1-5-21-1000-2000-3000-1002"],
      });
    }).toThrow(/owner-only/);
    // Same account NAME in another domain is a different SID and fails.
    expect(() => {
      hardenOwnerOnly("C:\\x", false, "win32", () => "", {
        allowedRoots: ["C:\\"],
        userSid: sid,
        listSids: () => ["S-1-5-21-9999-8888-7777-1001"],
      });
    }).toThrow(/owner-only/);
    // No SID resolved: fail closed, never fall back to name matching.
    // (Explicit null forces the unresolved path even on a real Windows
    // machine, where whoami would otherwise resolve.)
    expect(() => {
      hardenOwnerOnly("C:\\x", false, "win32", () => "", { allowedRoots: ["C:\\"], userSid: null });
    }).toThrow(/SID/);
  });

  it("refuses ACL changes outside the device credential root", () => {
    const sid = "S-1-5-21-1000-2000-3000-1001";
    expect(() => {
      hardenOwnerOnly("C:\\Users\\alice\\Documents", true, "win32", () => "", {
        allowedRoots: ["C:\\metavault-device"],
        userSid: sid,
        listSids: () => [sid],
      });
    }).toThrow(/outside/);
  });

  it("refuses to store credentials in a preexisting directory with unrelated contents", () => {
    const dir = mkdtempSync(join(tmpdir(), "mv-foreign-"));
    writeFileSync(join(dir, "unrelated.txt"), "not ours");
    expect(() => {
      saveDeviceProfile(
        dir,
        { deviceId: "dev-x", host: "127.0.0.1", port: 9443, pairedAt: "2026-11-04T00:00:00Z", serverCertFingerprint: "f" },
        { deviceId: "dev-x", keyPem: "k", certPem: "c", caCertPem: "a", serverCertFingerprint: "f", devicePort: 9443 },
        "mvshim_x",
      );
    }).toThrow(/unrelated/);
  });

  it("accepts only owner + SYSTEM/Administrators on the credential parent", () => {
    const sid = "S-1-5-21-1000-2000-3000-1001";
    expect(isParentAclSafe([sid, "S-1-5-18", "S-1-5-32-544"], sid)).toBe(true);
    expect(isParentAclSafe([sid, "S-1-1-0"], sid)).toBe(false);
    expect(isParentAclSafe([sid, "S-1-5-11"], sid)).toBe(false);
    expect(isParentAclSafe([], sid)).toBe(false);
  });

  it("keeps the pairing poll budget inside production limits for a 5-minute comparison", () => {
    // Simulated clock: count requests per rolling 60s window over the
    // full 5-minute pairing TTL using the shipped backoff schedule.
    const delays: number[] = [];
    let d = PAIRING_POLL_START_MS;
    let elapsed = 0;
    while (elapsed < 5 * 60_000) {
      delays.push(d);
      elapsed += d;
      d = nextPollDelay(d, PAIRING_POLL_CAP_MS);
    }
    const starts = [0];
    let acc = 0;
    for (const delay of delays) {
      acc += delay;
      starts.push(acc);
    }
    // Production budget: 10 pair/begin+status... begin is separate;
    // /pair/status allows 60/min/address. Worst rolling window must fit.
    let worst = 0;
    for (let i = 0; i < starts.length; i += 1) {
      const windowStart = starts[i] ?? 0;
      const count = starts.filter((t) => t >= windowStart && t < windowStart + 60_000).length;
      worst = Math.max(worst, count);
    }
    expect(worst).toBeLessThanOrEqual(20);
    // And a >1 minute delayed human still completes: total requests for a
    // 90s comparison are a fraction of the 60/min status budget.
    const at90s = starts.filter((t) => t <= 90_000).length;
    expect(at90s).toBeLessThanOrEqual(25);
  });
});

// Real-icacls integration coverage. Skipped everywhere except Windows so the
// gap stays visible in CI logs until a windows-latest runner carries it;
// the mocked ACE parser tests above are not a substitute for these.
const onWindows = process.platform === "win32";
describe.skipIf(!onWindows)("windows effective-ACL integration (requires win32 runner)", () => {
  it("hardens a real directory to the current user alone, verified by SDDL", () => {
    const dir = mkdtempSync(join(tmpdir(), "mv-acl-ok-"));
    hardenOwnerOnly(dir, true, "win32");
    const sid = currentWindowsUserSid();
    expect(sid).toBeDefined();
    // The effective ACL, parsed from real icacls /save SDDL, is exactly
    // the current user's SID - nothing inherited, nobody else.
    expect(defaultListAclSids(dir)).toEqual([(sid ?? "").toUpperCase()]);
  });

  it("strips a preexisting foreign grant down to the owner alone", () => {
    const dir = mkdtempSync(join(tmpdir(), "mv-acl-bad-"));
    execFileSync("icacls", [dir, "/inheritance:r"]);
    execFileSync("icacls", [dir, "/grant:r", "Everyone:(R)"]);
    hardenOwnerOnly(dir, true, "win32");
    const sid = currentWindowsUserSid();
    expect(sid).toBeDefined();
    expect(defaultListAclSids(dir)).toEqual([(sid ?? "").toUpperCase()]);
  });

  it("hardens a real credential file to the current user alone", () => {
    const dir = mkdtempSync(join(tmpdir(), "mv-acl-file-"));
    const file = join(dir, "key.pem");
    writeFileSync(file, "k");
    hardenOwnerOnly(file, false, "win32");
    const sid = currentWindowsUserSid();
    expect(sid).toBeDefined();
    expect(defaultListAclSids(file)).toEqual([(sid ?? "").toUpperCase()]);
  });

  it("strips a preexisting foreign grant on a file down to the owner alone", () => {
    const dir = mkdtempSync(join(tmpdir(), "mv-acl-filebad-"));
    const file = join(dir, "key.pem");
    writeFileSync(file, "k");
    execFileSync("icacls", [file, "/inheritance:r"]);
    execFileSync("icacls", [file, "/grant:r", "Everyone:(R)"]);
    hardenOwnerOnly(file, false, "win32");
    const sid = currentWindowsUserSid();
    expect(sid).toBeDefined();
    expect(defaultListAclSids(file)).toEqual([(sid ?? "").toUpperCase()]);
  });
});
