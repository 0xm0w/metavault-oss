import { describe, expect, it } from "vitest";
import { PresenceProofIssuer, SETTINGS_REMOTE_PROOF_SCOPE } from "../src/remote-approval-guard.js";
import { guardedDaemonCall, issuePresenceProof, type GuardDeps } from "../src/remote-approval-ipc.js";
import type { DaemonCallRequest } from "../src/daemon-client.js";

const NOW = 1_000_000;

function makeDeps(overrides: Partial<GuardDeps> = {}): GuardDeps & { forwarded: DaemonCallRequest[] } {
  const forwarded: DaemonCallRequest[] = [];
  return {
    issuer: new PresenceProofIssuer(),
    nowMs: () => NOW,
    getPending: () => Promise.resolve({ approvals: [{ grantId: "g-remote", origin: "remote" }] }),
    getRemoteSettings: () => Promise.resolve({ requireAuthForRemoteApproval: true }),
    verifyPin: (pin) => Promise.resolve(pin === "1234"),
    verifyHello: () => Promise.resolve(true),
    forward: (call) => { forwarded.push(call); return Promise.resolve({ ok: true }); },
    forwarded,
    ...overrides,
  };
}

describe("issuePresenceProof (trusted boundary)", () => {
  it("mints a scoped proof only after a real PIN verification", async () => {
    const deps = makeDeps();
    await expect(issuePresenceProof({ scope: "approve", grantId: "g-remote", pin: "wrong" }, deps)).rejects.toThrow(/not verified/);
    const { token } = await issuePresenceProof({ scope: "approve", grantId: "g-remote", pin: "1234" }, deps);
    expect(token.length).toBeGreaterThan(20);
    // proof is usable exactly once for that grant
    expect(deps.issuer.consume(token, "approve:g-remote", NOW)).toBe(true);
  });

  it("mints via Windows Hello and fails closed when neither factor verifies", async () => {
    const deps = makeDeps({ verifyHello: () => Promise.resolve(false), verifyPin: () => Promise.resolve(false) });
    await expect(issuePresenceProof({ scope: "approve", grantId: "g-remote", hello: true }, deps)).rejects.toThrow(/not verified/);
    await expect(issuePresenceProof({ scope: "approve", grantId: "g-remote" }, deps)).rejects.toThrow(/not verified/);
    const ok = makeDeps();
    const { token } = await issuePresenceProof({ scope: "settings-remote", hello: true }, ok);
    expect(ok.issuer.consume(token, SETTINGS_REMOTE_PROOF_SCOPE, NOW)).toBe(true);
  });

  it("rejects malformed requests", async () => {
    const deps = makeDeps();
    await expect(issuePresenceProof(null, deps)).rejects.toThrow(/malformed/);
    await expect(issuePresenceProof({ scope: "approve" }, deps)).rejects.toThrow(/malformed/);
  });
});

describe("guardedDaemonCall (forged IPC cannot bypass)", () => {
  it("rejects a bare approve of a remote grant and never forwards it", async () => {
    const deps = makeDeps();
    await expect(guardedDaemonCall({ method: "POST", path: "/approve", body: { grantId: "g-remote" } }, deps)).rejects.toThrow(/local presence/);
    expect(deps.forwarded).toEqual([]);
  });

  it("forwards an approve carrying a fresh proof, stripped of the proof field", async () => {
    const deps = makeDeps();
    const { token } = await issuePresenceProof({ scope: "approve", grantId: "g-remote", pin: "1234" }, deps);
    const result = await guardedDaemonCall({ method: "POST", path: "/approve", body: { grantId: "g-remote", __presenceProof: token } }, deps);
    expect(result).toEqual({ ok: true });
    expect(deps.forwarded).toEqual([{ method: "POST", path: "/approve", body: { grantId: "g-remote" } }]);
  });

  it("rejects disabling the remote presence requirement without proof", async () => {
    const deps = makeDeps();
    await expect(
      guardedDaemonCall({ method: "PATCH", path: "/settings/remote", body: { requireAuthForRemoteApproval: false } }, deps),
    ).rejects.toThrow(/local presence/);
    expect(deps.forwarded).toEqual([]);
  });

  it("passes ordinary calls through untouched", async () => {
    const deps = makeDeps();
    await guardedDaemonCall({ method: "GET", path: "/pending" }, deps);
    expect(deps.forwarded).toEqual([{ method: "GET", path: "/pending" }]);
  });
});
