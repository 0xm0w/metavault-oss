import { describe, expect, it } from "vitest";
import {
  PresenceProofIssuer,
  SETTINGS_REMOTE_PROOF_SCOPE,
  guardApprovalCall,
  guardRemoteSettingsCall,
  remotePresenceRequired,
} from "../src/remote-approval-guard.js";

const NOW = 1_000_000;
const pendingWithRemote = {
  approvals: [
    { grantId: "g-remote", origin: "remote", deviceId: "dev-1" },
    { grantId: "g-local", origin: "local" },
  ],
};

function makeCalls(settingsRaw: unknown = { requireAuthForRemoteApproval: true }) {
  return {
    getPending: () => Promise.resolve(pendingWithRemote),
    getRemoteSettings: () => Promise.resolve(settingsRaw),
  };
}

describe("presence proofs", () => {
  it("are single-use, scope-bound, and expire", () => {
    const issuer = new PresenceProofIssuer();
    const token = issuer.issue("approve:g1", NOW);
    expect(issuer.consume(token, "approve:g1", NOW + 1000)).toEqual({ daemonProof: undefined });
    // replay fails
    expect(issuer.consume(token, "approve:g1", NOW + 1000)).toBeNull();
    const other = issuer.issue("approve:g1", NOW);
    // wrong scope fails and consumes
    expect(issuer.consume(other, "approve:g2", NOW + 1000)).toBeNull();
    expect(issuer.consume(other, "approve:g1", NOW + 1000)).toBeNull();
    const stale = issuer.issue("approve:g1", NOW);
    expect(issuer.consume(stale, "approve:g1", NOW + 61_000)).toBeNull();
    expect(issuer.consume("", "approve:g1", NOW)).toBeNull();
    expect(issuer.consume(undefined, "approve:g1", NOW)).toBeNull();
  });
});

describe("remote approval guard (trusted boundary)", () => {
  it("rejects a forged approve IPC for a remote grant without a proof", async () => {
    const issuer = new PresenceProofIssuer();
    const result = await guardApprovalCall({
      path: "/approve",
      body: { grantId: "g-remote" },
      issuer,
      nowMs: NOW,
      ...makeCalls(),
    });
    expect(result.decision.allow).toBe(false);
    expect(result.decision.reason).toMatch(/local presence/);
  });

  it("fails closed when remote settings are unreadable or default", async () => {
    const issuer = new PresenceProofIssuer();
    for (const settings of [null, {}, { requireAuthForRemoteApproval: true }]) {
      const result = await guardApprovalCall({
        path: "/approve",
        body: { grantId: "g-remote" },
        issuer,
        nowMs: NOW,
        ...makeCalls(settings),
      });
      expect(result.decision.allow).toBe(false);
    }
  });

  it("allows with a fresh scoped proof and strips the proof before forwarding", async () => {
    const issuer = new PresenceProofIssuer();
    const token = issuer.issue("approve:g-remote", NOW);
    const result = await guardApprovalCall({
      path: "/approve",
      body: { grantId: "g-remote", __presenceProof: token },
      issuer,
      nowMs: NOW + 500,
      ...makeCalls(),
    });
    expect(result.decision.allow).toBe(true);
    expect(result.body).toEqual({ grantId: "g-remote" });
    // replay of the same proof fails
    const replay = await guardApprovalCall({
      path: "/approve",
      body: { grantId: "g-remote", __presenceProof: token },
      issuer,
      nowMs: NOW + 600,
      ...makeCalls(),
    });
    expect(replay.decision.allow).toBe(false);
  });

  it("rejects a proof minted for a different grant", async () => {
    const issuer = new PresenceProofIssuer();
    const token = issuer.issue("approve:g-local", NOW);
    const result = await guardApprovalCall({
      path: "/approve",
      body: { grantId: "g-remote", __presenceProof: token },
      issuer,
      nowMs: NOW + 500,
      ...makeCalls(),
    });
    expect(result.decision.allow).toBe(false);
  });

  it("does not gate local grants or non-approval paths", async () => {
    const issuer = new PresenceProofIssuer();
    const local = await guardApprovalCall({
      path: "/approve",
      body: { grantId: "g-local" },
      issuer,
      nowMs: NOW,
      ...makeCalls(),
    });
    expect(local.decision.allow).toBe(true);
    const deny = await guardApprovalCall({
      path: "/deny",
      body: { grantId: "g-remote" },
      issuer,
      nowMs: NOW,
      ...makeCalls(),
    });
    expect(deny.decision.allow).toBe(true);
  });

  it("respects an explicit user opt-out while the setting is off", async () => {
    const issuer = new PresenceProofIssuer();
    const result = await guardApprovalCall({
      path: "/approve",
      body: { grantId: "g-remote" },
      issuer,
      nowMs: NOW,
      ...makeCalls({ requireAuthForRemoteApproval: false }),
    });
    expect(result.decision.allow).toBe(true);
  });

  it("remotePresenceRequired fires for remote origin and fails closed for unknown origin", () => {
    expect(remotePresenceRequired({ grantId: "g", origin: "remote" }, null)).toBe(true);
    expect(remotePresenceRequired({ grantId: "g", origin: "local" }, null)).toBe(false);
    // A grant that vanished between listing and approval (replacement race)
    // must not inherit the local fast path.
    expect(remotePresenceRequired(null, null)).toBe(true);
    expect(remotePresenceRequired({ grantId: "g" }, null)).toBe(false);
  });
});

describe("remote settings guard", () => {
  it("disabling the presence requirement itself needs fresh presence", () => {
    const issuer = new PresenceProofIssuer();
    const denied = guardRemoteSettingsCall({
      method: "PATCH",
      path: "/settings/remote",
      body: { requireAuthForRemoteApproval: false },
      issuer,
      nowMs: NOW,
    });
    expect(denied.allow).toBe(false);
    const token = issuer.issue(SETTINGS_REMOTE_PROOF_SCOPE, NOW);
    const allowed = guardRemoteSettingsCall({
      method: "PATCH",
      path: "/settings/remote",
      body: { requireAuthForRemoteApproval: false, __presenceProof: token },
      issuer,
      nowMs: NOW + 100,
    });
    expect(allowed.allow).toBe(true);
  });

  it("does not gate other settings changes or paths", () => {
    const issuer = new PresenceProofIssuer();
    expect(guardRemoteSettingsCall({ method: "PATCH", path: "/settings/remote", body: { enabled: true }, issuer, nowMs: NOW }).allow).toBe(true);
    expect(guardRemoteSettingsCall({ method: "PATCH", path: "/settings/remote", body: { requireAuthForRemoteApproval: true }, issuer, nowMs: NOW }).allow).toBe(true);
    expect(guardRemoteSettingsCall({ method: "PATCH", path: "/settings/warden", body: { requireAuthForRemoteApproval: false }, issuer, nowMs: NOW }).allow).toBe(true);
  });
});
