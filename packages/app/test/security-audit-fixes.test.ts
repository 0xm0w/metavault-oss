// File: packages/app/test/security-audit-fixes.test.ts
import { describe, expect, it } from "vitest";
import {
  AGENTS_ROTATE_PROOF_SCOPE,
  PresenceProofIssuer,
  guardAgentRotateCall,
} from "../src/remote-approval-guard.js";

describe("Security Audit Fixes — Electron IPC Agent Token Guard", () => {
  it("blocks POST /agents, POST /agents/rotate, and POST /agents/revoke without a valid presence proof", () => {
    const issuer = new PresenceProofIssuer();
    const nowMs = 1_700_000_000_000;

    for (const path of ["/agents", "/agents/rotate", "/agents/revoke"]) {
      const denied = guardAgentRotateCall({
        method: "POST",
        path,
        body: { id: "cursor", name: "Cursor" },
        issuer,
        nowMs,
      });
      expect(denied.decision.allow).toBe(false);
    }
  });

  it("allows POST /agents and forwards daemonProof as presenceProof when a valid proof is supplied", () => {
    const issuer = new PresenceProofIssuer();
    const nowMs = 1_700_000_000_000;
    const uiProof = issuer.issue(AGENTS_ROTATE_PROOF_SCOPE, nowMs, "daemon_proof_abc123");

    const allowed = guardAgentRotateCall({
      method: "POST",
      path: "/agents",
      body: { id: "cursor", name: "Cursor", __presenceProof: uiProof },
      issuer,
      nowMs: nowMs + 100,
    });
    expect(allowed.decision.allow).toBe(true);
    expect((allowed.body as Record<string, unknown>)["presenceProof"]).toBe("daemon_proof_abc123");
    expect((allowed.body as Record<string, unknown>)["__presenceProof"]).toBeUndefined();
  });
});
