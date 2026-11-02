import { describe, expect, it } from "vitest";
import { calculateSecurityPosture, type SecurityPostureReport } from "../src/posture.js";
import type { AuditEvent } from "../src/types.js";
import type { CredentialMeta } from "../src/storage.js";

describe("Security Posture Scoring Engine (#20)", () => {
  const credentials: CredentialMeta[] = [
    { alias: "stripe", scopeCeiling: "charges.read", website: "stripe.com" },
    { alias: "github", scopeCeiling: "repos.write", website: "github.com" },
  ];

  const standingApprovals = [
    { agentId: "cursor", alias: "stripe", scope: "charges.read" },
  ];

  const now = Date.parse("2026-11-01T12:00:00.000Z");

  it("calculates a baseline posture score and flags over-permissive or risky settings", () => {
    const auditEvents: AuditEvent[] = [
      {
        ts: new Date(now - 3600_000).toISOString(),
        agentId: "cursor",
        alias: "stripe",
        scope: "charges.read",
        stage: "executed",
        detail: "executed",
      },
    ];

    const posture: SecurityPostureReport = calculateSecurityPosture({
      credentials,
      standingApprovals,
      auditEvents,
      wardenProvider: "ollama",
      nowMs: now,
    });

    expect(posture.score).toBeGreaterThan(0);
    expect(posture.score).toBeLessThanOrEqual(100);
    expect(posture.checks.length).toBeGreaterThan(0);
    expect(typeof posture.grade).toBe("string");
  });

  it("penalizes disabled warden (provider = none) and over-permissive write credentials", () => {
    const unhardenedCredentials: CredentialMeta[] = [
      { alias: "aws", scopeCeiling: "*.*", website: "" },
      { alias: "prod-db", scopeCeiling: "db.write", website: "" },
    ];

    const riskyStanding = [
      { agentId: "untrusted-agent", alias: "prod-db", scope: "db.write" },
    ];

    const posture = calculateSecurityPosture({
      credentials: unhardenedCredentials,
      standingApprovals: riskyStanding,
      auditEvents: [],
      wardenProvider: "none",
      nowMs: now,
    });

    expect(posture.score).toBeLessThan(70);
    const issueIds = posture.issues.map((i) => i.id);
    expect(issueIds).toContain("warden-disabled");
    expect(issueIds).toContain("wildcard-ceiling");
  });

  it("provides actionable remediation advice with one-click fix definitions", () => {
    const posture = calculateSecurityPosture({
      credentials: [{ alias: "legacy", scopeCeiling: "*.*", website: "" }],
      standingApprovals: [],
      auditEvents: [],
      wardenProvider: "none",
      nowMs: now,
    });

    expect(posture.remediations.length).toBeGreaterThan(0);
    const fixTypes = posture.remediations.map((r) => r.action);
    expect(fixTypes).toContain("enable-warden");
  });

  it("flags credentials idle for over 30 days with a rotate remediation", () => {
    const staleEvents: AuditEvent[] = [
      {
        ts: "2026-09-01T12:00:00.000Z",
        agentId: "cursor",
        alias: "stripe",
        scope: "charges.read",
        stage: "executed",
        detail: "ok",
      },
    ];
    const posture = calculateSecurityPosture({
      credentials: [{ alias: "stripe", scopeCeiling: "charges.read", website: "" }],
      standingApprovals: [],
      auditEvents: staleEvents,
      wardenProvider: "ollama",
      nowMs: now,
    });

    const issueIds = posture.issues.map((i) => i.id);
    expect(issueIds).toContain("stale-credential");
    const fixTypes = posture.remediations.map((r) => r.action);
    expect(fixTypes).toContain("rotate-stale");
  });
});
