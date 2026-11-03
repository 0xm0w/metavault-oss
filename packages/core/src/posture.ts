import type { AuditEvent } from "./types.js";
import type { CredentialMeta } from "./storage.js";
import { isWriteScope } from "./policy.js";

export interface SecurityPostureCheck {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly passed: boolean;
  readonly severity: "critical" | "warning" | "info";
  readonly scoreImpact: number;
}

export interface SecurityPostureIssue {
  readonly id: string;
  readonly title: string;
  readonly detail: string;
  readonly severity: "critical" | "warning" | "info";
  readonly alias?: string;
  readonly agentId?: string;
}

export interface SecurityPostureRemediation {
  readonly id: string;
  readonly title: string;
  readonly action: "enable-warden" | "restrict-ceiling" | "revoke-standing" | "rotate-stale";
  readonly alias?: string;
  readonly target?: string;
  readonly recommendedCeiling?: string;
}

export interface SecurityPostureReport {
  readonly score: number;
  readonly grade: "A+" | "A" | "B" | "C" | "D" | "F";
  readonly summary: string;
  readonly checks: readonly SecurityPostureCheck[];
  readonly issues: readonly SecurityPostureIssue[];
  readonly remediations: readonly SecurityPostureRemediation[];
}

export interface PostureInput {
  readonly credentials: readonly CredentialMeta[];
  readonly standingApprovals: readonly { readonly agentId: string; readonly alias: string; readonly scope: string }[];
  readonly auditEvents: readonly AuditEvent[];
  readonly wardenProvider: string;
  readonly nowMs?: number;
}

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

export function calculateSecurityPosture(input: PostureInput): SecurityPostureReport {
  const now = input.nowMs ?? Date.now();
  const checks: SecurityPostureCheck[] = [];
  const issues: SecurityPostureIssue[] = [];
  const remediations: SecurityPostureRemediation[] = [];

  // Check 1: Active Warden Protection
  const wardenActive = input.wardenProvider !== "none";
  checks.push({
    id: "warden-guard",
    name: "AI Warden Guard Active",
    description: "Evaluates capability requests for disguised writes and prompt injection.",
    passed: wardenActive,
    severity: "critical",
    scoreImpact: 35,
  });

  if (!wardenActive) {
    issues.push({
      id: "warden-disabled",
      title: "AI Warden is Disabled",
      detail: "The vault is operating in deterministic policy-only mode without semantic risk checks.",
      severity: "critical",
    });
    remediations.push({
      id: "rem-enable-warden",
      title: "Enable On-Device Muse Glimmer Warden",
      action: "enable-warden",
    });
  }

  // Check 2: No Wildcard Ceilings
  const wildcardCreds = input.credentials.filter((c) => c.scopeCeiling === "*.*" || c.scopeCeiling === "*");
  const noWildcards = wildcardCreds.length === 0;
  checks.push({
    id: "wildcard-check",
    name: "Principle of Least Privilege",
    description: "Prevents unrestricted wildcard access (*.*) to APIs.",
    passed: noWildcards,
    severity: "critical",
    scoreImpact: 25,
  });

  for (const c of wildcardCreds) {
    issues.push({
      id: "wildcard-ceiling",
      title: `Wildcard ceiling on alias '${c.alias}'`,
      detail: "Unrestricted ceiling permits any operation allowed by upstream API credentials.",
      severity: "critical",
      alias: c.alias,
    });
    remediations.push({
      id: `rem-ceiling-${c.alias}`,
      title: `Restrict ceiling on '${c.alias}' to scoped read`,
      action: "restrict-ceiling",
      alias: c.alias,
      recommendedCeiling: "read",
    });
  }

  // Check 3: Standing Approvals on Write Operations
  const riskyStanding = input.standingApprovals.filter((s) => isWriteScope(s.scope));
  const noRiskyStanding = riskyStanding.length === 0;
  checks.push({
    id: "standing-approval-check",
    name: "Human-in-the-Loop on Write Scopes",
    description: "Ensures destructive write actions always require human confirmation.",
    passed: noRiskyStanding,
    severity: "warning",
    scoreImpact: 20,
  });

  for (const s of riskyStanding) {
    issues.push({
      id: "risky-standing-approval",
      title: `Standing approval for write scope '${s.scope}'`,
      detail: `Agent '${s.agentId}' has standing permission to perform mutations without human approval.`,
      severity: "warning",
      alias: s.alias,
      agentId: s.agentId,
    });
    remediations.push({
      id: `rem-revoke-${s.agentId}-${s.alias}`,
      title: `Revoke standing write approval for '${s.agentId}' on '${s.alias}'`,
      action: "revoke-standing",
      alias: s.alias,
      target: s.agentId,
    });
  }

  // Check 4: Stale or Inactive Credentials
  const lastUsedByAlias = new Map<string, number>();
  for (const e of input.auditEvents) {
    const time = Date.parse(e.ts);
    if (!Number.isNaN(time)) {
      const prev = lastUsedByAlias.get(e.alias) ?? 0;
      if (time > prev) {
        lastUsedByAlias.set(e.alias, time);
      }
    }
  }

  const staleCreds = input.credentials.filter((c) => {
    const lastUsed = lastUsedByAlias.get(c.alias);
    if (lastUsed === undefined) return false; // newly created or uncalled
    return now - lastUsed > THIRTY_DAYS_MS;
  });

  const noStale = staleCreds.length === 0;
  checks.push({
    id: "stale-credentials-check",
    name: "Credential Freshness",
    description: "Ensures unused or stale credentials are regularly audited or rotated.",
    passed: noStale,
    severity: "info",
    scoreImpact: 10,
  });

  for (const s of staleCreds) {
    issues.push({
      id: "stale-credential",
      title: `Inactive credential '${s.alias}'`,
      detail: "No agent requests in the past 30 days.",
      severity: "info",
      alias: s.alias,
    });
    remediations.push({
      id: `rem-rotate-${s.alias}`,
      title: `Audit or rotate credential '${s.alias}'`,
      action: "rotate-stale",
      alias: s.alias,
    });
  }

  // Check 5: Attack & Blocked Request Density
  const recentDenials = input.auditEvents.filter((e) => {
    const t = Date.parse(e.ts);
    return !Number.isNaN(t) && now - t < 7 * 24 * 60 * 60 * 1000 && e.stage === "denied";
  });
  const lowDenials = recentDenials.length < 10;
  checks.push({
    id: "threat-density-check",
    name: "Low Attack / Escalation Velocity",
    description: "Flags frequent policy violations or prompt injection attempts.",
    passed: lowDenials,
    severity: "warning",
    scoreImpact: 10,
  });

  // Calculate composite score (0-100)
  let score = 100;
  for (const c of checks) {
    if (!c.passed) {
      score -= c.scoreImpact;
    }
  }
  score = Math.max(0, Math.min(100, score));

  let grade: SecurityPostureReport["grade"];
  if (score >= 95) grade = "A+";
  else if (score >= 85) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 60) grade = "C";
  else if (score >= 45) grade = "D";
  else grade = "F";

  const summary =
    score >= 85
      ? "Vault posture is strong. Least privilege is actively enforced."
      : score >= 60
        ? "Vault posture is moderate. Review recommended remediations."
        : "Vault posture requires immediate attention to prevent privilege escalation.";

  return {
    score,
    grade,
    summary,
    checks,
    issues,
    remediations,
  };
}
