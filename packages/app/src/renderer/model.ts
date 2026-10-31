import type {
  AuditEventLike,
  AuditStage,
  PendingApproval,
  PoliciesData,
  Risk,
  StandingApproval,
} from "./types.js";

// Direction B — Marshal Light (design spec Section 7.1). These exact hex
// values are the theme contract; styles.css mirrors them as CSS variables.
export const TOKENS = {
  surface: "#FFFFFF",
  surfaceAlt: "#F8FAFC",
  navy: "#1E3A5F",
  approve: "#16A34A",
  deny: "#DC2626",
  warn: "#D97706",
  ink: "#17233B",
  border: "#DBE3EE",
} as const;

export const MARSHAL_DEFAULT_LINE = "Marshal · Llama 3.2 3B · On-device";

export function marshalStatusLine(modelId?: string): string {
  if (modelId === undefined || modelId === "") {
    return MARSHAL_DEFAULT_LINE;
  }
  const lower = modelId.toLowerCase();
  if (lower.includes("llama3.2") || lower.includes("llama 3.2")) {
    return MARSHAL_DEFAULT_LINE;
  }
  if (lower.includes("glimmer")) {
    return "Marshal · Muse Glimmer 30B · On-device";
  }
  return `Marshal · ${modelId} · On-device`;
}

const WRITE_MARKERS = [".write", ".create", ".update", ".delete"] as const;

// Mirrors the daemon policy write test: a scope is a write when it carries
// a write marker. Everything else with a non-empty name reads as read-only.
export function isWriteScope(scope: string): boolean {
  return WRITE_MARKERS.some((marker) => scope.includes(marker)) || scope.endsWith(":write");
}

export function isReadOnlyScope(scope: string): boolean {
  return scope.length > 0 && !isWriteScope(scope);
}

// "Always allow" creates a standing approval, so it is offered only where
// the daemon will accept one: read-only scope, marshal-rated low risk.
export function canAlwaysAllow(approval: PendingApproval): boolean {
  return approval.risk === "low" && isReadOnlyScope(approval.allowedScope);
}

export function formatExpiry(expiresAtMs: number, nowMs: number): string {
  const remainingMs = expiresAtMs - nowMs;
  if (remainingMs <= 0) {
    return "Expired";
  }
  const totalSeconds = Math.floor(remainingMs / 1000);
  if (totalSeconds < 60) {
    return `Expires in ${String(totalSeconds)}s`;
  }
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `Expires in ${String(minutes)}m ${String(seconds)}s`;
}

export function formatLastUsed(tsIso: string | null, nowMs: number): string {
  if (tsIso === null) {
    return "Never used";
  }
  const then = Date.parse(tsIso);
  if (Number.isNaN(then)) {
    return "Never used";
  }
  const diffMs = nowMs - then;
  if (diffMs < 60_000) {
    return "Just now";
  }
  if (diffMs < 3_600_000) {
    return `${String(Math.floor(diffMs / 60_000))}m ago`;
  }
  if (diffMs < 86_400_000) {
    return `${String(Math.floor(diffMs / 3_600_000))}h ago`;
  }
  return `${String(Math.floor(diffMs / 86_400_000))}d ago`;
}

// ---------------------------------------------------------------------------
// Payload projection. Daemon payloads are data, not trust: the renderer
// rebuilds every object from whitelisted fields only, and drops any payload
// carrying a secret-like key outright (fail closed — a payload that smells
// like a secret is never rendered, under any field-name variant).
// ---------------------------------------------------------------------------

const SECRET_KEY_PATTERN =
  /(secret|password|passwd|pwd|token|credential|private.?key|api.?key|raw.?key|cipher|bearer)/i;

export function findSecretLikeKeys(value: unknown, prefix = ""): string[] {
  const found: string[] = [];
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      found.push(...findSecretLikeKeys(item, `${prefix}${String(index)}.`));
    });
    return found;
  }
  if (typeof value === "object" && value !== null) {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const path = `${prefix}${key}`;
      if (SECRET_KEY_PATTERN.test(key)) {
        found.push(path);
      }
      found.push(...findSecretLikeKeys(child, `${path}.`));
    }
  }
  return found;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringField(record: Record<string, unknown>, key: string): string | null {
  const value = record[key];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function numberField(record: Record<string, unknown>, key: string): number | null {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

const RISKS: readonly Risk[] = ["low", "medium", "high"];

export function projectApproval(raw: unknown): PendingApproval | null {
  if (!isRecord(raw) || findSecretLikeKeys(raw).length > 0) {
    return null;
  }
  const grantId = stringField(raw, "grantId");
  const agentId = stringField(raw, "agentId");
  const ide = stringField(raw, "ide");
  const tool = stringField(raw, "tool");
  const alias = stringField(raw, "alias");
  const requestedScope = stringField(raw, "requestedScope");
  const allowedScope = stringField(raw, "allowedScope");
  const reason = stringField(raw, "reason");
  const marshalExplanation = stringField(raw, "marshalExplanation");
  const createdAtMs = numberField(raw, "createdAtMs");
  const expiresAtMs = numberField(raw, "expiresAtMs");
  const riskRaw = raw["risk"];
  const risk: Risk | null =
    typeof riskRaw === "string" && (RISKS as readonly string[]).includes(riskRaw)
      ? (riskRaw as Risk)
      : null;
  if (
    grantId === null ||
    agentId === null ||
    ide === null ||
    tool === null ||
    alias === null ||
    requestedScope === null ||
    allowedScope === null ||
    reason === null ||
    marshalExplanation === null ||
    createdAtMs === null ||
    expiresAtMs === null ||
    risk === null
  ) {
    return null;
  }
  const base: PendingApproval = {
    grantId,
    agentId,
    ide,
    tool,
    alias,
    requestedScope,
    allowedScope,
    reason,
    risk,
    marshalExplanation,
    createdAtMs,
    expiresAtMs,
  };
  const modelId = raw["modelId"];
  return typeof modelId === "string" && modelId.length > 0 ? { ...base, modelId } : base;
}

export function projectPendingResponse(raw: unknown): PendingApproval[] {
  if (!isRecord(raw)) {
    return [];
  }
  const approvals = raw["approvals"];
  if (!Array.isArray(approvals)) {
    return [];
  }
  const projected: PendingApproval[] = [];
  for (const item of approvals as unknown[]) {
    const approval = projectApproval(item);
    if (approval !== null) {
      projected.push(approval);
    }
  }
  return projected;
}

const AUDIT_STAGES: readonly AuditStage[] = [
  "requested",
  "marshal",
  "policy",
  "approved",
  "denied",
  "executed",
  "expired",
  "revoked",
];

export function projectAuditEvent(raw: unknown): AuditEventLike | null {
  if (!isRecord(raw) || findSecretLikeKeys(raw).length > 0) {
    return null;
  }
  const ts = stringField(raw, "ts");
  const agentId = stringField(raw, "agentId");
  const alias = stringField(raw, "alias");
  const scope = raw["scope"];
  const detail = stringField(raw, "detail");
  const stageRaw = raw["stage"];
  const stage: AuditStage | null =
    typeof stageRaw === "string" && (AUDIT_STAGES as readonly string[]).includes(stageRaw)
      ? (stageRaw as AuditStage)
      : null;
  if (ts === null || agentId === null || alias === null || typeof scope !== "string" || detail === null || stage === null) {
    return null;
  }
  const base: AuditEventLike = { ts, agentId, alias, scope, stage, detail };
  const modelId = raw["modelId"];
  return typeof modelId === "string" && modelId.length > 0 ? { ...base, modelId } : base;
}

export function projectAuditResponse(raw: unknown): AuditEventLike[] {
  if (!isRecord(raw)) {
    return [];
  }
  const events = raw["events"];
  if (!Array.isArray(events)) {
    return [];
  }
  const projected: AuditEventLike[] = [];
  for (const item of events as unknown[]) {
    const event = projectAuditEvent(item);
    if (event !== null) {
      projected.push(event);
    }
  }
  return projected;
}

function projectStandingApproval(raw: unknown): StandingApproval | null {
  if (!isRecord(raw) || findSecretLikeKeys(raw).length > 0) {
    return null;
  }
  const agentId = stringField(raw, "agentId");
  const alias = stringField(raw, "alias");
  const scope = stringField(raw, "scope");
  if (agentId === null || alias === null || scope === null) {
    return null;
  }
  return { agentId, alias, scope };
}

export function projectPoliciesResponse(raw: unknown): PoliciesData {
  const empty: PoliciesData = { ceilings: {}, standingApprovals: [] };
  if (!isRecord(raw) || findSecretLikeKeys(raw).length > 0) {
    return empty;
  }
  const ceilingsRaw = raw["ceilings"];
  if (!isRecord(ceilingsRaw)) {
    return empty;
  }
  const ceilings: Record<string, string> = {};
  for (const [alias, ceiling] of Object.entries(ceilingsRaw)) {
    if (alias.length > 0 && typeof ceiling === "string" && ceiling.length > 0) {
      ceilings[alias] = ceiling;
    }
  }
  const standingRaw = raw["standingApprovals"];
  if (!Array.isArray(standingRaw)) {
    return empty;
  }
  const standingApprovals: StandingApproval[] = [];
  for (const item of standingRaw as unknown[]) {
    const projected = projectStandingApproval(item);
    if (projected !== null) {
      standingApprovals.push(projected);
    }
  }
  return { ceilings, standingApprovals };
}

export function projectAliasesResponse(raw: unknown): string[] {
  if (!isRecord(raw)) {
    return [];
  }
  const aliases = raw["aliases"];
  if (!Array.isArray(aliases)) {
    return [];
  }
  return (aliases as unknown[]).filter((a): a is string => typeof a === "string");
}

// ---------------------------------------------------------------------------
// View derivations (pure; the DOM layer only renders these).
// ---------------------------------------------------------------------------

export function sortApprovals(approvals: readonly PendingApproval[]): PendingApproval[] {
  return [...approvals].sort((a, b) => a.expiresAtMs - b.expiresAtMs);
}

export interface VaultCard {
  readonly alias: string;
  readonly scopes: readonly string[];
  readonly lastUsedTs: string | null;
}

export function deriveVaultCards(
  aliases: readonly string[],
  events: readonly AuditEventLike[],
): VaultCard[] {
  return aliases.map((alias) => {
    const mine = events.filter((e) => e.alias === alias);
    const scopes = [...new Set(mine.map((e) => e.scope).filter((s) => s.length > 0))].sort();
    let lastUsedTs: string | null = null;
    for (const event of mine) {
      if (lastUsedTs === null || event.ts > lastUsedTs) {
        lastUsedTs = event.ts;
      }
    }
    return { alias, scopes, lastUsedTs };
  });
}

export interface PolicyRow {
  readonly agentId: string;
  readonly scopes: readonly string[];
  readonly requestCount: number;
  readonly lastSeenTs: string | null;
}

export function derivePolicies(events: readonly AuditEventLike[]): PolicyRow[] {
  const byAgent = new Map<string, { scopes: Set<string>; requestCount: number; lastSeenTs: string | null }>();
  for (const event of events) {
    const entry = byAgent.get(event.agentId) ?? { scopes: new Set<string>(), requestCount: 0, lastSeenTs: null };
    if (event.scope.length > 0) {
      entry.scopes.add(event.scope);
    }
    if (event.stage === "requested") {
      entry.requestCount += 1;
    }
    if (entry.lastSeenTs === null || event.ts > entry.lastSeenTs) {
      entry.lastSeenTs = event.ts;
    }
    byAgent.set(event.agentId, entry);
  }
  return [...byAgent.entries()]
    .map(([agentId, entry]) => ({
      agentId,
      scopes: [...entry.scopes].sort(),
      requestCount: entry.requestCount,
      lastSeenTs: entry.lastSeenTs,
    }))
    .sort((a, b) => a.agentId.localeCompare(b.agentId));
}

export interface CeilingEntry {
  readonly alias: string;
  readonly ceiling: string;
}

export interface EnrichedPolicyRow extends PolicyRow {
  readonly ceilings: readonly CeilingEntry[];
  readonly standingApprovals: readonly StandingApproval[];
}

// Policies view rows built from real daemon policy state: observed scopes,
// request counts, and last-seen still come from audit, but ceilings are the
// enforced caps from GET /policies (never inferred from observed scopes)
// and standing approvals are the approvals currently in force.
export function buildPolicyRows(
  events: readonly AuditEventLike[],
  policies: PoliciesData,
): EnrichedPolicyRow[] {
  const observed = derivePolicies(events);
  const byAgent = new Map<string, EnrichedPolicyRow>();
  const aliasesByAgent = new Map<string, Set<string>>();
  for (const event of events) {
    const set = aliasesByAgent.get(event.agentId) ?? new Set<string>();
    if (event.alias.length > 0) {
      set.add(event.alias);
    }
    aliasesByAgent.set(event.agentId, set);
  }
  for (const approval of policies.standingApprovals) {
    const set = aliasesByAgent.get(approval.agentId) ?? new Set<string>();
    set.add(approval.alias);
    aliasesByAgent.set(approval.agentId, set);
  }
  const agentIds = new Set<string>([
    ...observed.map((row) => row.agentId),
    ...policies.standingApprovals.map((approval) => approval.agentId),
  ]);
  for (const agentId of [...agentIds].sort((a, b) => a.localeCompare(b))) {
    const base = observed.find((row) => row.agentId === agentId);
    const aliases = [...(aliasesByAgent.get(agentId) ?? new Set<string>())].sort();
    const ceilings: CeilingEntry[] = [];
    for (const alias of aliases) {
      const ceiling = policies.ceilings[alias];
      if (ceiling !== undefined) {
        ceilings.push({ alias, ceiling });
      }
    }
    byAgent.set(agentId, {
      agentId,
      scopes: base?.scopes ?? [],
      requestCount: base?.requestCount ?? 0,
      lastSeenTs: base?.lastSeenTs ?? null,
      ceilings,
      standingApprovals: policies.standingApprovals.filter((a) => a.agentId === agentId),
    });
  }
  return [...byAgent.values()];
}

const STAGE_LABELS: Record<AuditStage, string> = {
  requested: "Requested",
  marshal: "Marshal",
  policy: "Policy",
  approved: "Approved",
  denied: "Denied",
  executed: "Executed",
  expired: "Expired",
  revoked: "Revoked",
};

export function stageLabel(stage: AuditStage): string {
  return STAGE_LABELS[stage];
}

export interface AuditRow extends AuditEventLike {
  readonly stageLabel: string;
  readonly chain: string;
}

export function buildAuditRows(events: readonly AuditEventLike[]): AuditRow[] {
  return [...events].reverse().map((event) => {
    const label = STAGE_LABELS[event.stage];
    return { ...event, stageLabel: label, chain: `${event.agentId} → ${event.scope} → ${label}` };
  });
}
