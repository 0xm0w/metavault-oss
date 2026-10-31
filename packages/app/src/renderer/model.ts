import type {
  AuditEventLike,
  AuditStage,
  CredentialMeta,
  CredentialPatch,
  DeeplinkAddParams,
  PendingApproval,
  PoliciesData,
  Risk,
  StandingApproval,
} from "./types.js";

// Unified warm theme (promoted from the Vault page). These exact hex
// values are the theme contract; styles.css mirrors them as CSS variables.
export const TOKENS = {
  surface: "#FFFFFF",
  background: "#FAF9F6",
  ink: "#201A17",
  muted: "#8A8174",
  border: "#E6DDD0",
  field: "#F5F1EC",
  primary: "#201A17",
  danger: "#DC2626",
  teal: "#0F766E",
  warn: "#D97706",
} as const;

export const DISPLAY_FONT = "Georgia, 'Times New Roman', serif";
export const BODY_FONT = "'Segoe UI', -apple-system, 'San Francisco', system-ui, sans-serif";

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

export function credentialInitial(alias: string): string {
  const trimmed = alias.trim();
  return trimmed === "" ? "?" : trimmed.charAt(0).toUpperCase();
}

export function isCredentialFormComplete(alias: string, scope: string, secret: string): boolean {
  return alias.trim() !== "" && scope.trim() !== "" && secret.trim() !== "";
}

export function shouldShowAgentComputerWarning(website: string): boolean {
  return normalizeWebsite(website) !== "";
}

export function normalizeWebsite(website: string): string {
  let value = website.trim().toLowerCase();
  value = value.replace(/^https?:\/\//, "");
  value = value.split("/")[0] ?? "";
  value = value.split("?")[0] ?? "";
  value = value.split("#")[0] ?? "";
  return value.trim();
}

export function faviconUrl(website: string): string | null {
  const domain = normalizeWebsite(website);
  if (domain === "" || !domain.includes(".")) {
    return null;
  }
  return `https://${domain}/favicon.ico`;
}

export function buildEditPayload(input: {
  readonly scope: string;
  readonly website: string;
  readonly secret: string;
}): CredentialPatch {
  const payload: { scope?: string; website?: string; secret?: string } = {
    scope: input.scope.trim(),
    website: normalizeWebsite(input.website),
  };
  if (input.secret !== "") {
    payload.secret = input.secret;
  }
  return payload;
}

export function buildAddPayload(input: {
  readonly alias: string;
  readonly scope: string;
  readonly secret: string;
  readonly website: string;
}): { alias: string; scope: string; secret: string; website: string } {
  return {
    alias: input.alias.trim(),
    scope: input.scope.trim(),
    secret: input.secret,
    website: normalizeWebsite(input.website),
  };
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
  "credential-added",
  "credential-deleted",
  "enrollment-created",
  "enrollment-completed",
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

export function projectCredentialsResponse(raw: unknown): CredentialMeta[] {
  if (!isRecord(raw)) {
    return [];
  }
  const credentials = raw["credentials"];
  if (Array.isArray(credentials)) {
    const out: CredentialMeta[] = [];
    for (const item of credentials as unknown[]) {
      if (!isRecord(item) || findSecretLikeKeys(item).length > 0) {
        continue;
      }
      const alias = item["alias"];
      const website = item["website"];
      if (typeof alias === "string" && alias.length > 0) {
        out.push({ alias, website: typeof website === "string" ? website : "" });
      }
    }
    return out;
  }
  return projectAliasesResponse(raw).map((alias) => ({ alias, website: "" }));
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
  readonly website: string;
}

export function deriveVaultCards(
  aliases: readonly string[],
  events: readonly AuditEventLike[],
  meta: readonly CredentialMeta[] = [],
): VaultCard[] {
  const websiteByAlias = new Map(meta.map((entry) => [entry.alias, entry.website]));
  return aliases.map((alias) => {
    const mine = events.filter((e) => e.alias === alias);
    const scopes = [...new Set(mine.map((e) => e.scope).filter((s) => s.length > 0))].sort();
    let lastUsedTs: string | null = null;
    for (const event of mine) {
      // Adding a credential is not using it: a just-added credential
      // has never been used.
      if (event.stage === "credential-added" || event.stage === "credential-deleted") {
        continue;
      }
      if (lastUsedTs === null || event.ts > lastUsedTs) {
        lastUsedTs = event.ts;
      }
    }
    return { alias, scopes, lastUsedTs, website: websiteByAlias.get(alias) ?? "" };
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
    // Adding a credential is not agent activity: it must not create a
    // phantom "human" agent row.
    if (event.stage === "credential-added" || event.stage === "credential-deleted") {
      continue;
    }
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
  "credential-added": "Credential added",
  "credential-deleted": "Credential deleted",
  "enrollment-created": "Enrollment created",
  "enrollment-completed": "Enrollment completed",
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

// ---------------------------------------------------------------------------
// Deeplink add flow. The DOM layer supplies the effects; this helper owns
// the ordering, which is the whole contract: switch to Vault, let any
// in-flight render/refresh fully complete, close whatever modal is open,
// and only then open the prefilled Add modal. Opening the modal before the
// render settles is the race that left deeplinks with no modal on screen:
// the completing render rebuilt the view around (or the still-open modal
// short-circuited) the open. The modal open is therefore always the last
// step, and the params reach it untouched (secret is never a deeplink
// field; the human types it into the focused Secret input).
// ---------------------------------------------------------------------------

export interface DeeplinkAddFlowDeps {
  readonly switchToVault: () => void;
  readonly renderVault: () => void | Promise<void>;
  readonly closeModalIfOpen: () => void;
  readonly openAddModal: (params: DeeplinkAddParams) => void;
}

export async function runDeeplinkAddFlow(
  params: DeeplinkAddParams,
  deps: DeeplinkAddFlowDeps,
): Promise<void> {
  deps.switchToVault();
  await deps.renderVault();
  deps.closeModalIfOpen();
  deps.openAddModal(params);
}
