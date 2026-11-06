import type { CapabilityRequest, MarshalDecision } from "./types.js";
import { summarizeHttpRequestPayload } from "./payload.js";

export interface PolicyConfig {
  ceilings: Record<string, string>;
  standingApprovals: { agentId: string; alias: string; scope: string; verifiedOnly?: boolean }[];
  rateLimitPerHour: number;
  // Aliases whose use moves money (payment cards). Every request on one is
  // a high-risk financial write: it always needs a human, standing
  // approvals never apply, and no marshal verdict can auto-approve it.
  financialAliases?: readonly string[];
  // Remote-origin requests never reuse standing approvals: a remote grant
  // is a fresh human decision on the vault machine every time.
  disableStandingApprovals?: boolean;
  // Device write ceiling (DD4): when false, remote write scopes are denied
  // outright at the policy floor, below the alias ceiling.
  deviceAllowWrite?: boolean;
}

export interface AgentVelocityConfig {
  readonly maxRequestsPerMinute: number;
  readonly consecutiveFailureThreshold: number;
  readonly circuitBreakerDurationMs: number;
}

export const DEFAULT_VELOCITY_CONFIG: AgentVelocityConfig = {
  maxRequestsPerMinute: 15,
  consecutiveFailureThreshold: 3,
  circuitBreakerDurationMs: 60_000,
};

// Enrolled agents present a token. They get a wider burst budget so parallel
// tool calls are not stalled, and a slightly higher failure threshold.
// Unverified callers stay on DEFAULT_VELOCITY_CONFIG.
export const VERIFIED_VELOCITY_CONFIG: AgentVelocityConfig = {
  maxRequestsPerMinute: 60,
  consecutiveFailureThreshold: 5,
  circuitBreakerDurationMs: 60_000,
};

export function velocityConfigForAgent(verified: boolean | undefined): AgentVelocityConfig {
  return verified === true ? VERIFIED_VELOCITY_CONFIG : DEFAULT_VELOCITY_CONFIG;
}

export interface AgentVelocityTracker {
  readonly windowStartMs: number;
  readonly requestsInWindow: number;
  readonly consecutiveFailures: number;
  readonly circuitBrokenUntilMs: number;
}

export function isAgentRateLimited(
  tracker: AgentVelocityTracker | undefined,
  config: AgentVelocityConfig = DEFAULT_VELOCITY_CONFIG,
  nowMs: number = Date.now(),
): { limited: boolean; reason?: "rate-limit-velocity" | "circuit-breaker-tripped" } {
  if (tracker === undefined) {
    return { limited: false };
  }
  // Check active circuit breaker
  if (tracker.circuitBrokenUntilMs > nowMs) {
    return { limited: true, reason: "circuit-breaker-tripped" };
  }

  // Check rolling minute window
  const windowElapsed = nowMs - tracker.windowStartMs;
  if (windowElapsed < 60_000) {
    if (tracker.requestsInWindow >= config.maxRequestsPerMinute) {
      return { limited: true, reason: "rate-limit-velocity" };
    }
  }

  return { limited: false };
}

export interface RecordAgentRequestOptions {
  // Discovery misses such as unknown-alias are not authentication failures.
  // Leave this false to keep the request in the rate window without moving
  // the circuit breaker.
  readonly countFailure?: boolean;
}

export function recordAgentRequest(
  tracker: AgentVelocityTracker | undefined,
  nowMs: number,
  success: boolean,
  config: AgentVelocityConfig = DEFAULT_VELOCITY_CONFIG,
  options?: RecordAgentRequestOptions,
): AgentVelocityTracker {
  const current = tracker ?? {
    windowStartMs: nowMs,
    requestsInWindow: 0,
    consecutiveFailures: 0,
    circuitBrokenUntilMs: 0,
  };

  const windowElapsed = nowMs - current.windowStartMs;
  const newWindow = windowElapsed >= 60_000;
  const requestsInWindow = newWindow ? 1 : current.requestsInWindow + 1;
  const windowStartMs = newWindow ? nowMs : current.windowStartMs;

  const countFailure = options?.countFailure !== false;
  const consecutiveFailures = success
    ? 0
    : countFailure
      ? current.consecutiveFailures + 1
      : current.consecutiveFailures;
  let circuitBrokenUntilMs = current.circuitBrokenUntilMs;

  if (consecutiveFailures >= config.consecutiveFailureThreshold) {
    circuitBrokenUntilMs = Math.max(circuitBrokenUntilMs, nowMs + config.circuitBreakerDurationMs);
  }

  return {
    windowStartMs,
    requestsInWindow,
    consecutiveFailures,
    circuitBrokenUntilMs,
  };
}

export interface PolicyResult {
  allowedScope: string | null;
  requireApproval: boolean;
  reason: string;
}

const GRAPHQL_MUTATION = /\bmutation\b/i;

// Read is an explicit suffix. A wildcard, an unknown verb, or an empty
// scope is a write so a new connector scope cannot skip approval.
export function isExplicitReadScope(scope: string): boolean {
  if (scope.includes("*")) return false;
  return scope === "read" || scope.endsWith(".read") || scope.endsWith(":read");
}

export function isWriteScope(scope: string): boolean {
  return !isExplicitReadScope(scope);
}

export function sessionLeaseAllowed(input: {
  readonly scope: string;
  readonly risk: "low" | "medium" | "high" | undefined;
  readonly payload: unknown;
  readonly verified: boolean;
}): boolean {
  if (!input.verified) return false;
  if (input.risk !== "low") return false;
  if (isWriteScope(input.scope)) return false;
  const summary = summarizeHttpRequestPayload(input.payload);
  if (summary !== null && summary.mutating) return false;
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(input.payload);
  } catch {
    return false;
  }
  if (typeof serialized === "string" && GRAPHQL_MUTATION.test(serialized)) return false;
  return true;
}

function resourcePrefix(scope: string): string {
  const index = Math.max(scope.lastIndexOf("."), scope.lastIndexOf(":"));
  return index > 0 ? scope.slice(0, index) : scope;
}

// A marshal verdict on a financial alias is escalated, never trusted
// downward: risk is forced to high and approval is always required.
export function escalateFinancialDecision(decision: MarshalDecision | null): MarshalDecision | null {
  if (decision === null) return null;
  return {
    ...decision,
    risk: "high",
    requireApproval: true,
    explanation: `Payment card: financial write, human approval required. Warden said: ${decision.explanation}`,
  };
}

export interface PolicyEvaluationOptions {
  // Risk from assessByRules when the warden did not return a decision
  // (provider "none", or the model call failed closed to null). Standing
  // approvals may use this. A non-null marshal decision is never replaced
  // by it.
  readonly deterministicRisk?: "low" | "medium" | "high";
}

export function evaluatePolicy(
  req: CapabilityRequest,
  decision: MarshalDecision | null,
  cfg: PolicyConfig,
  historyCount: number,
  options?: PolicyEvaluationOptions,
): PolicyResult {
  const ceiling = cfg.ceilings[req.alias];
  if (ceiling === undefined) {
    return { allowedScope: null, requireApproval: false, reason: "unknown-alias" };
  }
  if (historyCount >= cfg.rateLimitPerHour) {
    return { allowedScope: null, requireApproval: false, reason: "rate-limit" };
  }
  // A scope the AGENT itself requested above the ceiling is a denial, not
  // a downgrade: silently substituting the ceiling would execute an
  // operation (or resource) the agent never asked for. Marshal
  // recommendations above the ceiling still clamp below - only the
  // agent's own requested scope is judged here.
  if (isWriteScope(req.requestedScope) && !isWriteScope(ceiling)) {
    return { allowedScope: null, requireApproval: false, reason: "scope-above-ceiling" };
  }
  if (resourcePrefix(req.requestedScope) !== resourcePrefix(ceiling)) {
    return { allowedScope: null, requireApproval: false, reason: "scope-above-ceiling" };
  }

  const candidate = decision?.recommendedScope ?? req.requestedScope;
  let allowedScope = candidate;
  if (resourcePrefix(allowedScope) !== resourcePrefix(ceiling)) {
    allowedScope =
      resourcePrefix(req.requestedScope) === resourcePrefix(ceiling) ? req.requestedScope : ceiling;
  }
  let clamped = allowedScope !== candidate;
  if (isWriteScope(allowedScope) && !isWriteScope(ceiling)) {
    allowedScope = ceiling;
    clamped = true;
  }
  if (
    decision !== null &&
    isWriteScope(allowedScope) &&
    !isWriteScope(req.requestedScope) &&
    resourcePrefix(req.requestedScope) === resourcePrefix(allowedScope)
  ) {
    allowedScope = req.requestedScope;
    clamped = true;
  }


  if (cfg.deviceAllowWrite === false && isWriteScope(allowedScope)) {
    return { allowedScope: null, requireApproval: false, reason: "device-ceiling-readonly" };
  }

  // Deterministic intent/payload floor: a payload that declares a
  // state-changing HTTP method can never execute under a read-only scope,
  // whatever the agent's reason says and whatever any warden decided. The
  // connector re-checks its own allowlists at execution time; this is the
  // decision-time floor so the mismatch is denied, not silently moved to a
  // post-approval ConnectorFailed.
  const payload = summarizeHttpRequestPayload(req.payload);
  if (payload !== null && payload.mutating && !isWriteScope(allowedScope)) {
    return { allowedScope: null, requireApproval: true, reason: "payload-mutates-readonly-scope" };
  }

  const financial = cfg.financialAliases?.includes(req.alias) === true;
  if (financial) {
    return { allowedScope, requireApproval: true, reason: "financial-approval-required" };
  }

  // A missing warden verdict is low only when the deterministic rules say
  // so. That lets standing approvals survive provider "none" and an offline
  // model. It does not auto-approve anything that lacks a standing approval.
  const riskIsLow =
    decision !== null ? decision.risk === "low" : options?.deterministicRisk === "low";
  const hasStandingApproval =
    cfg.disableStandingApprovals !== true &&
    req.verified === true &&
    riskIsLow &&
    !isWriteScope(allowedScope) &&
    cfg.standingApprovals.some(
      (approval) =>
        approval.agentId === req.agentId &&
        approval.alias === req.alias &&
        approval.scope === allowedScope,
    );

  let requireApproval: boolean;
  if (isWriteScope(allowedScope)) {
    requireApproval = true;
  } else if (hasStandingApproval) {
    requireApproval = false;
  } else if (decision === null) {
    requireApproval = true;
  } else if (decision.risk !== "low") {
    requireApproval = true;
  } else if (req.verified === false) {
    // Defense-in-depth: Unverified callers (no valid agent token) must never auto-execute.
    requireApproval = true;
  } else {
    requireApproval = decision.requireApproval;
  }

  const reason = hasStandingApproval
    ? "standing-approval"
    : requireApproval
      ? "approval-required"
      : clamped
        ? "clamped-to-ceiling"
        : "allowed";

  return { allowedScope, requireApproval, reason };
}
