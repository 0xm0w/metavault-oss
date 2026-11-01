import type { CapabilityRequest, MarshalDecision } from "./types.js";

export interface PolicyConfig {
  ceilings: Record<string, string>;
  standingApprovals: { agentId: string; alias: string; scope: string }[];
  rateLimitPerHour: number;
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

export function recordAgentRequest(
  tracker: AgentVelocityTracker | undefined,
  nowMs: number,
  success: boolean,
  config: AgentVelocityConfig = DEFAULT_VELOCITY_CONFIG,
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

  const consecutiveFailures = success ? 0 : current.consecutiveFailures + 1;
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

const WRITE_MARKERS = [".write", ".create", ".update", ".delete"] as const;

export function isWriteScope(scope: string): boolean {
  return WRITE_MARKERS.some((marker) => scope.includes(marker)) || scope.endsWith(":write");
}

function resourcePrefix(scope: string): string {
  const index = Math.max(scope.lastIndexOf("."), scope.lastIndexOf(":"));
  return index > 0 ? scope.slice(0, index) : scope;
}

export function evaluatePolicy(
  req: CapabilityRequest,
  decision: MarshalDecision | null,
  cfg: PolicyConfig,
  historyCount: number,
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

  const hasStandingApproval =
    decision !== null &&
    decision.risk === "low" &&
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
  } else if (decision === null) {
    requireApproval = true;
  } else if (hasStandingApproval) {
    requireApproval = false;
  } else if (decision.risk !== "low") {
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
