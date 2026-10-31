import type { CapabilityRequest, MarshalDecision } from "./types.js";

export interface PolicyConfig {
  ceilings: Record<string, string>;
  standingApprovals: { agentId: string; alias: string; scope: string }[];
  rateLimitPerHour: number;
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
