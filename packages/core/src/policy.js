const WRITE_MARKERS = [".write", ".create", ".update", ".delete"];
export function isWriteScope(scope) {
    return WRITE_MARKERS.some((marker) => scope.includes(marker)) || scope.endsWith(":write");
}
function resourcePrefix(scope) {
    const index = Math.max(scope.lastIndexOf("."), scope.lastIndexOf(":"));
    return index > 0 ? scope.slice(0, index) : scope;
}
export function evaluatePolicy(req, decision, cfg, historyCount) {
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
    if (decision !== null &&
        isWriteScope(allowedScope) &&
        !isWriteScope(req.requestedScope) &&
        resourcePrefix(req.requestedScope) === resourcePrefix(allowedScope)) {
        allowedScope = req.requestedScope;
        clamped = true;
    }
    const hasStandingApproval = decision !== null &&
        decision.risk === "low" &&
        !isWriteScope(allowedScope) &&
        cfg.standingApprovals.some((approval) => approval.agentId === req.agentId &&
            approval.alias === req.alias &&
            approval.scope === allowedScope);
    let requireApproval;
    if (isWriteScope(allowedScope)) {
        requireApproval = true;
    }
    else if (decision === null) {
        requireApproval = true;
    }
    else if (hasStandingApproval) {
        requireApproval = false;
    }
    else if (decision.risk !== "low") {
        requireApproval = true;
    }
    else {
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
