import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../src/policy.js";

const cfg = { ceilings: { stripe: "charges.read" }, standingApprovals: [], rateLimitPerHour: 20 };
const req = { agentId: "cursor", ide: "Cursor", tool: "http", alias: "stripe", requestedScope: "charges.read", reason: "list" };

describe("evaluatePolicy", () => {
  it("clamps a marshal recommendation above the ceiling", () => {
    const d = { risk: "low" as const, recommendedScope: "charges.write", requireApproval: false, explanation: "x" };
    expect(evaluatePolicy(req, d, cfg, 0).allowedScope).toBe("charges.read");
  });
  it("works with no marshal: sensitive read still needs approval", () => {
    expect(evaluatePolicy(req, null, cfg, 0).requireApproval).toBe(true);
  });
  it("denies unknown aliases", () => {
    expect(evaluatePolicy({ ...req, alias: "nope" }, null, cfg, 0).allowedScope).toBeNull();
  });
  it("standing approval never covers writes", () => {
    const c2 = { ...cfg, ceilings: { stripe: "charges.write" }, standingApprovals: [{ agentId: "cursor", alias: "stripe", scope: "charges.write" }] };
    const d = { risk: "low" as const, recommendedScope: "charges.write", requireApproval: false, explanation: "x" };
    expect(evaluatePolicy({ ...req, requestedScope: "charges.write" }, d, c2, 0).requireApproval).toBe(true);
  });
  it("denies at the rate limit with reason rate-limit", () => {
    const result = evaluatePolicy(req, null, cfg, cfg.rateLimitPerHour);
    expect(result.allowedScope).toBeNull();
    expect(result.reason).toBe("rate-limit");
  });
  it("allows a low-risk read within the ceiling without approval when the marshal says so", () => {
    const d = { risk: "low" as const, recommendedScope: "charges.read", requireApproval: false, explanation: "x" };
    const result = evaluatePolicy(req, d, cfg, 0);
    expect(result.allowedScope).toBe("charges.read");
    expect(result.requireApproval).toBe(false);
  });
  it("standing approval covers a low-risk read even when the marshal asks for approval", () => {
    const c2 = { ...cfg, standingApprovals: [{ agentId: "cursor", alias: "stripe", scope: "charges.read" }] };
    const d = { risk: "low" as const, recommendedScope: "charges.read", requireApproval: true, explanation: "x" };
    expect(evaluatePolicy(req, d, c2, 0).requireApproval).toBe(false);
  });
  it("standing approval does not apply when risk is not low", () => {
    const c2 = { ...cfg, standingApprovals: [{ agentId: "cursor", alias: "stripe", scope: "charges.read" }] };
    const d = { risk: "medium" as const, recommendedScope: "charges.read", requireApproval: false, explanation: "x" };
    expect(evaluatePolicy(req, d, c2, 0).requireApproval).toBe(true);
  });
  it("denies a requested write above a read ceiling when there is no marshal", () => {
    const result = evaluatePolicy({ ...req, requestedScope: "charges.write" }, null, cfg, 0);
    expect(result.allowedScope).toBeNull();
    expect(result.requireApproval).toBe(false);
    expect(result.reason).toBe("scope-above-ceiling");
  });
  it("denies a requested write under a read ceiling even with a low-risk marshal decision", () => {
    const d = { risk: "low" as const, recommendedScope: "charges.write", requireApproval: false, explanation: "x" };
    const result = evaluatePolicy({ ...req, requestedScope: "charges.write" }, d, cfg, 0);
    expect(result.allowedScope).toBeNull();
    expect(result.requireApproval).toBe(false);
    expect(result.reason).toBe("scope-above-ceiling");
  });
  it("denies a requested write under a read ceiling even with a standing approval present", () => {
    const c2 = { ...cfg, standingApprovals: [{ agentId: "cursor", alias: "stripe", scope: "charges.read" }] };
    const d = { risk: "low" as const, recommendedScope: "charges.write", requireApproval: false, explanation: "x" };
    const result = evaluatePolicy({ ...req, requestedScope: "charges.write" }, d, c2, 0);
    expect(result.allowedScope).toBeNull();
    expect(result.requireApproval).toBe(false);
    expect(result.reason).toBe("scope-above-ceiling");
  });
  it("denies a cross-resource requested scope instead of remapping to the ceiling", () => {
    const d = { risk: "low" as const, recommendedScope: "payments.read", requireApproval: false, explanation: "x" };
    const result = evaluatePolicy({ ...req, requestedScope: "payments.read" }, d, cfg, 0);
    expect(result.allowedScope).toBeNull();
    expect(result.requireApproval).toBe(false);
    expect(result.reason).toBe("scope-above-ceiling");
  });
  it("narrows a marshal-recommended cross-resource scope back to the requested scope", () => {
    const d = { risk: "low" as const, recommendedScope: "payments.read", requireApproval: false, explanation: "x" };
    const result = evaluatePolicy(req, d, cfg, 0);
    expect(result.allowedScope).toBe("charges.read");
  });
  it("never lets a write be auto-approved by a low-risk marshal decision", () => {
    const c2 = { ...cfg, ceilings: { stripe: "charges.write" } };
    const d = { risk: "low" as const, recommendedScope: "charges.write", requireApproval: false, explanation: "x" };
    expect(evaluatePolicy({ ...req, requestedScope: "charges.write" }, d, c2, 0).requireApproval).toBe(true);
  });
});
