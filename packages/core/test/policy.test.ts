import { describe, expect, it } from "vitest";
import { escalateFinancialDecision, evaluatePolicy } from "../src/policy.js";

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
  it("standing approval covers a null decision when deterministic risk is low", () => {
    const c2 = { ...cfg, standingApprovals: [{ agentId: "cursor", alias: "stripe", scope: "charges.read" }] };
    const honored = evaluatePolicy(req, null, c2, 0, { deterministicRisk: "low" });
    expect(honored.requireApproval).toBe(false);
    expect(honored.reason).toBe("standing-approval");
    expect(evaluatePolicy(req, null, c2, 0).requireApproval).toBe(true);
    expect(evaluatePolicy(req, null, c2, 0, { deterministicRisk: "medium" }).requireApproval).toBe(true);
    expect(evaluatePolicy(req, null, cfg, 0, { deterministicRisk: "low" }).requireApproval).toBe(true);
  });
  it("standing approval covers a low-risk read even when the marshal asks for approval", () => {
    const c2 = { ...cfg, standingApprovals: [{ agentId: "cursor", alias: "stripe", scope: "charges.read" }] };
    const d = { risk: "low" as const, recommendedScope: "charges.read", requireApproval: true, explanation: "x" };
    expect(evaluatePolicy(req, d, c2, 0).requireApproval).toBe(false);
  });
  it("standing approval with verifiedOnly never applies to unverified or spoofed requests", () => {
    const c2 = { ...cfg, standingApprovals: [{ agentId: "cursor", alias: "stripe", scope: "charges.read", verifiedOnly: true }] };
    const d = { risk: "low" as const, recommendedScope: "charges.read", requireApproval: true, explanation: "x" };
    const spoofedReq = { ...req, verified: false };
    expect(evaluatePolicy(spoofedReq, d, c2, 0).requireApproval).toBe(true);
    const verifiedReq = { ...req, verified: true };
    expect(evaluatePolicy(verifiedReq, d, c2, 0).requireApproval).toBe(false);
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

  it("demotes a marshal-recommended write to the requested read on the same resource", () => {
    const c2 = { ...cfg, ceilings: { stripe: "charges.write" } };
    const d = { risk: "low" as const, recommendedScope: "charges.write", requireApproval: false, explanation: "x" };
    const result = evaluatePolicy(req, d, c2, 0);
    expect(result.allowedScope).toBe("charges.read");
  });
});

describe("payload floor: declared mutating methods on read-only scopes", () => {
  const d = { risk: "low" as const, recommendedScope: "charges.read", requireApproval: false, explanation: "x" };

  it("denies a payload DELETE under a read-only ceiling even with a low-risk marshal and a standing approval", () => {
    const c2 = { ...cfg, standingApprovals: [{ agentId: "cursor", alias: "stripe", scope: "charges.read" }] };
    const result = evaluatePolicy(
      { ...req, payload: { method: "DELETE", path: "/v1/charges/ch_1" } },
      d,
      c2,
      0,
    );
    expect(result.allowedScope).toBeNull();
    expect(result.reason).toBe("payload-mutates-readonly-scope");
  });

  it("keeps working identically when no method is declared (body-payload routes)", () => {
    const result = evaluatePolicy(
      { ...req, payload: { query: "aggregate { totals }" } },
      d,
      cfg,
      0,
    );
    expect(result.allowedScope).toBe("charges.read");
    expect(result.reason).toBe("allowed");
  });

  it("allows a declared GET under a read-only ceiling", () => {
    const result = evaluatePolicy(
      { ...req, payload: { method: "GET", path: "/v1/charges" } },
      d,
      cfg,
      0,
    );
    expect(result.allowedScope).toBe("charges.read");
  });

  it("catches the mismatch before the marshal at the pre-check too", () => {
    const result = evaluatePolicy(
      { ...req, payload: { method: "POST", path: "/v1/charges" } },
      null,
      cfg,
      0,
    );
    expect(result.allowedScope).toBeNull();
    expect(result.reason).toBe("payload-mutates-readonly-scope");
  });

  it("a mutating payload under a write ceiling is unaffected", () => {
    const dw = { risk: "low" as const, recommendedScope: "charges.write", requireApproval: false, explanation: "x" };
    const c2 = { ...cfg, ceilings: { stripe: "charges.write" } };
    const result = evaluatePolicy(
      { ...req, requestedScope: "charges.write", payload: { method: "DELETE", path: "/v1/charges/ch_1" } },
      dw,
      c2,
      0,
    );
    expect(result.allowedScope).toBe("charges.write");
  });
});

describe("financial (payment card) aliases", () => {
  const card = { ceilings: { visa: "card.payment:write" }, standingApprovals: [{ agentId: "cursor", alias: "visa", scope: "card.payment:write" }], rateLimitPerHour: 20, financialAliases: ["visa"] };
  const cardReq = { ...req, alias: "visa", requestedScope: "card.payment:write" };
  it("always requires approval even with a low-risk marshal verdict and a standing approval", () => {
    const d = { risk: "low" as const, recommendedScope: "card.payment:write", requireApproval: false, explanation: "x" };
    const r = evaluatePolicy(cardReq, d, card, 0);
    expect(r.requireApproval).toBe(true);
    expect(r.reason).toBe("financial-approval-required");
  });
  it("escalates the marshal decision to high risk", () => {
    const d = { risk: "low" as const, recommendedScope: "card.payment:write", requireApproval: false, explanation: "fine" };
    const e = escalateFinancialDecision(d);
    expect(e?.risk).toBe("high");
    expect(e?.requireApproval).toBe(true);
    expect(escalateFinancialDecision(null)).toBeNull();
  });
});
