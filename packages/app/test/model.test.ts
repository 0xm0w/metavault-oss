import { describe, expect, it } from "vitest";
import {
  TOKENS,
  buildAuditRows,
  buildPolicyRows,
  canAlwaysAllow,
  derivePolicies,
  deriveVaultCards,
  findSecretLikeKeys,
  formatExpiry,
  formatLastUsed,
  isReadOnlyScope,
  marshalStatusLine,
  projectApproval,
  projectAuditEvent,
  projectPendingResponse,
  projectPoliciesResponse,
  sortApprovals,
} from "../src/renderer/model.js";
import type { AuditEventLike, PendingApproval } from "../src/renderer/types.js";

const approval = (over: Partial<PendingApproval> = {}): PendingApproval => ({
  grantId: "g1",
  agentId: "cursor",
  ide: "Cursor",
  tool: "http",
  alias: "stripe",
  requestedScope: "charges.read",
  allowedScope: "charges.read",
  reason: "List last 5 failed charges",
  risk: "low",
  marshalExplanation: "Read-only Stripe scope from a known agent.",
  createdAtMs: 1_000,
  expiresAtMs: 61_000,
  ...over,
});

const auditEvent = (over: Partial<AuditEventLike> = {}): AuditEventLike => ({
  ts: "2026-10-31T10:00:00.000Z",
  agentId: "cursor",
  alias: "stripe",
  scope: "charges.read",
  stage: "requested",
  detail: "capability requested",
  ...over,
});

describe("Direction B tokens", () => {
  it("pins the Direction B palette exactly", () => {
    expect(TOKENS.surface).toBe("#FFFFFF");
    expect(TOKENS.surfaceAlt).toBe("#F8FAFC");
    expect(TOKENS.navy).toBe("#1E3A5F");
    expect(TOKENS.approve).toBe("#16A34A");
    expect(TOKENS.deny).toBe("#DC2626");
    expect(TOKENS.warn).toBe("#D97706");
  });
});

describe("scope risk helpers", () => {
  it("treats read scopes as read-only and write markers as writes", () => {
    expect(isReadOnlyScope("charges.read")).toBe(true);
    expect(isReadOnlyScope("stripe.charges.read")).toBe(true);
    expect(isReadOnlyScope("charges.write")).toBe(false);
    expect(isReadOnlyScope("users.create")).toBe(false);
    expect(isReadOnlyScope("users.update")).toBe(false);
    expect(isReadOnlyScope("users.delete")).toBe(false);
    expect(isReadOnlyScope("data:write")).toBe(false);
    expect(isReadOnlyScope("")).toBe(false);
  });

  it("allows Always allow only for read-only low-risk approvals", () => {
    expect(canAlwaysAllow(approval())).toBe(true);
    expect(canAlwaysAllow(approval({ allowedScope: "charges.write" }))).toBe(false);
    expect(canAlwaysAllow(approval({ risk: "medium" }))).toBe(false);
    expect(canAlwaysAllow(approval({ risk: "high" }))).toBe(false);
  });
});

describe("marshal status line", () => {
  it("renders the pinned on-device line by default", () => {
    expect(marshalStatusLine()).toBe("Marshal · Llama 3.2 3B · On-device");
    expect(marshalStatusLine(undefined)).toBe("Marshal · Llama 3.2 3B · On-device");
    expect(marshalStatusLine("llama3.2:3b")).toBe("Marshal · Llama 3.2 3B · On-device");
  });

  it("names other models without changing the shape", () => {
    expect(marshalStatusLine("custom-model:7b")).toBe("Marshal · custom-model:7b · On-device");
  });
});

describe("expiry and last-used formatting", () => {
  it("formats expiry countdowns deterministically", () => {
    expect(formatExpiry(61_000, 19_000)).toBe("Expires in 42s");
    expect(formatExpiry(190_000, 0)).toBe("Expires in 3m 10s");
    expect(formatExpiry(1_000, 1_000)).toBe("Expired");
    expect(formatExpiry(1_000, 2_000)).toBe("Expired");
  });

  it("formats last-used relative labels", () => {
    const now = Date.parse("2026-10-31T12:00:00.000Z");
    expect(formatLastUsed(null, now)).toBe("Never used");
    expect(formatLastUsed("not-a-date", now)).toBe("Never used");
    expect(formatLastUsed("2026-10-31T11:59:30.000Z", now)).toBe("Just now");
    expect(formatLastUsed("2026-10-31T11:55:00.000Z", now)).toBe("5m ago");
    expect(formatLastUsed("2026-10-31T10:00:00.000Z", now)).toBe("2h ago");
    expect(formatLastUsed("2026-10-28T12:00:00.000Z", now)).toBe("3d ago");
  });
});

describe("payload projection (renderer never receives secrets)", () => {
  it("projects only whitelisted approval fields", () => {
    const raw = { ...approval(), benignExtra: "drop me" };
    const projected = projectApproval(raw);
    expect(projected).toEqual(approval());
    expect(projected !== null && "benignExtra" in projected).toBe(false);
  });

  it("fails closed on secret-like keys, including unenumerated variants", () => {
    expect(findSecretLikeKeys({ apiKeyValue: "x" })).toEqual(["apiKeyValue"]);
    expect(findSecretLikeKeys({ credential_value: "x" })).toEqual(["credential_value"]);
    expect(findSecretLikeKeys({ nested: [{ rawSecret: "x" }] })).toEqual(["nested.0.rawSecret"]);
    expect(projectApproval({ ...approval(), secretValue: "sk-canary" })).toBeNull();
    expect(projectApproval({ ...approval(), "x-api-key": "sk-canary" })).toBeNull();
  });

  it("does not flag benign daemon keys", () => {
    expect(findSecretLikeKeys({ ...approval(), events: [auditEvent()] })).toEqual([]);
  });

  it("rejects malformed approvals", () => {
    expect(projectApproval(null)).toBeNull();
    expect(projectApproval({ ...approval(), grantId: 42 })).toBeNull();
    expect(projectApproval({ ...approval(), risk: "critical" })).toBeNull();
    const noScope: Record<string, unknown> = { ...approval() };
    delete noScope["allowedScope"];
    expect(projectApproval(noScope)).toBeNull();
  });

  it("projects pending responses and audit events, dropping bad rows", () => {
    expect(projectPendingResponse({ approvals: [{ ...approval() }, { bad: true }] })).toEqual([
      approval(),
    ]);
    expect(projectPendingResponse({ nope: [] })).toEqual([]);
    expect(projectAuditEvent(auditEvent())).toEqual(auditEvent());
    expect(projectAuditEvent({ ...auditEvent(), stage: "teleported" })).toBeNull();
    expect(projectAuditEvent({ ...auditEvent(), secret: "x" })).toBeNull();
  });
});

describe("view derivations", () => {
  it("sorts approvals by soonest expiry without mutating the input", () => {
    const late = approval({ grantId: "late", expiresAtMs: 90_000 });
    const soon = approval({ grantId: "soon", expiresAtMs: 30_000 });
    const input = [late, soon];
    expect(sortApprovals(input).map((a) => a.grantId)).toEqual(["soon", "late"]);
    expect(input.map((a) => a.grantId)).toEqual(["late", "soon"]);
  });

  it("derives vault cards with scope chips and last used per alias", () => {
    const events = [
      auditEvent({ ts: "2026-10-31T09:00:00.000Z", scope: "charges.read" }),
      auditEvent({ ts: "2026-10-31T11:00:00.000Z", scope: "charges.read", stage: "executed" }),
      auditEvent({ ts: "2026-10-31T10:00:00.000Z", scope: "refunds.read" }),
    ];
    const cards = deriveVaultCards(["stripe", "github"], events);
    expect(cards).toHaveLength(2);
    expect(cards[0]).toEqual({
      alias: "stripe",
      scopes: ["charges.read", "refunds.read"],
      lastUsedTs: "2026-10-31T11:00:00.000Z",
    });
    expect(cards[1]).toEqual({ alias: "github", scopes: [], lastUsedTs: null });
  });

  it("derives per-agent policy rows for the Policies view", () => {
    const events = [
      auditEvent(),
      auditEvent({ ts: "2026-10-31T11:00:00.000Z", scope: "refunds.read" }),
      auditEvent({ agentId: "codex", alias: "github", scope: "repos.read" }),
    ];
    const rows = derivePolicies(events);
    expect(rows.map((r) => r.agentId)).toEqual(["codex", "cursor"]);
    const cursor = rows.find((r) => r.agentId === "cursor");
    expect(cursor?.scopes).toEqual(["charges.read", "refunds.read"]);
    expect(cursor?.requestCount).toBe(2);
    expect(cursor?.lastSeenTs).toBe("2026-10-31T11:00:00.000Z");
  });

  it("projects policies responses with real ceilings and standing approvals", () => {
    const projected = projectPoliciesResponse({
      ceilings: { stripe: "charges.read", github: "repos.read" },
      standingApprovals: [{ agentId: "cursor", alias: "stripe", scope: "charges.read" }],
      benignExtra: "drop me",
    });
    expect(projected.ceilings).toEqual({ stripe: "charges.read", github: "repos.read" });
    expect(projected.standingApprovals).toEqual([
      { agentId: "cursor", alias: "stripe", scope: "charges.read" },
    ]);
    expect(projectPoliciesResponse(null)).toEqual({ ceilings: {}, standingApprovals: [] });
    expect(projectPoliciesResponse({ ceilings: "nope", standingApprovals: [] })).toEqual({
      ceilings: {},
      standingApprovals: [],
    });
  });

  it("fails closed on secret-like keys in policies payloads", () => {
    expect(
      projectPoliciesResponse({
        ceilings: { stripe: "charges.read" },
        standingApprovals: [],
        ciphertext: "canary",
      }),
    ).toEqual({ ceilings: {}, standingApprovals: [] });
    expect(
      projectPoliciesResponse({
        ceilings: { stripe: "charges.read" },
        standingApprovals: [{ agentId: "cursor", alias: "stripe", scope: "charges.read", secretValue: "x" }],
      }).standingApprovals,
    ).toEqual([]);
  });

  it("builds policy rows from real ceilings and standing approvals, not audit alone", () => {
    const events = [
      auditEvent(),
      auditEvent({ ts: "2026-10-31T11:00:00.000Z", scope: "refunds.read" }),
    ];
    const policies = {
      ceilings: { stripe: "charges.read", github: "repos.read" },
      standingApprovals: [{ agentId: "cursor", alias: "stripe", scope: "charges.read" }],
    };
    const rows = buildPolicyRows(events, policies);
    expect(rows.map((r) => r.agentId)).toEqual(["cursor"]);
    const cursor = rows[0];
    expect(cursor?.ceilings).toEqual([{ alias: "stripe", ceiling: "charges.read" }]);
    expect(cursor?.standingApprovals).toEqual([
      { agentId: "cursor", alias: "stripe", scope: "charges.read" },
    ]);
    // Observed scopes still come from audit; ceilings are the enforced caps.
    expect(cursor?.scopes).toEqual(["charges.read", "refunds.read"]);
    expect(cursor?.requestCount).toBe(2);
  });

  it("surfaces agents known only from standing approvals", () => {
    const rows = buildPolicyRows([], {
      ceilings: { stripe: "charges.read" },
      standingApprovals: [{ agentId: "codex", alias: "stripe", scope: "charges.read" }],
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.agentId).toBe("codex");
    expect(rows[0]?.ceilings).toEqual([{ alias: "stripe", ceiling: "charges.read" }]);
    expect(rows[0]?.requestCount).toBe(0);
    expect(rows[0]?.lastSeenTs).toBeNull();
  });

  it("builds audit rows newest-first with chain text and stage labels", () => {
    const rows = buildAuditRows([
      auditEvent({ stage: "requested" }),
      auditEvent({ stage: "approved", detail: "approved by human" }),
    ]);
    expect(rows.map((r) => r.stage)).toEqual(["approved", "requested"]);
    expect(rows[0]?.chain).toBe("cursor → charges.read → Approved");
    expect(rows[0]?.stageLabel).toBe("Approved");
    expect(rows[1]?.stageLabel).toBe("Requested");
  });
});
