import { describe, expect, it } from "vitest";
import {
  TOKENS,
  buildAuditRows,
  buildEditPayload,
  buildPolicyRows,
  canAlwaysAllow,
  credentialInitial,
  derivePolicies,
  deriveVaultCards,
  faviconUrl,
  filterAuditGroups,
  groupAuditByRequest,
  findSecretLikeKeys,
  formatExpiry,
  formatLastUsed,
  isCredentialFormComplete,
  isReadOnlyScope,
  marshalStatusLine,
  normalizeWebsite,
  projectApproval,
  projectAuditEvent,
  projectCredentialsResponse,
  projectPendingResponse,
  projectPoliciesResponse,
  runDeeplinkAddFlow,
  shouldShowAgentComputerWarning,
  sortApprovals,
  wardenVerdict,
} from "../src/renderer/model.js";
import type { AuditEventLike, DeeplinkAddParams, PendingApproval } from "../src/renderer/types.js";

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

describe("unified warm tokens", () => {
  it("pins the warm palette exactly", () => {
    expect(TOKENS.surface).toBe("#FFFFFF");
    expect(TOKENS.background).toBe("#FAF9F6");
    expect(TOKENS.ink).toBe("#201A17");
    expect(TOKENS.muted).toBe("#8A8174");
    expect(TOKENS.border).toBe("#E6DDD0");
    expect(TOKENS.field).toBe("#F5F1EC");
    expect(TOKENS.primary).toBe("#201A17");
    expect(TOKENS.danger).toBe("#DC2626");
    expect(TOKENS.teal).toBe("#0F766E");
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
      website: "",
    });
    expect(cards[1]).toEqual({ alias: "github", scopes: [], lastUsedTs: null, website: "" });
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

describe("credential form helpers", () => {
  it("derives avatar initials", () => {
    expect(credentialInitial("stripe")).toBe("S");
    expect(credentialInitial(" github ")).toBe("G");
    expect(credentialInitial("")).toBe("?");
    expect(credentialInitial("   ")).toBe("?");
  });

  it("requires all credential fields non-empty", () => {
    expect(isCredentialFormComplete("Stripe", "charges.read", "test-secret")).toBe(true);
    expect(isCredentialFormComplete("", "charges.read", "test-secret")).toBe(false);
    expect(isCredentialFormComplete("Stripe", "  ", "test-secret")).toBe(false);
    expect(isCredentialFormComplete("Stripe", "charges.read", "")).toBe(false);
    expect(isCredentialFormComplete("  Stripe  ", " charges.read ", "x")).toBe(true);
  });

  it("rejects a whitespace-only secret in the form completeness mirror", () => {
    expect(isCredentialFormComplete("Stripe", "charges.read", "   ")).toBe(false);
    expect(isCredentialFormComplete("Stripe", "charges.read", " x ")).toBe(true);
  });

  it("does not count credential-added as last used (just-added reads Never used)", () => {
    const now = Date.parse("2026-10-31T12:00:00.000Z");
    const cards = deriveVaultCards(
      ["stripe"],
      [
        auditEvent({
          stage: "credential-added",
          agentId: "human",
          ts: "2026-10-31T11:59:30.000Z",
          detail: "credential added: stripe (charges.read)",
        }),
      ],
    );
    expect(cards[0]?.lastUsedTs).toBeNull();
    expect(formatLastUsed(cards[0]?.lastUsedTs ?? null, now)).toBe("Never used");
    // Real usage still counts.
    const used = deriveVaultCards(
      ["stripe"],
      [
        auditEvent({
          stage: "credential-added",
          agentId: "human",
          ts: "2026-10-31T11:59:30.000Z",
          detail: "credential added: stripe (charges.read)",
        }),
        auditEvent({ stage: "executed", ts: "2026-10-31T11:00:00.000Z" }),
      ],
    );
    expect(used[0]?.lastUsedTs).toBe("2026-10-31T11:00:00.000Z");
  });

  it("does not create a phantom human policy row from credential-added", () => {
    const rows = derivePolicies([
      auditEvent({
        stage: "credential-added",
        agentId: "human",
        detail: "credential added: stripe (charges.read)",
      }),
    ]);
    expect(rows).toEqual([]);
    const mixed = derivePolicies([
      auditEvent({
        stage: "credential-added",
        agentId: "human",
        detail: "credential added: stripe (charges.read)",
      }),
      auditEvent(),
    ]);
    expect(mixed.map((r) => r.agentId)).toEqual(["cursor"]);
  });

  it("projects credential-added audit events", () => {
    expect(projectAuditEvent(auditEvent({ stage: "credential-added", detail: "credential added: stripe (charges.read)" }))).toEqual(
      auditEvent({ stage: "credential-added", detail: "credential added: stripe (charges.read)" }),
    );
  });
});

describe("agent-computer warning visibility", () => {
  it("shows only when website is non-empty", () => {
    expect(shouldShowAgentComputerWarning("")).toBe(false);
    expect(shouldShowAgentComputerWarning("   ")).toBe(false);
    expect(shouldShowAgentComputerWarning("github.com")).toBe(true);
    expect(shouldShowAgentComputerWarning("https://github.com/x")).toBe(true);
  });
});

describe("website, favicon and edit payload", () => {
  it("builds favicon URLs from bare and full websites", () => {
    expect(faviconUrl("cloudflare.com")).toBe("https://cloudflare.com/favicon.ico");
    expect(faviconUrl("https://cloudflare.com/dns")).toBe("https://cloudflare.com/favicon.ico");
    expect(faviconUrl("  Example.COM ")).toBe("https://example.com/favicon.ico");
    expect(faviconUrl("")).toBeNull();
    expect(faviconUrl("localhost")).toBeNull();
    expect(normalizeWebsite("https://Example.com/path?q=1")).toBe("example.com");
  });

  it("omits empty secret from the edit payload so the daemon keeps the current secret", () => {
    expect(buildEditPayload({ scope: " dns.read ", website: "https://cloudflare.com/x", secret: "" })).toEqual({
      scope: "dns.read",
      website: "cloudflare.com",
    });
    expect(buildEditPayload({ scope: "dns.read", website: "", secret: "new-secret" })).toEqual({
      scope: "dns.read",
      website: "",
      secret: "new-secret",
    });
  });

  it("projects credential metadata with websites and carries it into vault cards", () => {
    const raw = {
      aliases: ["stripe", "cf"],
      credentials: [
        { alias: "stripe", website: "" },
        { alias: "cf", website: "cloudflare.com" },
      ],
    };
    expect(projectCredentialsResponse(raw)).toEqual([
      { alias: "stripe", website: "" },
      { alias: "cf", website: "cloudflare.com" },
    ]);
    const cards = deriveVaultCards(["cf"], [], projectCredentialsResponse(raw));
    expect(cards[0]?.website).toBe("cloudflare.com");
    expect(projectCredentialsResponse({ aliases: ["stripe"] })).toEqual([{ alias: "stripe", website: "" }]);
    expect(projectCredentialsResponse({ aliases: [], credentials: [{ alias: "x", website: "a.com", secret: "no" }] })).toEqual([]);
  });
});

describe("deeplink add flow sequencing", () => {
  const params: DeeplinkAddParams = {
    alias: "github",
    scope: "repo.read",
    website: "github.com",
    enrollmentId: "5e392c08-2d7d-4395-bd84-36f1bb2a279e",
  };

  function deferred(): { promise: Promise<void>; resolve: () => void } {
    let resolve: () => void = () => undefined;
    const promise = new Promise<void>((res) => {
      resolve = res;
    });
    return { promise, resolve };
  }

  it("opens the prefilled modal only after an async render completes", async () => {
    const order: string[] = [];
    const gate = deferred();
    let openedWith: DeeplinkAddParams | null = null;
    const flow = runDeeplinkAddFlow(params, {
      switchToVault: () => {
        order.push("switch");
      },
      renderVault: () => {
        order.push("render-start");
        return gate.promise.then(() => {
          order.push("render-done");
        });
      },
      closeModalIfOpen: () => {
        order.push("close");
      },
      openAddModal: (prefill) => {
        order.push("open");
        openedWith = prefill;
      },
    });
    // The modal must not open while the render is still in flight: this
    // is the race that left deeplinks with no modal on screen.
    await Promise.resolve();
    expect(order).toEqual(["switch", "render-start"]);
    expect(openedWith).toBeNull();
    gate.resolve();
    await flow;
    expect(order).toEqual(["switch", "render-start", "render-done", "close", "open"]);
    expect(openedWith).toEqual(params);
  });

  it("replaces an already-open modal: close runs before the prefilled open", async () => {
    const order: string[] = [];
    let modalOpen = true;
    await runDeeplinkAddFlow(params, {
      switchToVault: () => {
        order.push("switch");
      },
      renderVault: () => {
        order.push("render");
      },
      closeModalIfOpen: () => {
        if (modalOpen) {
          order.push("close");
          modalOpen = false;
        }
      },
      openAddModal: () => {
        order.push("open");
        modalOpen = true;
      },
    });
    expect(order).toEqual(["switch", "render", "close", "open"]);
    expect(modalOpen).toBe(true);
  });

  it("still opens after a synchronous render from a non-Vault view", async () => {
    const order: string[] = [];
    await runDeeplinkAddFlow(params, {
      switchToVault: () => {
        order.push("switch");
      },
      renderVault: () => {
        order.push("render");
      },
      closeModalIfOpen: () => {
        order.push("close");
      },
      openAddModal: (prefill) => {
        order.push("open:" + prefill.alias + ":" + prefill.scope + ":" + prefill.website + ":" + prefill.enrollmentId);
      },
    });
    expect(order).toEqual([
      "switch",
      "render",
      "close",
      "open:github:repo.read:github.com:5e392c08-2d7d-4395-bd84-36f1bb2a279e",
    ]);
  });

  it("propagates a render failure and never opens the modal", async () => {
    let opened = false;
    await expect(
      runDeeplinkAddFlow(params, {
        switchToVault: () => undefined,
        renderVault: () => Promise.reject(new Error("view missing")),
        closeModalIfOpen: () => undefined,
        openAddModal: () => {
          opened = true;
        },
      }),
    ).rejects.toThrow("view missing");
    expect(opened).toBe(false);
  });
});

describe("audit request grouping and warden verdicts (Task 5)", () => {
  const chain = (over: Partial<AuditEventLike> = {}): AuditEventLike =>
    auditEvent({ requestId: "req-1", ...over });

  const firstGroup = (events: readonly AuditEventLike[]) => {
    const group = groupAuditByRequest(events)[0];
    if (group === undefined) {
      throw new Error("expected an audit group");
    }
    return group;
  };

  const executedChain: AuditEventLike[] = [
    chain({ stage: "requested", ts: "2026-10-31T10:00:00.000Z", scope: "charges.read" }),
    chain({
      stage: "marshal",
      ts: "2026-10-31T10:00:01.000Z",
      scope: "charges.read",
      detail: "marshal decision",
      modelId: "llama3.2:3b",
      risk: "low",
      recommendedScope: "charges.read",
      decisionSource: "marshal",
      latencyMs: 42,
      explanation: "low-risk read of charges",
    }),
    chain({ stage: "policy", ts: "2026-10-31T10:00:02.000Z", scope: "charges.read", detail: "within ceiling", decisionSource: "marshal+policy" }),
    chain({ stage: "approved", ts: "2026-10-31T10:00:03.000Z", scope: "charges.read", detail: "auto-approved by policy", decisionSource: "marshal+policy" }),
    chain({ stage: "executed", ts: "2026-10-31T10:00:04.000Z", scope: "charges.read", detail: "executed", decisionSource: "marshal+policy" }),
  ];

  it("groups one row per requestId, legacy under legacy, newest first, events chronological", () => {
    const older: AuditEventLike[] = [
      chain({ requestId: "req-old", stage: "requested", ts: "2026-10-31T09:00:00.000Z", alias: "github", scope: "repos.read" }),
      chain({ requestId: "req-old", stage: "denied", ts: "2026-10-31T09:00:01.000Z", alias: "github", scope: "repos.read", decisionSource: "policy" }),
    ];
    const legacy: AuditEventLike[] = [
      auditEvent({ stage: "credential-added", agentId: "human", ts: "2026-10-31T08:00:00.000Z", detail: "credential added: stripe (charges.read)" }),
    ];
    const groups = groupAuditByRequest([...legacy, ...older, ...executedChain]);
    expect(groups.map((g) => g.requestId)).toEqual(["req-1", "req-old", "legacy"]);
    const first = groups[0];
    expect(first?.events.map((e) => e.stage)).toEqual(["requested", "marshal", "policy", "approved", "executed"]);
    expect(first?.agentId).toBe("cursor");
    expect(first?.alias).toBe("stripe");
    expect(first?.requestedScope).toBe("charges.read");
    expect(first?.allowedScope).toBe("charges.read");
    expect(first?.outcome).toBe("executed");
    expect(groups[2]?.events).toHaveLength(1);
    expect(groups[2]?.requestId).toBe("legacy");
  });

  it("derives an executed verdict with risk + model from the marshal event", () => {
    const verdict = wardenVerdict(firstGroup(executedChain));
    expect(verdict.outcome).toBe("executed");
    expect(verdict.outcomeLabel).toBe("Executed");
    expect(verdict.risk).toBe("low");
    expect(verdict.modelId).toBe("llama3.2:3b");
    expect(verdict.isPolicyOnly).toBe(false);
    expect(verdict.wardenLabel).toBe("low · llama3.2:3b");
    expect(verdict.recommendedScope).toBe("charges.read");
    expect(verdict.latencyMs).toBe(42);
    expect(verdict.explanation).toBe("low-risk read of charges");
    expect(verdict.decisionSource).toBe("marshal+policy");
    expect(verdict.escalated).toBe(false);
  });

  it("derives a policy-only verdict for a policy-denied chain with no marshal event", () => {
    const events: AuditEventLike[] = [
      chain({ requestId: "req-denied", stage: "requested", ts: "2026-10-31T10:00:00.000Z", scope: "charges.write" }),
      chain({ requestId: "req-denied", stage: "policy", ts: "2026-10-31T10:00:01.000Z", scope: "charges.write", detail: "scope-above-ceiling", decisionSource: "policy" }),
      chain({ requestId: "req-denied", stage: "denied", ts: "2026-10-31T10:00:02.000Z", scope: "charges.write", detail: "scope-above-ceiling", decisionSource: "policy" }),
    ];
    const verdict = wardenVerdict(firstGroup(events));
    expect(verdict.outcome).toBe("denied");
    expect(verdict.isPolicyOnly).toBe(true);
    expect(verdict.wardenLabel).toBe("policy-only");
    expect(verdict.risk).toBeNull();
    expect(verdict.decisionSource).toBe("policy");
  });

  it("flags a marshal-escalated chain where the recommended scope narrows the request", () => {
    const events: AuditEventLike[] = [
      chain({ requestId: "req-esc", stage: "requested", ts: "2026-10-31T10:00:00.000Z", scope: "charges.write" }),
      chain({
        requestId: "req-esc",
        stage: "marshal",
        ts: "2026-10-31T10:00:01.000Z",
        scope: "charges.write",
        detail: "marshal decision",
        modelId: "llama3.1:8b",
        risk: "high",
        recommendedScope: "charges.read",
        decisionSource: "marshal",
        latencyMs: 120,
        explanation: "write is too broad; read is enough",
      }),
      chain({ requestId: "req-esc", stage: "policy", ts: "2026-10-31T10:00:02.000Z", scope: "charges.read", detail: "narrowed", decisionSource: "marshal+policy" }),
      chain({ requestId: "req-esc", stage: "approved", ts: "2026-10-31T10:00:03.000Z", scope: "charges.read", detail: "approved by human", decisionSource: "human" }),
    ];
    const group = firstGroup(events);
    expect(group.requestedScope).toBe("charges.write");
    expect(group.allowedScope).toBe("charges.read");
    const verdict = wardenVerdict(group);
    expect(verdict.escalated).toBe(true);
    expect(verdict.wardenLabel).toBe("high · llama3.1:8b");
    expect(verdict.outcome).toBe("pending");
    expect(verdict.recommendedScope).toBe("charges.read");
  });

  it("reports expired and revoked outcomes from the terminal stage", () => {
    const expired = firstGroup([
      chain({ requestId: "r-exp", stage: "requested" }),
      chain({ requestId: "r-exp", stage: "expired", ts: "2026-10-31T10:05:00.000Z" }),
    ]);
    expect(wardenVerdict(expired).outcome).toBe("expired");
    const revoked = firstGroup([
      chain({ requestId: "r-rev", stage: "requested" }),
      chain({ requestId: "r-rev", stage: "revoked", ts: "2026-10-31T10:05:00.000Z" }),
    ]);
    expect(wardenVerdict(revoked).outcome).toBe("revoked");
  });

  it("filters groups by agent, alias and outcome text, case-insensitively", () => {
    const groups = groupAuditByRequest([
      ...executedChain,
      chain({ requestId: "req-old", stage: "requested", ts: "2026-10-31T09:00:00.000Z", agentId: "codex", alias: "github", scope: "repos.read" }),
      chain({ requestId: "req-old", stage: "denied", ts: "2026-10-31T09:00:01.000Z", agentId: "codex", alias: "github", scope: "repos.read", decisionSource: "policy" }),
    ]);
    expect(filterAuditGroups(groups, "").map((g) => g.requestId)).toEqual(["req-1", "req-old"]);
    expect(filterAuditGroups(groups, "CURSOR").map((g) => g.requestId)).toEqual(["req-1"]);
    expect(filterAuditGroups(groups, "github").map((g) => g.requestId)).toEqual(["req-old"]);
    expect(filterAuditGroups(groups, "denied").map((g) => g.requestId)).toEqual(["req-old"]);
    expect(filterAuditGroups(groups, "executed").map((g) => g.requestId)).toEqual(["req-1"]);
    expect(filterAuditGroups(groups, "nope")).toEqual([]);
  });

  it("projects the Task 4 audit fields and drops invalid optional values", () => {
    expect(projectAuditEvent(executedChain[1])).toEqual(executedChain[1]);
    const projected = projectAuditEvent({
      ...auditEvent(),
      requestId: "req-9",
      risk: "critical",
      latencyMs: "fast",
      decisionSource: "nobody",
      explanation: 42,
    });
    expect(projected?.requestId).toBe("req-9");
    expect(projected?.risk).toBeUndefined();
    expect(projected?.latencyMs).toBeUndefined();
    expect(projected?.decisionSource).toBeUndefined();
    expect(projected?.explanation).toBeUndefined();
  });
});
