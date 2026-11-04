import { describe, expect, it } from "vitest";
import {
  projectSshTunnelResult,
  projectSshTunnelStatus,
  MIN_PASSPHRASE_LENGTH,
  TOKENS,
  keyGateErrorMessage,
  passphraseSetupError,
  projectKeyGate,
  buildAuditRows,
  buildEditPayload,
  buildPolicyRows,
  canAlwaysAllow,
  credentialInitial,
  derivePolicies,
  deriveVaultCards,
  faviconUrl,
  filterAuditGroups,
  paginate,
  groupAuditByRequest,
  findSecretLikeKeys,
  formatExpiry,
  formatLastUsed,
  isCredentialFormComplete,
  isReadOnlyScope,
  marshalStatusLine,
  normalizeWebsite,
  projectApproval,
  projectDevicesResponse,
  projectPairingSession,
  projectRemoteSettings,
  shouldRequireAuthForRemoteApproval,
  projectAuditEvent,
  projectCredentialsResponse,
  projectCardMeta,
  parseCardExpiry,
  isCardFormComplete,
  cardLabel,
  projectPendingResponse,
  projectPoliciesResponse,
  runDeeplinkAddFlow,
  shouldShowAgentComputerWarning,
  sortApprovals,
  wardenVerdict,
  DEFAULT_WARDEN_SETTINGS,
  EFFORT_OPTIONS,
  LOCAL_API_OPTIONS,
  SUGGESTED_LOCAL_BASE_URL,
  SUGGESTED_LOCAL_MODEL,
  WARDEN_PROVIDERS,
  isLocalBaseUrlValid,
  buildWardenPatch,
  isWardenFormComplete,
  META_API_MODEL_OPTIONS,
  DEFAULT_META_API_MODEL_ID,
  isKnownMetaApiModel,
  projectWardenKeyStatus,
  projectWardenSettings,
  wardenKeyStatusText,
  projectWardenTestResult,
  wardenTestMessage,
  projectSecurityPosture,
  parseDotEnv,
  inferAliasAndScope,
  parseDotEnvWithInference,
  projectLocalAuthStatus,
  DEFAULT_LOCAL_AUTH_STATUS,
  shouldPromptPinSetupOnEnable,
  shouldLockOnLaunch,
  shouldRequireAuthForApproval,
  shouldRequireAuthForSettings,
  isBiometricsActive,
  localAuthFactorLabel,
  isAutoLockDue,
  canLockSessionNow,
  isSettingsTab,
  SETTINGS_TABS,} from "../src/renderer/model.js";
import type { AuditEventLike, DeeplinkAddParams, PendingApproval, WardenSettingsLike } from "../src/renderer/types.js";

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
    expect(canAlwaysAllow(approval({ verified: false }))).toBe(false);
  });
});

describe("marshal status line", () => {
  it("renders the Muse Spark Meta API line by default", () => {
    expect(marshalStatusLine()).toBe("Marshal · muse-spark-1.3 · Meta API");
    expect(marshalStatusLine(undefined)).toBe("Marshal · muse-spark-1.3 · Meta API");
    expect(marshalStatusLine("  ")).toBe("Marshal · muse-spark-1.3 · Meta API");
    expect(marshalStatusLine("muse-spark-1.2")).toBe("Marshal · muse-spark-1.2 · Meta API");
  });

  it("names a bring-your-own model without claiming where it runs", () => {
    expect(marshalStatusLine("muse-glimmer:30b")).toBe("Marshal · muse-glimmer:30b");
    expect(marshalStatusLine("custom-model:7b")).toBe("Marshal · custom-model:7b");
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

  it("does not create phantom policy rows from admin or enrollment lifecycle events", () => {
    const rows = derivePolicies([
      auditEvent({
        stage: "settings-changed",
        agentId: "human",
        detail: "warden settings changed: provider=none model=muse-glimmer:30b",
      }),
      auditEvent({
        stage: "enrollment-created",
        agentId: "agent",
        detail: "enrollment created: stripe",
      }),
      auditEvent({
        stage: "enrollment-completed",
        agentId: "agent",
        detail: "enrollment completed: stripe",
      }),
      auditEvent({
        stage: "credential-deleted",
        agentId: "human",
        detail: "credential deleted: stripe",
      }),
    ]);
    expect(rows).toEqual([]);
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
    for (const unsafe of ['example.com"><svg onload=alert(1)>', 'user@example.com', 'example.com:443', 'example.com\\evil', 'a'.repeat(254) + '.com']) expect(faviconUrl(unsafe)).toBeNull();
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

describe("payment card credential type", () => {
  it("projects card kind with brand + last 4 only and carries it into vault rows", () => {
    const raw = {
      aliases: ["corp-visa"],
      credentials: [{ alias: "corp-visa", website: "", kind: "card", card: { brand: "visa", last4: "4242", masked: "x" } }],
    };
    const meta = projectCredentialsResponse(raw);
    expect(meta).toEqual([{ alias: "corp-visa", website: "", kind: "card", card: { brand: "visa", last4: "4242", masked: "\u2022\u2022\u2022\u2022 4242" } }]);
    const rows = deriveVaultCards(["corp-visa"], [], meta);
    expect(rows[0]?.card?.last4).toBe("4242");
    expect(cardLabel(rows[0]?.card ?? { brand: "", last4: "", masked: "" })).toBe("Visa \u2022\u2022\u2022\u2022 4242");
  });
  it("drops card metadata that is not exactly 4 digits", () => {
    expect(projectCardMeta({ brand: "visa", last4: "4242424242424242" })).toBeNull();
    expect(projectCardMeta(null)).toBeNull();
    const meta = projectCredentialsResponse({ aliases: [], credentials: [{ alias: "c", website: "", kind: "card", card: { brand: "visa", last4: "12345" } }] });
    expect(meta).toEqual([{ alias: "c", website: "" }]);
  });
  it("parses MM/YY expiry and gates the add-card form", () => {
    expect(parseCardExpiry("12/29")).toEqual({ expMonth: 12, expYear: 2029 });
    expect(parseCardExpiry("1/2031")).toEqual({ expMonth: 1, expYear: 2031 });
    expect(parseCardExpiry("13/29")).toBeNull();
    expect(isCardFormComplete("visa", "4242 4242 4242 4242", "Ada", "12/29", "123")).toBe(true);
    expect(isCardFormComplete("visa", "4242", "Ada", "12/29", "123")).toBe(false);
    expect(isCardFormComplete("visa", "4242 4242 4242 4242", "Ada", "12/29", "")).toBe(false);
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
      modelId: "muse-glimmer:30b",
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

  it("sorts events within a bucket by ts regardless of input order", () => {
    const shuffled: AuditEventLike[] = [
      chain({ stage: "executed", ts: "2026-10-31T10:00:04.000Z" }),
      chain({ stage: "requested", ts: "2026-10-31T10:00:00.000Z" }),
      chain({ stage: "approved", ts: "2026-10-31T10:00:03.000Z" }),
      chain({ stage: "marshal", ts: "2026-10-31T10:00:01.000Z" }),
    ];
    const group = firstGroup(shuffled);
    expect(group.events.map((e) => e.stage)).toEqual(["requested", "marshal", "approved", "executed"]);
    expect(group.firstTs).toBe("2026-10-31T10:00:00.000Z");
    expect(group.lastTs).toBe("2026-10-31T10:00:04.000Z");
    expect(group.isLegacy).toBe(false);
  });

  it("marks the no-requestId bucket as legacy", () => {
    const groups = groupAuditByRequest([
      auditEvent({ stage: "credential-added", agentId: "human", detail: "credential added: stripe (charges.read)" }),
      auditEvent({ stage: "executed", agentId: "cursor", detail: "executed" }),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.requestId).toBe("legacy");
    expect(groups[0]?.isLegacy).toBe(true);
  });

  it("derives a human-denied verdict and never shows the requested scope as allowed", () => {
    const events: AuditEventLike[] = [
      chain({ requestId: "req-human-denied", stage: "requested", ts: "2026-10-31T10:00:00.000Z", scope: "charges.read" }),
      chain({
        requestId: "req-human-denied",
        stage: "marshal",
        ts: "2026-10-31T10:00:01.000Z",
        scope: "charges.read",
        detail: "marshal decision",
        modelId: "muse-glimmer:30b",
        risk: "low",
        recommendedScope: "charges.read",
        decisionSource: "marshal",
        explanation: "read-only",
      }),
      chain({ requestId: "req-human-denied", stage: "policy", ts: "2026-10-31T10:00:02.000Z", scope: "charges.read", detail: "approval-required", decisionSource: "marshal+policy" }),
      chain({ requestId: "req-human-denied", stage: "denied", ts: "2026-10-31T10:00:03.000Z", scope: "charges.read", detail: "denied by human", decisionSource: "human" }),
    ];
    const group = firstGroup(events);
    expect(group.allowedScope).toBeNull();
    const verdict = wardenVerdict(group);
    expect(verdict.outcome).toBe("denied");
    expect(verdict.outcomeLabel).toBe("Denied");
    expect(verdict.decisionSource).toBe("human");
    expect(verdict.allowedScope).toBeNull();
    expect(verdict.requestedScope).toBe("charges.read");
  });

  it("treats routine narrowing as narrowed, not escalated", () => {
    const events: AuditEventLike[] = [
      chain({ requestId: "req-narrow", stage: "requested", ts: "2026-10-31T10:00:00.000Z", scope: "charges.write" }),
      chain({
        requestId: "req-narrow",
        stage: "marshal",
        ts: "2026-10-31T10:00:01.000Z",
        scope: "charges.write",
        detail: "marshal decision",
        modelId: "muse-glimmer:30b",
        risk: "low",
        recommendedScope: "charges.read",
        decisionSource: "marshal",
        explanation: "read is enough",
      }),
      chain({ requestId: "req-narrow", stage: "executed", ts: "2026-10-31T10:00:02.000Z", scope: "charges.read", decisionSource: "marshal+policy" }),
    ];
    const verdict = wardenVerdict(firstGroup(events));
    expect(verdict.escalated).toBe(false);
    expect(verdict.narrowed).toBe(true);
  });

  it("derives an executed verdict with risk + model from the marshal event", () => {
    const verdict = wardenVerdict(firstGroup(executedChain));
    expect(verdict.outcome).toBe("executed");
    expect(verdict.outcomeLabel).toBe("Executed");
    expect(verdict.risk).toBe("low");
    expect(verdict.modelId).toBe("muse-glimmer:30b");
    expect(verdict.isPolicyOnly).toBe(false);
    expect(verdict.wardenLabel).toBe("low · muse-glimmer:30b");
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
    expect(verdict.allowedScope).toBeNull();
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
        modelId: "muse-glimmer:30b",
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
    expect(verdict.narrowed).toBe(true);
    expect(verdict.wardenLabel).toBe("high · muse-glimmer:30b");
    expect(verdict.outcome).toBe("pending");
    expect(verdict.recommendedScope).toBe("charges.read");
  });

  it("reports expired and revoked outcomes from the terminal stage", () => {
    const expired = firstGroup([
      chain({ requestId: "r-exp", stage: "requested" }),
      chain({ requestId: "r-exp", stage: "expired", ts: "2026-10-31T10:05:00.000Z" }),
    ]);
    expect(wardenVerdict(expired).outcome).toBe("expired");
    expect(wardenVerdict(expired).allowedScope).toBeNull();
    expect(expired.allowedScope).toBeNull();
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

describe("warden settings form state (Task 6)", () => {
  it("defaults to Muse Spark on the Meta API with no local endpoint set", () => {
    expect(DEFAULT_WARDEN_SETTINGS).toEqual({
      provider: "meta-api",
      model: "muse-spark-1.3",
      effort: "standard",
      metaApiBaseUrl: "https://api.meta.ai/v1",
      localBaseUrl: "",
      localApi: "ollama",
      localModel: "",
    });
    expect(WARDEN_PROVIDERS.map((p) => p.id)).toEqual(["meta-api", "local", "bft", "none"]);
    expect(LOCAL_API_OPTIONS.map((o) => o.id)).toEqual(["ollama", "openai"]);
    expect(SUGGESTED_LOCAL_MODEL).toBe("muse-glimmer:30b");
    expect(SUGGESTED_LOCAL_BASE_URL.ollama).toBe("http://localhost:11434");
    expect(SUGGESTED_LOCAL_BASE_URL.openai).toBe("http://localhost:8000/v1");
    expect(EFFORT_OPTIONS.map((e) => e.id)).toEqual(["fast", "standard", "deep"]);
    for (const e of EFFORT_OPTIONS) expect(e.description.length).toBeGreaterThan(10);
  });

  it("projects warden settings whitelisted fields only and validates enums", () => {
    expect(projectWardenSettings({ provider: "meta-api", model: "muse-spark-1.3", effort: "deep", metaApiBaseUrl: "https://api.meta.ai/v1", extra: 1 })).toEqual({
      provider: "meta-api", model: "muse-spark-1.3", effort: "deep", metaApiBaseUrl: "https://api.meta.ai/v1",
      localBaseUrl: "", localApi: "ollama", localModel: "",
    });
    expect(projectWardenSettings({
      provider: "local", model: "muse-spark-1.3", effort: "fast", metaApiBaseUrl: "u",
      localBaseUrl: "http://localhost:8000/v1", localApi: "openai", localModel: "muse-glimmer:30b",
    })).toEqual({
      provider: "local", model: "muse-spark-1.3", effort: "fast", metaApiBaseUrl: "u",
      localBaseUrl: "http://localhost:8000/v1", localApi: "openai", localModel: "muse-glimmer:30b",
    });
    // Legacy provider names from older daemons map to the BYO local endpoint.
    expect(projectWardenSettings({ provider: "builtin", model: "x", effort: "fast", metaApiBaseUrl: "u" })?.provider).toBe("local");
    expect(projectWardenSettings({ provider: "ollama", model: "x", effort: "fast", metaApiBaseUrl: "u", localApi: "grpc" })?.localApi).toBe("ollama");
    expect(projectWardenSettings({ provider: "evil", model: "x", effort: "standard", metaApiBaseUrl: "u" })).toBeNull();
    expect(projectWardenSettings({ provider: "ollama", model: "x", effort: "turbo", metaApiBaseUrl: "u" })).toBeNull();
    expect(projectWardenSettings(null)).toBeNull();
    expect(projectWardenSettings({ provider: "ollama", model: "x", effort: "fast", metaApiBaseUrl: "u", apiKey: "canary" })).toBeNull();
  });

  it("projects key status without ever exposing a key and formats status text", () => {
    expect(projectWardenKeyStatus({ configured: true, last4: "1234" })).toEqual({ configured: true, last4: "1234" });
    expect(projectWardenKeyStatus({ configured: false, last4: null })).toEqual({ configured: false, last4: null });
    expect(projectWardenKeyStatus({ configured: true, last4: "1234", key: "canary" })).toBeNull();
    expect(projectWardenKeyStatus("nope")).toBeNull();
    expect(wardenKeyStatusText({ configured: false, last4: null })).toBe("Not configured");
    expect(wardenKeyStatusText({ configured: true, last4: "1234" })).toBe("Configured \u2022\u2022\u2022\u20221234");
    expect(wardenKeyStatusText({ configured: true, last4: null })).toBe("Configured");
  });

  it("builds a trimmed patch and checks form completeness", () => {
    const s: WardenSettingsLike = {
      provider: "meta-api", model: "  muse-spark-1.3  ", effort: "fast", metaApiBaseUrl: " https://api.meta.ai/v1 ",
      localBaseUrl: " http://localhost:11434 ", localApi: "ollama", localModel: " muse-glimmer:30b ",
    };
    expect(buildWardenPatch(s)).toEqual({
      provider: "meta-api", model: "muse-spark-1.3", effort: "fast", metaApiBaseUrl: "https://api.meta.ai/v1",
      localBaseUrl: "http://localhost:11434", localApi: "ollama", localModel: "muse-glimmer:30b",
    });
    expect(isWardenFormComplete(s)).toBe(true);
    expect(isWardenFormComplete({ ...s, model: "  " })).toBe(false);
    expect(isWardenFormComplete({ ...s, metaApiBaseUrl: "" })).toBe(false);
    expect(isWardenFormComplete({ ...DEFAULT_WARDEN_SETTINGS, provider: "none", model: "", metaApiBaseUrl: "" })).toBe(true);
    const local: WardenSettingsLike = { ...DEFAULT_WARDEN_SETTINGS, provider: "local", localBaseUrl: "http://localhost:11434", localModel: "muse-glimmer:30b" };
    expect(isWardenFormComplete(local)).toBe(true);
    expect(isWardenFormComplete({ ...local, localBaseUrl: "" })).toBe(false);
    expect(isWardenFormComplete({ ...local, localModel: " " })).toBe(false);
    expect(isWardenFormComplete({ ...local, localBaseUrl: "file:///etc/passwd" })).toBe(false);
    expect(isWardenFormComplete({ ...local, localBaseUrl: "http://user:pw@localhost:11434" })).toBe(false);
    // BFT: the local leg is optional, but a typed URL must be valid and named.
    const bft: WardenSettingsLike = { ...DEFAULT_WARDEN_SETTINGS, provider: "bft" };
    expect(isWardenFormComplete(bft)).toBe(true);
    expect(isWardenFormComplete({ ...bft, localBaseUrl: "http://localhost:11434" })).toBe(false);
    expect(isWardenFormComplete({ ...bft, localBaseUrl: "http://localhost:11434", localModel: "muse-glimmer:30b" })).toBe(true);
    expect(isLocalBaseUrlValid("https://gpu-box.lan:8000/v1")).toBe(true);
    expect(isLocalBaseUrlValid("not a url")).toBe(false);
  });

  it("maps warden test failure reasons to specific copy without secrets", () => {
    const base = { ok: false, provider: "meta-api", model: "muse-spark-1.3", latencyMs: 3, detail: "warden unavailable" };
    for (const reason of ["no_key", "vault_locked", "key_unreadable", "unauthorized", "rate_limited", "bad_request", "http_error", "timeout", "network", "bad_response", "unavailable"]) {
      const projected = projectWardenTestResult({ ...base, reason });
      if (projected === null) throw new Error("projection failed");
      expect(projected.reason).toBe(reason);
      const msg = wardenTestMessage(projected);
      expect(msg.ok).toBe(false);
      expect(msg.message).not.toContain("did not respond");
    }
    const msgFor = (reason: string): string => {
      const projected = projectWardenTestResult({ ...base, reason });
      if (projected === null) throw new Error("projection failed");
      return wardenTestMessage(projected).message;
    };
    expect(msgFor("no_key")).toContain("Save key");
    expect(msgFor("vault_locked").toLowerCase()).toContain("locked");
    expect(msgFor("unauthorized")).toContain("401");
    // Unknown reason is dropped and falls back to the generic copy.
    const unknown = projectWardenTestResult({ ...base, reason: "Bearer abc" });
    if (unknown === null) throw new Error("projection failed");
    expect(unknown.reason).toBeUndefined();
    expect(wardenTestMessage(unknown).message).toContain("did not respond");
  });

  it("projects real warden test results strictly and maps them to honest copy", () => {
    const raw = { ok: true, provider: "meta-api", model: "muse-spark-1.3", latencyMs: 42, detail: "ok" };
    expect(projectWardenTestResult(raw)).toEqual(raw);
    expect(projectWardenTestResult({ ...raw, ok: "yes" })).toBeNull();
    expect(projectWardenTestResult({ ...raw, provider: "evil" })).toBeNull();
    expect(projectWardenTestResult({ ...raw, latencyMs: -1 })).toBeNull();
    expect(projectWardenTestResult({ ...raw, apiKey: "canary" })).toBeNull();
    expect(projectWardenTestResult(null)).toBeNull();
    const okMsg = wardenTestMessage({ ok: true, provider: "meta-api", model: "muse-spark-1.3", latencyMs: 42, detail: "ok" });
    expect(okMsg.ok).toBe(true);
    expect(okMsg.message).toContain("meta-api");
    expect(okMsg.message).toContain("muse-spark-1.3");
    expect(okMsg.message).toContain("42");
    expect(okMsg.message).not.toContain("canary");
    const failMsg = wardenTestMessage({ ok: false, provider: "meta-api", model: "muse-spark-1.3", latencyMs: 7, detail: "warden unavailable" });
    expect(failMsg.ok).toBe(false);
    expect(failMsg.message.toLowerCase()).toContain("fail");
    expect(failMsg.message).not.toContain("reachable");
    const localFail = wardenTestMessage({ ok: false, provider: "local", model: "muse-glimmer:30b", latencyMs: 7, detail: "connection refused" });
    expect(localFail.ok).toBe(false);
    expect(localFail.message).toContain("go to you for approval");
    const localOk = wardenTestMessage({ ok: true, provider: "local", model: "muse-glimmer:30b", latencyMs: 12, detail: "ok" });
    expect(localOk.message).toContain("muse-glimmer:30b");
    expect(projectWardenTestResult({ ...raw, provider: "ollama" })?.provider).toBe("local");
    const noneMsg = wardenTestMessage({ ok: true, provider: "none", model: "muse-glimmer:30b", latencyMs: 0, detail: "policy-only" });
    expect(noneMsg.ok).toBe(true);
    expect(noneMsg.message.toLowerCase()).toContain("policy-only");
  });
});

describe("audit filtering and pagination", () => {
  function auditEvent(overrides: Record<string, unknown> = {}) {
    return {
      ts: "2026-10-31T10:00:00.000Z",
      agentId: "cursor",
      alias: "stripe",
      scope: "charges.read",
      stage: "requested" as const,
      detail: "read charges",
      ...overrides,
    };
  }

  it("supports advanced filter options and structured queries for audit groups", () => {
    const now = Date.parse("2026-10-31T12:00:00.000Z");
    const groups = groupAuditByRequest([
      auditEvent({ requestId: "r1", stage: "requested", ts: "2026-10-31T11:55:00.000Z", agentId: "cursor", alias: "stripe", scope: "charges.read" }),
      auditEvent({ requestId: "r1", stage: "executed", ts: "2026-10-31T11:55:01.000Z", agentId: "cursor", alias: "stripe", scope: "charges.read" }),
      auditEvent({ requestId: "r2", stage: "requested", ts: "2026-10-30T10:00:00.000Z", agentId: "claude-code", alias: "github", scope: "repos.write" }),
      auditEvent({ requestId: "r2", stage: "denied", ts: "2026-10-30T10:00:01.000Z", agentId: "claude-code", alias: "github", scope: "repos.write" }),
    ]);

    // Structured tokens in query
    expect(filterAuditGroups(groups, "agent:cursor").map(g => g.requestId)).toEqual(["r1"]);
    expect(filterAuditGroups(groups, "caller:claude").map(g => g.requestId)).toEqual(["r2"]);
    expect(filterAuditGroups(groups, "alias:stripe").map(g => g.requestId)).toEqual(["r1"]);
    expect(filterAuditGroups(groups, "outcome:denied").map(g => g.requestId)).toEqual(["r2"]);
    expect(filterAuditGroups(groups, "scope:write").map(g => g.requestId)).toEqual(["r2"]);

    // Options object
    expect(filterAuditGroups(groups, { outcome: "executed" }).map(g => g.requestId)).toEqual(["r1"]);
    expect(filterAuditGroups(groups, { outcome: "denied" }).map(g => g.requestId)).toEqual(["r2"]);
    expect(filterAuditGroups(groups, { agentId: "cursor" }).map(g => g.requestId)).toEqual(["r1"]);
    expect(filterAuditGroups(groups, { alias: "github" }).map(g => g.requestId)).toEqual(["r2"]);
    expect(filterAuditGroups(groups, { dateRange: "today", nowMs: now }).map(g => g.requestId)).toEqual(["r1"]);
    expect(filterAuditGroups(groups, { dateRange: "7d", nowMs: now }).map(g => g.requestId)).toEqual(["r1", "r2"]);
  });

  it("paginates arrays correctly", () => {
    const items = [1, 2, 3, 4, 5, 6, 7];
    const p1 = paginate(items, 1, 3);
    expect(p1.items).toEqual([1, 2, 3]);
    expect(p1.totalItems).toBe(7);
    expect(p1.totalPages).toBe(3);
    expect(p1.currentPage).toBe(1);
    expect(p1.startIndex).toBe(1);
    expect(p1.endIndex).toBe(3);

    const p3 = paginate(items, 3, 3);
    expect(p3.items).toEqual([7]);
    expect(p3.currentPage).toBe(3);
    expect(p3.startIndex).toBe(7);
    expect(p3.endIndex).toBe(7);

    const pOut = paginate(items, 99, 3);
    expect(pOut.currentPage).toBe(3);
    expect(pOut.items).toEqual([7]);

    const empty = paginate([], 1, 10);
    expect(empty.items).toEqual([]);
    expect(empty.totalItems).toBe(0);
    expect(empty.totalPages).toBe(1);
    expect(empty.startIndex).toBe(0);
    expect(empty.endIndex).toBe(0);
  });
});


describe("projectSecurityPosture", () => {
  it("projects valid security posture report", () => {
    const raw = {
      score: 85,
      grade: "A",
      summary: "Vault is operating with high posture",
      checks: [
        { id: "chk-warden", name: "Active Warden", description: "Warden enabled", passed: true, severity: "critical", scoreImpact: 20 },
      ],
      issues: [],
      remediations: [],
    };
    const res = projectSecurityPosture(raw);
    expect(res).not.toBeNull();
    expect(res?.score).toBe(85);
    expect(res?.grade).toBe("A");
    expect(res?.checks.length).toBe(1);
  });

  it("fails closed if secret-like fields leak into posture report", () => {
    const leaky = {
      score: 90,
      grade: "A+",
      summary: "Good",
      checks: [],
      issues: [],
      remediations: [],
      secret: "sk-ant-live-super-secret",
    };
    expect(projectSecurityPosture(leaky)).toBeNull();
  });

  it("returns null on invalid shapes", () => {
    expect(projectSecurityPosture(null)).toBeNull();
    expect(projectSecurityPosture("not-an-object")).toBeNull();
    expect(projectSecurityPosture({ score: "NaN" })).toBeNull();
  });
});

describe("dotenv parser and inference (#17)", () => {
  it("parses environment entries and strips comments", () => {
    const raw = "PORT=8080\n# comment\nDEBUG=true # inline";
    const entries = parseDotEnv(raw);
    expect(entries).toEqual([
      { key: "PORT", value: "8080" },
      { key: "DEBUG", value: "true" },
    ]);
  });

  it("infers alias and scope correctly", () => {
    expect(inferAliasAndScope("STRIPE_SECRET_KEY")).toEqual({
      alias: "stripe",
      scope: "charges.read",
    });
    expect(inferAliasAndScope("OPENAI_API_KEY")).toEqual({
      alias: "openai",
      scope: "chat.completions",
    });
    expect(inferAliasAndScope("MY_KEY")).toEqual({
      alias: "my",
      scope: "read",
    });
  });

  it("generates import items with default included true", () => {
    const raw = "STRIPE_KEY=sk_test_123";
    const items = parseDotEnvWithInference(raw);
    expect(items).toHaveLength(1);
    expect(items[0]).toEqual({
      rawKey: "STRIPE_KEY",
      alias: "stripe",
      scope: "charges.read",
      value: "sk_test_123",
      included: true,
    });
  });
});

describe("projectLocalAuthStatus (#19)", () => {
  it("projects valid local auth status and verifies all layers are off by default", () => {
    const raw = {
      enabled: true,
      configured: true,
      biometricEnabled: true,
      requireOnApproval: true,
      requireOnLaunch: false,
      requireOnSettings: true,
      autoLockMinutes: 15,
    };
    const projected = projectLocalAuthStatus(raw);
    expect(projected).toEqual(raw);
    expect(DEFAULT_LOCAL_AUTH_STATUS.enabled).toBe(false);
    expect(DEFAULT_LOCAL_AUTH_STATUS.configured).toBe(false);
    expect(DEFAULT_LOCAL_AUTH_STATUS.biometricEnabled).toBe(false);
    expect(DEFAULT_LOCAL_AUTH_STATUS.requireOnApproval).toBe(false);
    expect(DEFAULT_LOCAL_AUTH_STATUS.requireOnLaunch).toBe(false);
    expect(DEFAULT_LOCAL_AUTH_STATUS.requireOnSettings).toBe(false);
    expect(DEFAULT_LOCAL_AUTH_STATUS.autoLockMinutes).toBe(0);
  });

  it("fails closed on secret-like leakage or invalid shapes", () => {
    const leaky = {
      enabled: true,
      configured: true,
      requireOnApproval: true,
      requireOnLaunch: false,
      autoLockMinutes: 15,
      pinHash: "secret-hash-leaked",
    };
    expect(projectLocalAuthStatus(leaky)).toBeNull();
    expect(projectLocalAuthStatus(null)).toBeNull();
    expect(projectLocalAuthStatus({ enabled: "true" })).toBeNull();
  });

  describe("ON-state verification for each protection layer (#19)", () => {
    // Base configured state
    const baseAuth = {
      enabled: true,
      configured: true,
      biometricEnabled: false,
      requireOnApproval: false,
      requireOnLaunch: false,
      requireOnSettings: false,
      autoLockMinutes: 0,
    };

    it("Layer 1: Enable local authentication gate (Master switch)", () => {
      // When unconfigured, enabling prompts PIN setup modal
      expect(shouldPromptPinSetupOnEnable({ ...baseAuth, configured: false })).toBe(true);
      // When already configured, no setup modal needed
      expect(shouldPromptPinSetupOnEnable({ ...baseAuth, configured: true })).toBe(false);

      // When master switch is OFF, all gates are bypassed
      const off = { ...baseAuth, enabled: false, requireOnLaunch: true, requireOnApproval: true, requireOnSettings: true, biometricEnabled: true, autoLockMinutes: 15 };
      expect(shouldLockOnLaunch(off)).toBe(false);
      expect(shouldRequireAuthForApproval(off, "charges.write")).toBe(false);
      expect(shouldRequireAuthForSettings(off)).toBe(false);
      expect(isBiometricsActive(off)).toBe(false);
      expect(isAutoLockDue(off, 0, 100_000_000)).toBe(false);
      expect(canLockSessionNow(off)).toBe(false);
    });

    it("Layer 2: Require on app launch / initial unlock", () => {
      const on = { ...baseAuth, requireOnLaunch: true };
      expect(shouldLockOnLaunch(on)).toBe(true);

      // No app PIN and no Windows Hello: cannot lock on launch.
      expect(shouldLockOnLaunch({ ...on, configured: false })).toBe(false);
      // Windows Hello alone is enough to lock on launch.
      expect(shouldLockOnLaunch({ ...on, configured: false, biometricEnabled: true })).toBe(true);

      // If master switch disabled, launch gate does not lock
      expect(shouldLockOnLaunch({ ...on, enabled: false })).toBe(false);

      // If requireOnLaunch is OFF, launch gate does not lock
      expect(shouldLockOnLaunch({ ...baseAuth, requireOnLaunch: false })).toBe(false);
    });

    it("Layer 3: Require on capability approvals", () => {
      const on = { ...baseAuth, requireOnApproval: true };

      // Write-level scopes demand PIN verification
      expect(shouldRequireAuthForApproval(on, "charges.write")).toBe(true);
      expect(shouldRequireAuthForApproval(on, "users.create")).toBe(true);
      expect(shouldRequireAuthForApproval(on, "data:write")).toBe(true);

      // High risk demands PIN verification even on read scopes
      expect(shouldRequireAuthForApproval(on, "charges.read", "high")).toBe(true);

      // Low/medium read-only scopes do not require PIN prompt
      expect(shouldRequireAuthForApproval(on, "charges.read", "low")).toBe(false);
      expect(shouldRequireAuthForApproval(on, "stripe.charges.read", "medium")).toBe(false);

      // When requireOnApproval is OFF, write scopes do not demand PIN
      expect(shouldRequireAuthForApproval(baseAuth, "charges.write")).toBe(false);
    });

    it("Layer 4: Require to modify security settings & policies", () => {
      const on = { ...baseAuth, requireOnSettings: true };
      expect(shouldRequireAuthForSettings(on)).toBe(true);

      // When requireOnSettings is OFF, settings modifications do not prompt
      expect(shouldRequireAuthForSettings({ ...baseAuth, requireOnSettings: false })).toBe(false);

      // When master switch is OFF, settings modifications do not prompt
      expect(shouldRequireAuthForSettings({ ...on, enabled: false })).toBe(false);
    });

    it("Layer 5: Enable Windows Hello / Touch ID biometrics", () => {
      const on = { ...baseAuth, biometricEnabled: true };
      expect(isBiometricsActive(on)).toBe(true);

      // When biometricEnabled is OFF
      expect(isBiometricsActive({ ...baseAuth, biometricEnabled: false })).toBe(false);

      // When master switch is OFF
      expect(isBiometricsActive({ ...on, enabled: false })).toBe(false);
      expect(localAuthFactorLabel({ ...baseAuth, enabled: false, biometricEnabled: true })).toBe("Off");
      expect(localAuthFactorLabel(on)).toBe("Windows Hello on · App PIN set");
      expect(localAuthFactorLabel({ ...baseAuth, configured: false, biometricEnabled: true })).toBe("Windows Hello on");
      expect(localAuthFactorLabel({ ...baseAuth, biometricEnabled: false })).toBe("App PIN only");
    });

    it("Layer 6: Inactivity auto-lock session", () => {
      const now = 1_000_000_000;

      // 1 minute auto-lock
      const oneMin = { ...baseAuth, autoLockMinutes: 1 };
      expect(isAutoLockDue(oneMin, now - 30_000, now)).toBe(false); // 30s < 1m
      expect(isAutoLockDue(oneMin, now - 61_000, now)).toBe(true);  // 61s > 1m

      // 5 minutes auto-lock
      const fiveMin = { ...baseAuth, autoLockMinutes: 5 };
      expect(isAutoLockDue(fiveMin, now - 4 * 60 * 1000, now)).toBe(false);
      expect(isAutoLockDue(fiveMin, now - (5 * 60 * 1000 + 1), now)).toBe(true);

      // 15, 30, 60 minutes auto-lock
      const fifteenMin = { ...baseAuth, autoLockMinutes: 15 };
      expect(isAutoLockDue(fifteenMin, now - 14 * 60 * 1000, now)).toBe(false);
      expect(isAutoLockDue(fifteenMin, now - 16 * 60 * 1000, now)).toBe(true);

      // 0 minutes (Disabled)
      expect(isAutoLockDue(baseAuth, now - 999_999_999, now)).toBe(false);

      // When master switch is OFF, auto-lock never triggers
      expect(isAutoLockDue({ ...oneMin, enabled: false }, now - 999_999_999, now)).toBe(false);
    });

    it("Layer 7: Lock session now", () => {
      // Available and active when enabled and configured
      expect(canLockSessionNow(baseAuth)).toBe(true);

      // Not available when there is no app PIN and no Windows Hello
      expect(canLockSessionNow({ ...baseAuth, configured: false })).toBe(false);
      expect(canLockSessionNow({ ...baseAuth, configured: false, biometricEnabled: true })).toBe(true);

      // Not available when master switch is disabled
      expect(canLockSessionNow({ ...baseAuth, enabled: false })).toBe(false);
    });
  });

  describe("Meta API Models", () => {
    it("recognizes known Meta AI models and allows custom model IDs", () => {
      expect(META_API_MODEL_OPTIONS.length).toBeGreaterThan(0);
      expect(isKnownMetaApiModel("muse-spark-1.3")).toBe(true);
      expect(isKnownMetaApiModel("muse-spark-1.2")).toBe(true);
      expect(isKnownMetaApiModel("muse-wonder-1.0")).toBe(true);
      // Only approved Meta model ids are offered (sources: dev.meta.ai/docs/models,
      // ollama.com/library/muse-glimmer). Anything else must fail this allowlist.
      const APPROVED_META_API_IDS = ["muse-spark-1.3", "muse-spark-1.2", "muse-wonder-1.0"];
      expect(META_API_MODEL_OPTIONS.map((o) => o.id)).toEqual(APPROVED_META_API_IDS);
      expect(APPROVED_META_API_IDS).toContain(DEFAULT_META_API_MODEL_ID);
      expect(DEFAULT_WARDEN_SETTINGS.model).toBe(DEFAULT_META_API_MODEL_ID);
      expect(isKnownMetaApiModel("custom-fine-tuned-meta-model")).toBe(false);
    });
  });
});

describe("vault key gate", () => {
  it("asks for a new passphrase on a first-run daemon and for unlock on a locked passphrase vault", () => {
    expect(projectKeyGate({ mode: "uninitialized", locked: true })).toBe("setup");
    expect(projectKeyGate({ mode: "passphrase", locked: true })).toBe("unlock");
    expect(projectKeyGate({ mode: "passphrase", locked: false })).toBeNull();
    expect(projectKeyGate({ mode: "keychain-legacy", locked: false })).toBeNull();
    expect(projectKeyGate(null)).toBeNull();
    expect(projectKeyGate("nope")).toBeNull();
  });

  it("checks passphrase length the way the daemon does, and that both entries match", () => {
    expect(passphraseSetupError("short", "short")).toContain(String(MIN_PASSPHRASE_LENGTH));
    expect(passphraseSetupError("twelve chars", "twelve chars")).toBeNull();
    expect(passphraseSetupError("twelve chars", "twelve charz")).toBe("The two passwords do not match.");
  });

  it("turns daemon error tags into plain words", () => {
    expect(keyGateErrorMessage("MetaVault OSS daemon error (401): WrongPassphrase")).toBe("Wrong password or damaged key file.");
    expect(keyGateErrorMessage("daemon error (429): UnlockThrottled")).toContain("Wait");
    expect(keyGateErrorMessage("daemon error (400): PassphraseTooShort")).toContain("12");
    expect(keyGateErrorMessage("daemon error (409): AlreadyInitialized")).toContain("Unlock");
    expect(keyGateErrorMessage("MetaVault OSS daemon unreachable — is vaultd running?")).toContain("background service");
    expect(keyGateErrorMessage("daemon error (409): VaultRecoveryRequired")).toContain("matching database and key backup");
    expect(keyGateErrorMessage("something else")).toBe("That did not work. Try again.");
  });
});

describe("remote connections model", () => {
  it("requires local auth for remote approvals by default, and only for remote origin", () => {
    expect(shouldRequireAuthForRemoteApproval(null, { origin: "remote" })).toBe(true);
    expect(shouldRequireAuthForRemoteApproval({ enabled: true }, { origin: "remote" })).toBe(true);
    expect(shouldRequireAuthForRemoteApproval({ enabled: true, requireAuthForRemoteApproval: true }, { origin: "remote" })).toBe(true);
    expect(shouldRequireAuthForRemoteApproval({ enabled: true, requireAuthForRemoteApproval: false }, { origin: "remote" })).toBe(false);
    expect(shouldRequireAuthForRemoteApproval({ enabled: true, requireAuthForRemoteApproval: true }, { origin: "local" })).toBe(false);
    expect(shouldRequireAuthForRemoteApproval({ enabled: true, requireAuthForRemoteApproval: true }, {})).toBe(false);
  });

  it("projects remote settings conservatively", () => {
    expect(projectRemoteSettings(null)).toBeNull();
    expect(projectRemoteSettings({})).toBeNull();
    expect(projectRemoteSettings({ enabled: false })).toEqual({ enabled: false });
    expect(projectRemoteSettings({ enabled: true, host: "127.0.0.1", port: 7078, requireAuthForRemoteApproval: false })).toEqual({
      enabled: true,
      host: "127.0.0.1",
      port: 7078,
      requireAuthForRemoteApproval: false,
    });
    expect(projectRemoteSettings({ enabled: true, port: 0 })).toEqual({ enabled: true });
  });

  it("carries remote origin fields through approval projection", () => {
    const approval = projectApproval({
      grantId: "g1",
      agentId: "remote-ide",
      ide: "vscode",
      tool: "http",
      alias: "stripe",
      requestedScope: "charges.read",
      allowedScope: "charges.read",
      reason: "test",
      marshalExplanation: "policy",
      createdAtMs: 1,
      expiresAtMs: 2,
      risk: "low",
      origin: "remote",
      deviceId: "dev-abc123",
      transport: "loopback",
    });
    expect(approval?.origin).toBe("remote");
    expect(approval?.deviceId).toBe("dev-abc123");
    expect(approval?.transport).toBe("loopback");
    const local = projectApproval({
      grantId: "g2",
      agentId: "a",
      ide: "i",
      tool: "t",
      alias: "stripe",
      requestedScope: "charges.read",
      allowedScope: "charges.read",
      reason: "r",
      marshalExplanation: "m",
      createdAtMs: 1,
      expiresAtMs: 2,
      risk: "low",
      origin: "bogus",
    });
    expect(local?.origin).toBeUndefined();
  });

  it("projects devices and pairing sessions defensively", () => {
    expect(projectDevicesResponse(null)).toEqual([]);
    expect(projectDevicesResponse({ devices: [{ id: "dev-1", name: "laptop", platform: "win32", pairedAt: "2026-11-04T00:00:00Z" }, { name: "no-id" }] })).toEqual([
      { id: "dev-1", name: "laptop", platform: "win32", pairedAt: "2026-11-04T00:00:00Z" },
    ]);
    expect(projectPairingSession({ session: null })).toBeNull();
    expect(projectPairingSession({ session: { status: "joined", sas: "AB12-CD34-EF56-7890", deviceName: "laptop", pairingId: "p1" } })).toEqual({
      status: "joined",
      sas: "AB12-CD34-EF56-7890",
      deviceName: "laptop",
      pairingId: "p1",
    });
    expect(projectPairingSession({})).toBeNull();
  });
});

describe("settings tabs", () => {
  it("every tab the UI renders passes the dispatcher predicate", () => {
    // Regression: a Connections tab unreachable by click because the
    // dispatcher whitelist dropped it.
    for (const tab of ["general", "warden", "daemon", "security", "connections"]) {
      expect(isSettingsTab(tab)).toBe(true);
    }
    expect(isSettingsTab("admin")).toBe(false);
    expect(isSettingsTab(undefined)).toBe(false);
    expect(SETTINGS_TABS).toHaveLength(5);
  });
});

describe("SSH tunnel projections", () => {
  const validStatus = {
    state: "connected",
    configured: true,
    host: "relay.example.com",
    user: "mow",
    port: 22,
    remotePairingPort: 7078,
    remoteDevicePort: 7080,
    fingerprint: "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
    autoReconnect: true,
    connectedSince: "2026-11-04T12:00:00.000Z",
  };

  it("projects a valid status and drops junk fields", () => {
    const projected = projectSshTunnelStatus({ ...validStatus, evil: "<script>" });
    expect(projected).toEqual(validStatus);
  });

  it("rejects unknown states and non-boolean configured", () => {
    expect(projectSshTunnelStatus({ ...validStatus, state: "pwned" })).toBeNull();
    expect(projectSshTunnelStatus({ ...validStatus, configured: "yes" })).toBeNull();
    expect(projectSshTunnelStatus(null)).toBeNull();
    expect(projectSshTunnelStatus("connected")).toBeNull();
  });

  it("drops malformed optional fields instead of failing", () => {
    const projected = projectSshTunnelStatus({ ...validStatus, port: 70000, fingerprint: "not-a-fp", detail: "x".repeat(400) });
    expect(projected).not.toBeNull();
    expect(projected?.port).toBeUndefined();
    expect(projected?.fingerprint).toBeUndefined();
    expect(projected?.detail).toBeUndefined();
  });

  it("projects tagged results and rejects junk", () => {
    expect(projectSshTunnelResult({ kind: "ok" })).toEqual({ kind: "ok" });
    expect(projectSshTunnelResult({ kind: "error", error: "nope" })).toEqual({ kind: "error", error: "nope" });
    expect(projectSshTunnelResult({ kind: "status", status: validStatus })).toEqual({ kind: "status", status: validStatus });
    expect(projectSshTunnelResult({ kind: "status", status: { state: "pwned" } })).toBeNull();
    expect(projectSshTunnelResult({ kind: "verification", verified: true })).toEqual({ kind: "verification", verified: true });
    expect(projectSshTunnelResult({ kind: "verification", verified: "yes" })).toBeNull();
    expect(projectSshTunnelResult({ kind: "exec" })).toBeNull();
  });
});
