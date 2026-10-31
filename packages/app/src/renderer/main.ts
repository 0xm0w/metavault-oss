import {
  buildAuditRows,
  buildPolicyRows,
  canAlwaysAllow,
  deriveVaultCards,
  formatExpiry,
  formatLastUsed,
  marshalStatusLine,
  projectAliasesResponse,
  projectAuditResponse,
  projectPendingResponse,
  projectPoliciesResponse,
  sortApprovals,
  stageLabel,
} from "./model.js";
import type { AuditEventLike, PendingApproval, PoliciesData } from "./types.js";

// Renderer bootstrap: plain TypeScript over the preload bridge. Every
// daemon payload is projected through model.ts whitelists before it is
// rendered, and all daemon text reaches the page via textContent only.

type ViewName = "approval" | "vault" | "audit" | "policies";

const POLL_MS = 4_000;

let currentView: ViewName = "approval";
let approvals: PendingApproval[] = [];
let aliases: string[] = [];
let auditEvents: AuditEventLike[] = [];
let policiesData: PoliciesData = { ceilings: {}, standingApprovals: [] };
let selectedGrantId: string | null = null;
let busy = false;
let notice: string | null = null;

function mustElement(selector: string): HTMLElement {
  const found = document.querySelector(selector);
  if (!(found instanceof HTMLElement)) {
    throw new Error(`missing element ${selector}`);
  }
  return found;
}

function el(tag: string, className: string, text?: string): HTMLElement {
  const node = document.createElement(tag);
  if (className !== "") {
    node.className = className;
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
}

function showBanner(message: string | null): void {
  const banner = mustElement("#banner");
  if (message === null) {
    banner.hidden = true;
    banner.textContent = "";
    return;
  }
  banner.hidden = false;
  banner.textContent = message;
}

function setDaemonStatus(ok: boolean): void {
  const status = mustElement("#daemon-status");
  status.textContent = ok ? "● vaultd connected" : "● vaultd unreachable";
  status.className = ok ? "daemon-status is-ok" : "daemon-status is-down";
}

function updateMarshalLine(): void {
  const fromPending = approvals.find((a) => a.modelId !== undefined)?.modelId;
  const fromAudit = auditEvents.find((e) => e.modelId !== undefined)?.modelId;
  mustElement("#marshal-line").textContent = marshalStatusLine(fromPending ?? fromAudit);
}

function selectedApproval(): PendingApproval | null {
  const sorted = sortApprovals(approvals);
  if (selectedGrantId !== null) {
    const chosen = sorted.find((a) => a.grantId === selectedGrantId);
    if (chosen !== undefined) {
      return chosen;
    }
  }
  return sorted[0] ?? null;
}

async function runAction(action: () => Promise<unknown>, done: string): Promise<void> {
  if (busy) {
    return;
  }
  busy = true;
  render();
  try {
    await action();
    notice = done;
    selectedGrantId = null;
    await refresh();
  } catch (err) {
    showBanner(err instanceof Error ? err.message : "Action failed");
  } finally {
    busy = false;
    render();
  }
}

function renderApproval(view: HTMLElement): void {
  view.append(el("h1", "", "Approval"));
  view.append(el("p", "sub", "An agent is asking for a scoped capability. The credential itself never leaves vaultd."));
  const hero = selectedApproval();
  if (hero === null) {
    const empty = el("div", "empty");
    empty.append(el("p", "", "No pending requests."));
    empty.append(el("p", "", "When an agent asks for access, the marshal assessment appears here for your decision. If this window is closed, requests wait in the tray queue and in vaultd."));
    view.append(empty);
    return;
  }

  const card = el("section", "hero");
  const want = el("p", "want");
  want.append(document.createTextNode(`${hero.agentId} in ${hero.ide} wants `));
  const scopeMono = el("span", "mono", hero.allowedScope);
  want.append(scopeMono);
  want.append(document.createTextNode(` on ${hero.alias}`));
  card.append(want);
  card.append(el("p", "reason", `“${hero.reason}”`));

  const assess = el("div", "assess");
  const heading = el("b", "");
  heading.append(document.createTextNode("MARSHAL ASSESSMENT"));
  const chip = el("span", `risk-chip risk-${hero.risk}`, `${hero.risk.toUpperCase()} RISK`);
  heading.append(chip);
  assess.append(heading);
  assess.append(document.createTextNode(hero.marshalExplanation));
  card.append(assess);

  const fine = el("p", "fine");
  const expiry = el("span", "");
  expiry.dataset["expiry"] = String(hero.expiresAtMs);
  expiry.textContent = formatExpiry(hero.expiresAtMs, Date.now());
  fine.append(expiry);
  fine.append(
    document.createTextNode(
      hero.requestedScope === hero.allowedScope
        ? `. Single execution, inside vaultd only. Tool: ${hero.tool}`
        : `. Requested ${hero.requestedScope}; policy allows ${hero.allowedScope}. Single execution, inside vaultd only.`,
    ),
  );
  card.append(fine);

  const buttons = el("div", "btns");
  const approveBtn = el("button", "action btn-approve", "Approve once") as HTMLButtonElement;
  approveBtn.type = "button";
  approveBtn.disabled = busy;
  approveBtn.addEventListener("click", () => {
    void runAction(() => window.openvault.approve(hero.grantId), "Approved — the grant executed inside vaultd and expired.");
  });
  const denyBtn = el("button", "action btn-deny", "Deny") as HTMLButtonElement;
  denyBtn.type = "button";
  denyBtn.disabled = busy;
  denyBtn.addEventListener("click", () => {
    void runAction(() => window.openvault.deny(hero.grantId), "Denied — the agent was told no, with the allowed ceiling.");
  });
  buttons.append(approveBtn, denyBtn);
  // Always allow is offered only for read-only low-risk grants; the daemon
  // re-checks the same rule before creating a standing approval.
  if (canAlwaysAllow(hero)) {
    const alwaysBtn = el("button", "action btn-always", "Always allow") as HTMLButtonElement;
    alwaysBtn.type = "button";
    alwaysBtn.disabled = busy;
    alwaysBtn.addEventListener("click", () => {
      void runAction(
        () => window.openvault.approveAlways(hero.grantId),
        `Standing approval saved for ${hero.agentId} · ${hero.allowedScope}. Read-only low-risk only; writes still ask every time.`,
      );
    });
    buttons.append(alwaysBtn);
  }
  card.append(buttons);
  view.append(card);

  const others = sortApprovals(approvals).filter((a) => a.grantId !== hero.grantId);
  if (others.length > 0) {
    const queue = el("div", "queue");
    queue.append(el("p", "label", `ALSO WAITING (${String(others.length)})`));
    for (const item of others) {
      const row = el("button", "queue-item") as HTMLButtonElement;
      row.type = "button";
      const left = el("span", "mono", `${item.agentId} · ${item.allowedScope}`);
      const right = el("span", "", formatExpiry(item.expiresAtMs, Date.now()));
      right.dataset["expiry"] = String(item.expiresAtMs);
      row.append(left, right);
      row.addEventListener("click", () => {
        selectedGrantId = item.grantId;
        render();
      });
      queue.append(row);
    }
    view.append(queue);
  }
}

function renderVault(view: HTMLElement): void {
  view.append(el("h1", "", "Vault"));
  view.append(el("p", "sub", "Credentials enrolled in vaultd. Cards show aliases and scopes only — values are never displayed, copied, or sent to this window."));
  if (aliases.length === 0) {
    view.append(el("div", "empty", "No credentials yet. Add one with the CLI: openvault add <alias> --scope <scope>"));
    return;
  }
  const cards = el("div", "cards");
  for (const card of deriveVaultCards(aliases, auditEvents)) {
    const node = el("article", "card");
    node.append(el("h2", "mono", card.alias));
    const chips = el("div", "");
    if (card.scopes.length === 0) {
      chips.append(el("span", "chip", "no requests yet"));
    }
    for (const scope of card.scopes) {
      chips.append(el("span", "chip", scope));
    }
    node.append(chips);
    node.append(el("p", "meta", `Last used · ${formatLastUsed(card.lastUsedTs, Date.now())}`));
    cards.append(node);
  }
  view.append(cards);
}

function renderAudit(view: HTMLElement): void {
  view.append(el("h1", "", "Audit"));
  view.append(el("p", "sub", "Every transition, in order: agent → scope → marshal → policy → human → expiry. Marshal rows name the model that advised."));
  const rows = buildAuditRows(auditEvents);
  if (rows.length === 0) {
    view.append(el("div", "empty", "No audit events yet."));
    return;
  }
  const list = el("div", "rows");
  for (const row of rows) {
    const node = el("article", "row");
    node.append(el("div", "chain", row.chain));
    const detail = el("div", "detail", row.detail);
    node.append(detail);
    const when = el("div", "when", row.modelId !== undefined ? `${row.ts} · model ${row.modelId}` : row.ts);
    node.append(when);
    list.append(node);
  }
  view.append(list);
}

function renderPolicies(view: HTMLElement): void {
  view.append(el("h1", "", "Policies"));
  view.append(el("p", "sub", "Deterministic ceilings are enforced inside vaultd policy; the marshal can only narrow them. Revoking an agent blocks its pending and future grants immediately."));
  const rows = buildPolicyRows(auditEvents, policiesData);
  const ceilingEntries = Object.entries(policiesData.ceilings).sort(([a], [b]) =>
    a.localeCompare(b),
  );
  if (rows.length === 0 && ceilingEntries.length === 0) {
    view.append(el("div", "empty", "No agent activity yet. Agents appear here after their first request."));
    return;
  }
  if (ceilingEntries.length > 0) {
    const caps = el("div", "rows");
    const capsNode = el("article", "row");
    capsNode.append(el("div", "chain", "Enforced ceilings (per alias)"));
    const capChips = el("div", "");
    for (const [alias, ceiling] of ceilingEntries) {
      capChips.append(el("span", "chip", `${alias}: ${ceiling}`));
    }
    capsNode.append(capChips);
    capsNode.append(el("div", "when", "Ceilings are read from vaultd policy state, not inferred from observed requests."));
    caps.append(capsNode);
    view.append(caps);
  }
  const list = el("div", "rows");
  for (const row of rows) {
    const node = el("article", "row policy-row");
    const grow = el("div", "grow");
    grow.append(el("div", "chain", row.agentId));
    const chips = el("div", "");
    if (row.scopes.length === 0) {
      chips.append(el("span", "chip", "no scopes observed"));
    }
    for (const scope of row.scopes) {
      chips.append(el("span", "chip", scope));
    }
    grow.append(chips);
    const ceilingChips = el("div", "");
    if (row.ceilings.length === 0) {
      ceilingChips.append(el("span", "chip", "no ceiling on record"));
    }
    for (const entry of row.ceilings) {
      ceilingChips.append(el("span", "chip", `ceiling ${entry.alias}: ${entry.ceiling}`));
    }
    grow.append(ceilingChips);
    const standingChips = el("div", "");
    if (row.standingApprovals.length === 0) {
      standingChips.append(el("span", "chip", "no standing approvals"));
    }
    for (const approval of row.standingApprovals) {
      standingChips.append(
        el("span", "chip", `standing ${approval.alias}: ${approval.scope}`),
      );
    }
    grow.append(standingChips);
    grow.append(
      el("div", "when", `${String(row.requestCount)} requests · last seen ${formatLastUsed(row.lastSeenTs, Date.now())} · ceiling enforced by vaultd`),
    );
    node.append(grow);
    const revokeBtn = el("button", "action btn-revoke", "Revoke") as HTMLButtonElement;
    revokeBtn.type = "button";
    revokeBtn.disabled = busy;
    revokeBtn.addEventListener("click", () => {
      void runAction(() => window.openvault.revoke(row.agentId), `Revoked ${row.agentId} — pending grants cancelled, new requests denied.`);
    });
    node.append(revokeBtn);
    list.append(node);
  }
  view.append(list);
  const note = el("p", "fine", `Stages: ${(["requested", "marshal", "policy", "approved", "denied", "executed", "expired", "revoked"] as const).map(stageLabel).join(" · ")}`);
  view.append(note);
}

function render(): void {
  const view = mustElement("#view");
  view.replaceChildren();
  showBanner(notice);
  if (currentView === "approval") {
    renderApproval(view);
  } else if (currentView === "vault") {
    renderVault(view);
  } else if (currentView === "audit") {
    renderAudit(view);
  } else {
    renderPolicies(view);
  }
}

async function refresh(): Promise<void> {
  try {
    const [pendingRaw, aliasesRaw, auditRaw, policiesRaw] = await Promise.all([
      window.openvault.pending(),
      window.openvault.aliases(),
      window.openvault.audit(),
      window.openvault.policies(),
    ]);
    approvals = projectPendingResponse(pendingRaw);
    aliases = projectAliasesResponse(aliasesRaw);
    auditEvents = projectAuditResponse(auditRaw);
    policiesData = projectPoliciesResponse(policiesRaw);
    setDaemonStatus(true);
    updateMarshalLine();
  } catch (err) {
    setDaemonStatus(false);
    showBanner(err instanceof Error ? err.message : "Could not reach vaultd");
  }
  render();
}

function tickExpiryLabels(): void {
  const now = Date.now();
  document.querySelectorAll<HTMLElement>("[data-expiry]").forEach((node) => {
    const raw = node.dataset["expiry"];
    if (raw !== undefined) {
      node.textContent = formatExpiry(Number(raw), now);
    }
  });
}

function start(): void {
  document.querySelectorAll<HTMLButtonElement>(".nav-btn").forEach((button) => {
    button.addEventListener("click", () => {
      const next = button.dataset["view"];
      if (next === "approval" || next === "vault" || next === "audit" || next === "policies") {
        currentView = next;
        notice = null;
        document.querySelectorAll(".nav-btn").forEach((b) => {
          b.classList.toggle("is-active", b === button);
        });
        render();
      }
    });
  });
  void refresh();
  window.setInterval(() => {
    void refresh();
  }, POLL_MS);
  window.setInterval(tickExpiryLabels, 1_000);
}

start();
