import {
  filterAuditGroups,
  buildEditPayload,
  buildPolicyRows,
  canAlwaysAllow,
  credentialInitial,
  deriveVaultCards,
  faviconUrl,
  formatExpiry,
  formatLastUsed,
  groupAuditByRequest,
  isCredentialFormComplete,
  marshalStatusLine,
  normalizeWebsite,
  projectAliasesResponse,
  projectAuditResponse,
  projectCredentialsResponse,
  projectPendingResponse,
  projectPoliciesResponse,
  runDeeplinkAddFlow,
  shouldShowAgentComputerWarning,
  sortApprovals,
  stageLabel,
  wardenVerdict,
  APP_VERSION_DISPLAY,
  DAEMON_URL_DISPLAY,
  DEFAULT_WARDEN_SETTINGS,
  EFFORT_OPTIONS,
  OLLAMA_MODEL_OPTIONS,
  VAULT_PATH_DISPLAY,
  WARDEN_PROVIDERS,
  buildWardenPatch,
  isKnownOllamaModel,
  isWardenFormComplete,
  projectWardenKeyStatus,
  projectWardenSettings,
  wardenKeyStatusText,
  projectWardenTestResult,
  wardenTestMessage,
} from "./model.js";
import type { AuditEventLike, CredentialMeta, DeeplinkAddParams, PendingApproval, PoliciesData, WardenKeyStatusLike, WardenSettingsLike } from "./types.js";

// Renderer bootstrap: plain TypeScript over the preload bridge. Every
// daemon payload is projected through model.ts whitelists before it is
// rendered, and all daemon text reaches the page via textContent only.

type ViewName = "approval" | "vault" | "audit" | "policies" | "settings";

const POLL_MS = 4_000;

let currentView: ViewName = "approval";
let approvals: PendingApproval[] = [];
let aliases: string[] = [];
let credentialMeta: CredentialMeta[] = [];
let auditEvents: AuditEventLike[] = [];
let policiesData: PoliciesData = { ceilings: {}, standingApprovals: [] };
let selectedGrantId: string | null = null;
let auditFilter = "";
let auditFilterWasFocused = false;
let auditFilterSelectionStart: number | null = null;
let auditFilterSelectionEnd: number | null = null;
const expandedAuditIds = new Set<string>();
let busy = false;
let notice: string | null = null;
let wardenDraft: WardenSettingsLike = { ...DEFAULT_WARDEN_SETTINGS };
let wardenKeyStatusState: WardenKeyStatusLike = { configured: false, last4: null };
let wardenLoaded = false;
let wardenDirty = false;
let settingsKeyDraft = "";
let settingsBusy = false;
let settingsMessage: { readonly text: string; readonly ok: boolean } | null = null;

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
  if (wardenLoaded) {
    const line = mustElement("#marshal-line");
    if (wardenDraft.provider === "none") {
      line.textContent = "Marshal \u00B7 Off \u00B7 Policy only";
    } else if (wardenDraft.provider === "meta-api") {
      line.textContent = `Marshal \u00B7 ${wardenDraft.model} \u00B7 Meta API (cloud)`;
    } else {
      line.textContent = marshalStatusLine(wardenDraft.model);
    }
    return;
  }
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

let credentialModal: HTMLElement | null = null;
let credentialModalKeyHandler: ((event: KeyboardEvent) => void) | null = null;

function closeCredentialModal(restoreFocus = true): void {
  if (credentialModalKeyHandler !== null) {
    document.removeEventListener("keydown", credentialModalKeyHandler);
    credentialModalKeyHandler = null;
  }
  if (credentialModal !== null) {
    credentialModal.remove();
    credentialModal = null;
  }
  const trigger = document.querySelector<HTMLElement>(".vault-add-btn");
  if (restoreFocus) {
    trigger?.focus();
  }
}

function openCredentialModal(prefill?: DeeplinkAddParams): void {
  if (credentialModal !== null) {
    return;
  }
  const overlay = el("div", "vault-modal-overlay");
  const dialog = el("div", "vault-modal");
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-labelledby", "vault-modal-title");

  const header = el("div", "vault-modal-header");
  const title = el("h2", "vault-modal-title", "Add credential");
  title.id = "vault-modal-title";
  const closeBtn = el("button", "vault-modal-close", "\u00D7") as HTMLButtonElement;
  closeBtn.type = "button";
  closeBtn.setAttribute("aria-label", "Close");
  header.append(title, closeBtn);
  dialog.append(header);
  dialog.append(el("p", "vault-modal-sub", "The secret is sent to vaultd over the local daemon channel and never displayed again."));

  const errorBox = el("p", "vault-modal-error");
  errorBox.hidden = true;
  dialog.append(errorBox);

  const makeField = (
    labelText: string,
    inputType: string,
    placeholder: string,
    autocomplete: "off" | "new-password",
  ): HTMLInputElement => {
    const wrap = el("label", "vault-field");
    wrap.append(el("span", "vault-field-label", labelText));
    const input = document.createElement("input");
    input.className = "vault-input";
    input.type = inputType;
    input.placeholder = placeholder;
    input.autocomplete = autocomplete;
    wrap.append(input);
    dialog.append(wrap);
    return input;
  };

  const nameInput = makeField("Name", "text", "Stripe", "off");
  const scopeInput = makeField("Scope", "text", "charges.read", "off");
  const secretInput = makeField("Secret", "password", "Secret value", "new-password");
  const websiteInput = makeField("Website", "text", "cloudflare.com", "off");
  if (prefill !== undefined) {
    nameInput.value = prefill.alias;
    scopeInput.value = prefill.scope;
    websiteInput.value = prefill.website;
    secretInput.value = "";
  }

  const actions = el("div", "vault-modal-actions");
  const cancelBtn = el("button", "vault-btn vault-btn-ghost", "Cancel") as HTMLButtonElement;
  cancelBtn.type = "button";
  const saveBtn = el("button", "vault-btn vault-btn-primary", "Save") as HTMLButtonElement;
  saveBtn.type = "button";
  saveBtn.disabled = true;
  actions.append(cancelBtn, saveBtn);
  dialog.append(actions);

  const syncSave = (): void => {
    saveBtn.disabled = !isCredentialFormComplete(nameInput.value, scopeInput.value, secretInput.value);
  };
  for (const input of [nameInput, scopeInput, secretInput]) {
    input.addEventListener("input", syncSave);
  }

  const close = (): void => {
    closeCredentialModal();
  };
  closeBtn.addEventListener("click", close);
  cancelBtn.addEventListener("click", close);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) {
      close();
    }
  });
  credentialModalKeyHandler = (event: KeyboardEvent): void => {
    if (event.key === "Escape") {
      close();
    }
  };
  document.addEventListener("keydown", credentialModalKeyHandler);

  saveBtn.addEventListener("click", () => {
    void (async () => {
      saveBtn.disabled = true;
      cancelBtn.disabled = true;
      errorBox.hidden = true;
      try {
        await window.openvault.addCredential(
          nameInput.value.trim(),
          scopeInput.value.trim(),
          secretInput.value,
          websiteInput.value.trim(),
          prefill?.enrollmentId,
        );
        closeCredentialModal(false);
        notice = null;
        await refresh();
        // Focus only after the refresh re-render: render() replaces the
        // view children, so focusing before it would target a detached
        // + button and be lost.
        document.querySelector<HTMLElement>(".vault-add-btn")?.focus();
      } catch (err) {
        const message = err instanceof Error ? err.message : "Could not add credential";
        errorBox.textContent = message.includes("alias-exists")
          ? "A credential with this name already exists. Choose a different name."
          : message;
        errorBox.hidden = false;
        saveBtn.disabled = !isCredentialFormComplete(nameInput.value, scopeInput.value, secretInput.value);
        cancelBtn.disabled = false;
      }
    })();
  });

  overlay.append(dialog);
  document.body.append(overlay);
  credentialModal = overlay;
  syncSave();
  // From a deeplink the human only supplies the secret, so focus lands
  // there; a manual open still starts at Name.
  if (prefill !== undefined) {
    secretInput.focus();
  } else {
    nameInput.focus();
  }
}

function faviconNode(website: string, alias: string, large = false): HTMLElement {
  const url = faviconUrl(website);
  if (url === null) {
    return el("div", "vault-avatar", credentialInitial(alias));
  }
  const wrap = el("div", "vault-avatar");
  if (large) {
    wrap.style.width = "44px";
    wrap.style.height = "44px";
    wrap.style.borderRadius = "12px";
  }
  const img = document.createElement("img");
  img.src = url;
  img.alt = "";
  img.className = large ? "vault-favicon-lg" : "vault-favicon";
  img.addEventListener("error", () => {
    wrap.replaceChildren(document.createTextNode(credentialInitial(alias)));
  });
  wrap.append(img);
  return wrap;
}

let detailReturnFocus: HTMLElement | null = null;

function openCredentialDetail(card: { alias: string; website: string; scopes: readonly string[] }): void {
  if (credentialModal !== null) {
    return;
  }
  detailReturnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const overlay = el("div", "vault-modal-overlay");
  const dialog = el("div", "vault-modal");
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-labelledby", "vault-detail-title");

  const iconWrap = el("div", "vault-detail-icon");
  iconWrap.append(faviconNode(card.website, card.alias, true));
  dialog.append(iconWrap);

  const header = el("div", "vault-modal-header");
  const title = el("h2", "vault-modal-title", card.alias);
  title.id = "vault-detail-title";
  const closeBtn = el("button", "vault-modal-close", "\u00D7") as HTMLButtonElement;
  closeBtn.type = "button";
  closeBtn.setAttribute("aria-label", "Close");
  header.append(title, closeBtn);
  dialog.append(header);

  const errorBox = el("p", "vault-modal-error");
  errorBox.hidden = true;
  dialog.append(errorBox);

  const makeField = (
    labelText: string,
    inputType: string,
    placeholder: string,
    value: string,
    readOnly = false,
  ): HTMLInputElement => {
    const wrap = el("label", "vault-field");
    wrap.append(el("span", "vault-field-label", labelText));
    const input = document.createElement("input");
    input.className = "vault-input";
    input.type = inputType;
    input.placeholder = placeholder;
    input.value = value;
    input.autocomplete = "off";
    if (readOnly) {
      input.readOnly = true;
    }
    wrap.append(input);
    dialog.append(wrap);
    return input;
  };

  makeField("Name", "text", "", card.alias, true);
  dialog.append(el("p", "vault-note", "Name cannot be changed. Delete and re-add to rename."));
  const scopeInput = makeField("Scope", "text", "charges.read", card.scopes[0] ?? "");
  // Scope ceiling is the policies ceiling when available; fall back to first observed scope.
  const ceiling = policiesData.ceilings[card.alias];
  if (ceiling !== undefined) {
    scopeInput.value = ceiling;
  }
  const secretInput = makeField("Password", "password", "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022", "");
  const websiteInput = makeField("Website", "text", "cloudflare.com", card.website);

  const warning = el("p", "vault-warning", "Your agent can read it on its computer.");
  const contextRow = el("div", "vault-context-row");
  const renderContext = (): void => {
    contextRow.replaceChildren();
    const site = normalizeWebsite(websiteInput.value);
    warning.hidden = !shouldShowAgentComputerWarning(websiteInput.value);
    if (site !== "") {
      const chip = el("span", "chip vault-site-chip");
      const fav = faviconUrl(site);
      if (fav !== null) {
        const img = document.createElement("img");
        img.src = fav;
        img.alt = "";
        img.className = "vault-favicon";
        img.addEventListener("error", () => { img.remove(); });
        chip.append(img);
      }
      chip.append(document.createTextNode(site));
      contextRow.append(chip);
      contextRow.append(el("span", "chip vault-agent-chip", "Agent's computer"));
    }
  };
  renderContext();
  websiteInput.addEventListener("input", renderContext);
  dialog.append(contextRow);
  dialog.append(warning);

  const actions = el("div", "vault-modal-actions vault-modal-actions-split");
  const deleteBtn = el("button", "vault-btn vault-btn-danger", "Delete") as HTMLButtonElement;
  deleteBtn.type = "button";
  const right = el("div", "vault-modal-actions-right");
  const cancelBtn = el("button", "vault-btn vault-btn-ghost", "Cancel") as HTMLButtonElement;
  cancelBtn.type = "button";
  const saveBtn = el("button", "vault-btn vault-btn-primary", "Save") as HTMLButtonElement;
  saveBtn.type = "button";
  right.append(cancelBtn, saveBtn);
  actions.append(deleteBtn, right);
  dialog.append(actions);

  let confirmTimer: number | null = null;
  const close = (): void => {
    if (confirmTimer !== null) {
      window.clearTimeout(confirmTimer);
    }
    closeCredentialModal(false);
    const target =
      detailReturnFocus !== null && document.contains(detailReturnFocus)
        ? detailReturnFocus
        : document.querySelector<HTMLElement>(".vault-add-btn");
    target?.focus();
    detailReturnFocus = null;
  };
  closeBtn.addEventListener("click", close);
  cancelBtn.addEventListener("click", close);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) {
      close();
    }
  });
  credentialModalKeyHandler = (event: KeyboardEvent): void => {
    if (event.key === "Escape") {
      close();
    }
  };
  document.addEventListener("keydown", credentialModalKeyHandler);

  deleteBtn.addEventListener("click", () => {
    void (async () => {
      if (deleteBtn.dataset["confirm"] !== "true") {
        deleteBtn.dataset["confirm"] = "true";
        deleteBtn.textContent = "Confirm delete";
        deleteBtn.className = "vault-btn vault-btn-danger-confirm";
        confirmTimer = window.setTimeout(() => {
          deleteBtn.dataset["confirm"] = "";
          deleteBtn.textContent = "Delete";
          deleteBtn.className = "vault-btn vault-btn-danger";
        }, 3000);
        return;
      }
      if (confirmTimer !== null) {
        window.clearTimeout(confirmTimer);
      }
      deleteBtn.disabled = true;
      saveBtn.disabled = true;
      cancelBtn.disabled = true;
      errorBox.hidden = true;
      try {
        await window.openvault.deleteCredential(card.alias);
        closeCredentialModal(false);
        await refresh();
        document.querySelector<HTMLElement>(".vault-add-btn")?.focus();
      } catch (err) {
        errorBox.textContent = err instanceof Error ? err.message : "Could not delete credential";
        errorBox.hidden = false;
        deleteBtn.disabled = false;
        saveBtn.disabled = false;
        cancelBtn.disabled = false;
      }
    })();
  });

  saveBtn.addEventListener("click", () => {
    void (async () => {
      saveBtn.disabled = true;
      cancelBtn.disabled = true;
      deleteBtn.disabled = true;
      errorBox.hidden = true;
      try {
        await window.openvault.updateCredential(
          card.alias,
          buildEditPayload({ scope: scopeInput.value, website: websiteInput.value, secret: secretInput.value }),
        );
        closeCredentialModal(false);
        await refresh();
        const cardBtn = document.querySelector<HTMLElement>(`[data-alias="${CSS.escape(card.alias)}"]`);
        (cardBtn ?? document.querySelector<HTMLElement>(".vault-add-btn"))?.focus();
      } catch (err) {
        errorBox.textContent = err instanceof Error ? err.message : "Could not save credential";
        errorBox.hidden = false;
        saveBtn.disabled = false;
        cancelBtn.disabled = false;
        deleteBtn.disabled = false;
      }
    })();
  });

  overlay.append(dialog);
  document.body.append(overlay);
  credentialModal = overlay;
  scopeInput.focus();
}

function renderVault(view: HTMLElement): void {
  const panel = el("section", "vault-panel");
  const headerRow = el("div", "vault-section-header");
  headerRow.append(el("h1", "vault-title", "Agent credentials"));
  const addBtn = el("button", "vault-add-btn", "+") as HTMLButtonElement;
  addBtn.type = "button";
  addBtn.setAttribute("aria-label", "Add credential");
  addBtn.title = "Add credential";
  addBtn.addEventListener("click", () => {
    openCredentialModal();
  });
  headerRow.append(addBtn);
  panel.append(headerRow);
  panel.append(el("p", "vault-sub", "Aliases and scopes only \u2014 values are never displayed, copied, or sent to this window."));
  if (aliases.length === 0) {
    panel.append(el("p", "vault-empty", "No credentials saved"));
    view.append(panel);
    return;
  }
  const list = el("div", "vault-list");
  for (const card of deriveVaultCards(aliases, auditEvents, credentialMeta)) {
    const row = el("button", "vault-row vault-row-btn") as HTMLButtonElement;
    row.type = "button";
    row.dataset["alias"] = card.alias;
    row.setAttribute("aria-label", `Edit credential ${card.alias}`);
    row.append(faviconNode(card.website, card.alias));
    const main = el("div", "vault-row-main");
    main.append(el("div", "vault-alias", card.alias));
    const sub = el("div", "vault-row-sub");
    if (card.scopes.length === 0) {
      sub.append(el("span", "vault-muted", "no requests yet"));
    }
    for (const scope of card.scopes) {
      sub.append(el("span", "chip vault-scope-chip", scope));
    }
    if (card.website !== "") {
      sub.append(el("span", "vault-muted", card.website));
    }
    sub.append(el("span", "vault-muted", `Last used \u00B7 ${formatLastUsed(card.lastUsedTs, Date.now())}`));
    main.append(sub);
    row.append(main);
    row.addEventListener("click", () => {
      openCredentialDetail(card);
    });
    list.append(row);
  }
  panel.append(list);
  view.append(panel);
}

function renderAudit(view: HTMLElement): void {
  view.append(el("h1", "", "Audit"));
  view.append(
    el(
      "p",
      "sub",
      "One row per request. Expand a row to see the warden verification timeline: marshal explanation, recommended scope, latency and who decided.",
    ),
  );
  const filterWrap = el("div", "audit-filter-wrap");
  const filterLabel = el("label", "audit-filter-label", "Filter");
  filterLabel.setAttribute("for", "audit-filter");
  const filterInput = document.createElement("input");
  filterInput.id = "audit-filter";
  filterInput.className = "audit-filter";
  filterInput.type = "text";
  filterInput.placeholder = "Filter by agent, alias or outcome";
  filterInput.value = auditFilter;
  filterInput.setAttribute("aria-label", "Filter audit by agent, alias or outcome");
  filterWrap.append(filterLabel, filterInput);
  view.append(filterWrap);

  const list = el("div", "rows");
  view.append(list);

  const renderList = (): void => {
    list.replaceChildren();
    const groups = filterAuditGroups(groupAuditByRequest(auditEvents), auditFilter);
    if (auditEvents.length === 0) {
      list.append(el("div", "empty", "No audit events yet."));
      return;
    }
    if (groups.length === 0) {
      list.append(el("div", "empty", "No requests match this filter."));
      return;
    }
    for (const group of groups) {
      const verdict = wardenVerdict(group);
      const expanded = expandedAuditIds.has(group.requestId);
      const node = el("article", "row audit-row");
      const summary = el("div", "audit-summary");
      const allowedText = group.allowedScope ?? "—";
      const scopeText =
        group.requestedScope !== "" && group.requestedScope !== allowedText
          ? `${group.requestedScope} → ${allowedText}`
          : allowedText || group.requestedScope;
      // The legacy bucket mixes unrelated pre-requestId admin events, so
      // no single outcome/warden verdict describes it: label it honestly
      // and suppress both chips for that row.
      const chainText = group.isLegacy
        ? `Earlier activity · ${String(group.events.length)} ${group.events.length === 1 ? "event" : "events"}`
        : `${group.agentId} · ${group.alias} · ${scopeText}`;
      summary.append(el("div", "chain", chainText));
      if (!group.isLegacy) {
        const chips = el("div", "audit-chips");
        chips.append(el("span", `chip outcome-chip outcome-${verdict.outcome}`, verdict.outcomeLabel));
        const wardenClass =
          verdict.risk !== null ? `chip warden-chip risk-${verdict.risk}` : "chip warden-chip is-policy";
        chips.append(el("span", wardenClass, verdict.wardenLabel));
        if (verdict.escalated) {
          chips.append(el("span", "chip warden-chip is-escalated", "escalated"));
        }
        if (verdict.narrowed) {
          chips.append(el("span", "chip warden-chip is-narrowed", "narrowed"));
        }
        summary.append(chips);
      }
      node.append(summary);
      node.append(el("div", "when", group.lastTs));
      const toggle = el(
        "button",
        "action audit-toggle",
        group.isLegacy
          ? expanded
            ? "Hide details"
            : "Show details"
          : expanded
            ? "Hide verification"
            : "Show verification",
      ) as HTMLButtonElement;
      toggle.type = "button";
      toggle.setAttribute("aria-expanded", expanded ? "true" : "false");
      toggle.addEventListener("click", () => {
        if (expandedAuditIds.has(group.requestId)) {
          expandedAuditIds.delete(group.requestId);
        } else {
          expandedAuditIds.add(group.requestId);
        }
        renderList();
      });
      node.append(toggle);
      if (expanded) {
        const timeline = el("div", "audit-timeline");
        for (const event of group.events) {
          const step = el("div", "audit-step");
          const stepHead = el("div", "audit-step-head");
          stepHead.append(el("span", "audit-stage", stageLabel(event.stage)));
          stepHead.append(el("span", "when", event.ts));
          step.append(stepHead);
          step.append(el("div", "detail", event.detail));
          if (event.explanation !== undefined && event.explanation !== "") {
            step.append(el("div", "audit-explanation", event.explanation));
          }
          const meta: string[] = [];
          if (event.recommendedScope !== undefined && event.recommendedScope !== "") {
            meta.push(`recommended ${event.recommendedScope}`);
          }
          if (event.latencyMs !== undefined) {
            meta.push(`${String(event.latencyMs)}ms`);
          }
          if (event.decisionSource !== undefined) {
            meta.push(`source ${event.decisionSource}`);
          }
          if (event.modelId !== undefined && event.modelId !== "") {
            meta.push(`model ${event.modelId}`);
          }
          if (event.risk !== undefined) {
            meta.push(`risk ${event.risk}`);
          }
          if (meta.length > 0) {
            step.append(el("div", "when", meta.join(" · ")));
          }
          timeline.append(step);
        }
        node.append(timeline);
      }
      list.append(node);
    }
  };

  const rememberSelection = (): void => {
    auditFilterSelectionStart = filterInput.selectionStart;
    auditFilterSelectionEnd = filterInput.selectionEnd;
  };
  filterInput.addEventListener("input", () => {
    auditFilter = filterInput.value;
    rememberSelection();
    renderList();
  });
  filterInput.addEventListener("select", rememberSelection);
  filterInput.addEventListener("keyup", rememberSelection);
  filterInput.addEventListener("click", rememberSelection);
  filterInput.addEventListener("focus", () => {
    auditFilterWasFocused = true;
    rememberSelection();
  });
  filterInput.addEventListener("blur", () => {
    auditFilterWasFocused = false;
  });
  renderList();
  if (auditFilterWasFocused) {
    filterInput.focus();
    const start = Math.min(auditFilterSelectionStart ?? filterInput.value.length, filterInput.value.length);
    const end = Math.min(auditFilterSelectionEnd ?? start, filterInput.value.length);
    filterInput.setSelectionRange(start, end);
  }
}


function settingsSection(title: string, copy: string): HTMLElement {
  const section = el("section", "settings-section");
  section.append(el("h2", "settings-title", title));
  if (copy !== "") {
    section.append(el("p", "settings-copy", copy));
  }
  return section;
}

async function runSettingsAction(action: () => Promise<void>): Promise<void> {
  if (settingsBusy) return;
  settingsBusy = true;
  render();
  try {
    await action();
  } catch (err) {
    settingsMessage = { text: err instanceof Error ? err.message : "Settings action failed", ok: false };
  } finally {
    settingsBusy = false;
    render();
  }
}

function renderSettings(view: HTMLElement): void {
  view.append(el("h1", "", "Settings"));
  view.append(el("p", "sub", "Choose who judges capability requests. Deterministic policy stays the floor: the warden can narrow or escalate, never widen."));
  if (!wardenLoaded) {
    view.append(el("div", "empty", "Loading warden settings from vaultd\u2026"));
  }

  // 1. Provider
  const providerSection = settingsSection("Warden provider", "");
  const providerCopy: Record<WardenSettingsLike["provider"], string> = {
    none: "No model judges requests. Deterministic policy alone decides, and anything needing approval comes to you.",
    ollama: "Ollama runs on this device. Request metadata stays on-device.",
    "meta-api": "Meta API (cloud) sends request metadata \u2014 agent, alias, scope and reason, never secrets \u2014 off-device to Meta's API for judgement. Secrets never leave vaultd.",
  };
  for (const provider of WARDEN_PROVIDERS) {
    const label = el("label", "settings-radio");
    const radio = document.createElement("input");
    radio.type = "radio";
    radio.name = "warden-provider";
    radio.value = provider.id;
    radio.checked = wardenDraft.provider === provider.id;
    radio.addEventListener("change", () => {
      wardenDraft = { ...wardenDraft, provider: provider.id };
      wardenDirty = true;
      settingsMessage = null;
      render();
    });
    const text = el("span", "");
    text.append(el("span", "settings-radio-label", provider.label));
    text.append(el("span", "settings-radio-copy", providerCopy[provider.id]));
    label.append(radio, text);
    providerSection.append(label);
  }
  view.append(providerSection);

  // 2. Model
  const modelSection = settingsSection("Model", "");
  if (wardenDraft.provider === "none") {
    modelSection.append(el("p", "settings-copy", "No model \u2014 policy only. Choose Ollama or Meta API to enable a warden model."));
  } else {
    if (wardenDraft.provider === "ollama") {
      const selectLabel = el("label", "vault-field");
      selectLabel.append(el("span", "vault-field-label", "Ollama model"));
      const select = document.createElement("select");
      select.className = "vault-input";
      select.id = "warden-model-select";
      for (const option of OLLAMA_MODEL_OPTIONS) {
        const opt = document.createElement("option");
        opt.value = option.id;
        opt.textContent = option.label;
        select.append(opt);
      }
      if (!isKnownOllamaModel(wardenDraft.model)) {
        const custom = document.createElement("option");
        custom.value = wardenDraft.model;
        custom.textContent = `${wardenDraft.model} \u2014 Custom`;
        select.append(custom);
      }
      select.value = wardenDraft.model;
      select.addEventListener("change", () => {
        wardenDraft = { ...wardenDraft, model: select.value };
        wardenDirty = true;
        render();
      });
      selectLabel.append(select);
      modelSection.append(selectLabel);
    }
    const modelLabel = el("label", "vault-field");
    modelLabel.append(el("span", "vault-field-label", wardenDraft.provider === "meta-api" ? "Meta API model id" : "Model id (free text)"));
    const modelInput = document.createElement("input");
    modelInput.className = "vault-input";
    modelInput.id = "warden-model-input";
    modelInput.type = "text";
    modelInput.value = wardenDraft.model;
    modelInput.placeholder = wardenDraft.provider === "meta-api" ? "Meta API model id" : "llama3.2:3b";
    modelInput.autocomplete = "off";
    modelInput.addEventListener("input", () => {
      wardenDraft = { ...wardenDraft, model: modelInput.value };
      wardenDirty = true;
    });
    modelLabel.append(modelInput);
    modelSection.append(modelLabel);
    modelSection.append(el("p", "settings-copy", "Free-text model ids are allowed; the catalogue above is a shortcut, not a limit."));
    if (wardenDraft.provider === "meta-api") {
      const baseLabel = el("label", "vault-field");
      baseLabel.append(el("span", "vault-field-label", "Meta API base URL"));
      const baseInput = document.createElement("input");
      baseInput.className = "vault-input";
      baseInput.id = "warden-base-url-input";
      baseInput.type = "text";
      baseInput.value = wardenDraft.metaApiBaseUrl;
      baseInput.autocomplete = "off";
      baseInput.addEventListener("input", () => {
        wardenDraft = { ...wardenDraft, metaApiBaseUrl: baseInput.value };
        wardenDirty = true;
      });
      baseLabel.append(baseInput);
      modelSection.append(baseLabel);
    }
  }
  view.append(modelSection);

  // 3. Effort
  const effortSection = settingsSection("Effort", "");
  for (const option of EFFORT_OPTIONS) {
    const label = el("label", "settings-radio");
    const radio = document.createElement("input");
    radio.type = "radio";
    radio.name = "warden-effort";
    radio.value = option.id;
    radio.checked = wardenDraft.effort === option.id;
    radio.addEventListener("change", () => {
      wardenDraft = { ...wardenDraft, effort: option.id };
      wardenDirty = true;
      settingsMessage = null;
      render();
    });
    const text = el("span", "");
    text.append(el("span", "settings-radio-label", option.label));
    text.append(el("span", "settings-radio-copy", option.description));
    label.append(radio, text);
    effortSection.append(label);
  }
  const saveBtn = el("button", "action btn-approve", "Save settings") as HTMLButtonElement;
  saveBtn.type = "button";
  saveBtn.disabled = settingsBusy || !isWardenFormComplete(wardenDraft);
  saveBtn.addEventListener("click", () => {
    void runSettingsAction(async () => {
      const raw = await window.openvault.updateWardenSettings(buildWardenPatch(wardenDraft));
      const projected = projectWardenSettings(raw);
      if (projected !== null) {
        wardenDraft = projected;
      }
      wardenDirty = false;
      wardenLoaded = true;
      updateMarshalLine();
      settingsMessage = { text: "Warden settings saved. They apply on the next request \u2014 no daemon restart needed.", ok: true };
    });
  });
  effortSection.append(saveBtn);
  view.append(effortSection);

  // 4. Meta API key
  const keySection = settingsSection("Meta API key", "The key is stored encrypted by vaultd and decrypted only inside the daemon at call time. It is never shown again after saving.");
  const statusLine = el("p", "settings-status");
  statusLine.id = "warden-key-status";
  statusLine.textContent = `Meta API key: ${wardenKeyStatusText(wardenKeyStatusState)}`;
  keySection.append(statusLine);
  const keyLabel = el("label", "vault-field");
  keyLabel.append(el("span", "vault-field-label", "Meta API key"));
  const keyInput = document.createElement("input");
  keyInput.className = "vault-input";
  keyInput.id = "warden-key-input";
  keyInput.type = "password";
  keyInput.placeholder = "Paste Meta API key";
  keyInput.autocomplete = "new-password";
  keyInput.value = settingsKeyDraft;
  keyInput.addEventListener("input", () => {
    settingsKeyDraft = keyInput.value;
    const btn = document.querySelector<HTMLButtonElement>("#warden-save-key");
    if (btn !== null) btn.disabled = settingsBusy || keyInput.value.trim() === "";
  });
  keyLabel.append(keyInput);
  keySection.append(keyLabel);
  const keyBtns = el("div", "btns");
  const saveKeyBtn = el("button", "action btn-approve", "Save key") as HTMLButtonElement;
  saveKeyBtn.type = "button";
  saveKeyBtn.id = "warden-save-key";
  saveKeyBtn.disabled = settingsBusy || settingsKeyDraft.trim() === "";
  saveKeyBtn.addEventListener("click", () => {
    void runSettingsAction(async () => {
      const key = settingsKeyDraft;
      const raw = await window.openvault.setWardenKey(key);
      const projected = projectWardenKeyStatus(raw);
      if (projected !== null) wardenKeyStatusState = projected;
      // Clear the field and never repopulate it from the daemon response.
      settingsKeyDraft = "";
      const live = document.querySelector<HTMLInputElement>("#warden-key-input");
      if (live !== null) live.value = "";
      settingsMessage = { text: "Meta API key saved. The field has been cleared; the key is never shown again.", ok: true };
    });
  });
  const testBtn = el("button", "action btn-always", "Test connection") as HTMLButtonElement;
  testBtn.type = "button";
  testBtn.disabled = settingsBusy;
  testBtn.addEventListener("click", () => {
    void runSettingsAction(async () => {
      const raw = await window.openvault.testWarden();
      const projected = projectWardenTestResult(raw);
      if (projected === null) {
        settingsMessage = { text: "Warden test failed \u2014 vaultd returned an unexpected response.", ok: false };
        return;
      }
      const result = wardenTestMessage(projected);
      settingsMessage = { text: result.message, ok: result.ok };
    });
  });
  const deleteKeyBtn = el("button", "action btn-deny", "Delete key") as HTMLButtonElement;
  deleteKeyBtn.type = "button";
  deleteKeyBtn.disabled = settingsBusy || !wardenKeyStatusState.configured;
  deleteKeyBtn.addEventListener("click", () => {
    void runSettingsAction(async () => {
      const raw = await window.openvault.deleteWardenKey();
      const projected = projectWardenKeyStatus(raw);
      wardenKeyStatusState = projected ?? { configured: false, last4: null };
      settingsKeyDraft = "";
      settingsMessage = { text: "Meta API key deleted.", ok: true };
    });
  });
  keyBtns.append(saveKeyBtn, testBtn, deleteKeyBtn);
  keySection.append(keyBtns);
  keySection.append(el("p", "settings-copy", "Test connection runs one metadata-only warden self-check through vaultd using the saved provider and model (save settings changes first to test them). It creates no grants and writes no audit entries."));
  view.append(keySection);

  if (settingsMessage !== null) {
    const msg = el("p", settingsMessage.ok ? "settings-message is-ok" : "settings-message is-error", settingsMessage.text);
    view.append(msg);
  }

  // 5. Daemon (read-only)
  const daemonSection = settingsSection("Daemon", "");
  const rows: readonly (readonly [string, string])[] = [
    ["Daemon URL", DAEMON_URL_DISPLAY],
    ["Vault path", VAULT_PATH_DISPLAY],
    ["Version", `OpenVault ${APP_VERSION_DISPLAY}`],
  ];
  for (const [label, value] of rows) {
    const row = el("div", "settings-row");
    row.append(el("span", "settings-row-label", label));
    row.append(el("span", "mono settings-row-value", value));
    daemonSection.append(row);
  }
  daemonSection.append(el("p", "settings-copy", "Read-only. Warden settings apply on the next request, so no restart is needed after saving. If vaultd is unreachable, restart it from the terminal where it was launched, then reopen this page."));
  view.append(daemonSection);

  // 6. Security defaults (read-only summary)
  const policySection = settingsSection("Security defaults", "");
  const ceilingCount = Object.keys(policiesData.ceilings).length;
  policySection.append(el("p", "settings-copy", `Deterministic policy is the floor and never moves: ${String(ceilingCount)} alias ceiling${ceilingCount === 1 ? "" : "s"} on record, ${String(policiesData.standingApprovals.length)} standing approval${policiesData.standingApprovals.length === 1 ? "" : "s"} in force. The warden may narrow or escalate a request, never widen it. Editing policy stays on the Policies view.`));
  const policiesBtn = el("button", "action settings-link", "Open Policies") as HTMLButtonElement;
  policiesBtn.type = "button";
  policiesBtn.addEventListener("click", () => {
    currentView = "policies";
    document.querySelectorAll(".nav-btn").forEach((b) => {
      b.classList.toggle("is-active", (b as HTMLElement).dataset["view"] === "policies");
    });
    render();
  });
  policySection.append(policiesBtn);
  view.append(policySection);
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
  const note = el("p", "fine", `Stages: ${(["requested", "marshal", "policy", "approved", "denied", "executed", "expired", "revoked", "credential-added", "credential-deleted"] as const).map(stageLabel).join(" · ")}`);
  view.append(note);
}

function render(): void {
  const view = mustElement("#view");
  // Capture the audit filter caret before the old input is discarded, so
  // a poll re-render can restore focus and selection exactly.
  const oldFilter = document.querySelector<HTMLInputElement>("#audit-filter");
  if (oldFilter !== null && document.activeElement === oldFilter) {
    auditFilterWasFocused = true;
    auditFilterSelectionStart = oldFilter.selectionStart;
    auditFilterSelectionEnd = oldFilter.selectionEnd;
  }
  if (currentView === "settings") {
    const liveKey = document.querySelector<HTMLInputElement>("#warden-key-input");
    if (liveKey !== null) settingsKeyDraft = liveKey.value;
  }
  view.replaceChildren();
  showBanner(notice);
  if (currentView === "approval") {
    renderApproval(view);
  } else if (currentView === "vault") {
    renderVault(view);
  } else if (currentView === "audit") {
    renderAudit(view);
  } else if (currentView === "settings") {
    renderSettings(view);
  } else {
    renderPolicies(view);
  }
}

async function refresh(): Promise<void> {
  try {
    const [pendingRaw, aliasesRaw, auditRaw, policiesRaw, wardenRaw, wardenKeyRaw] = await Promise.all([
      window.openvault.pending(),
      window.openvault.aliases(),
      window.openvault.audit(),
      window.openvault.policies(),
      window.openvault.getWardenSettings().catch(() => null),
      window.openvault.wardenKeyStatus().catch(() => null),
    ]);
    approvals = projectPendingResponse(pendingRaw);
    aliases = projectAliasesResponse(aliasesRaw);
    credentialMeta = projectCredentialsResponse(aliasesRaw);
    auditEvents = projectAuditResponse(auditRaw);
    policiesData = projectPoliciesResponse(policiesRaw);
    const projectedWarden = projectWardenSettings(wardenRaw);
    if (projectedWarden !== null) {
      if (!wardenDirty) {
        wardenDraft = projectedWarden;
      }
      wardenLoaded = true;
    }
    const projectedKey = projectWardenKeyStatus(wardenKeyRaw);
    if (projectedKey !== null) {
      wardenKeyStatusState = projectedKey;
    }
    setDaemonStatus(true);
    updateMarshalLine();
  } catch (err) {
    setDaemonStatus(false);
    showBanner(err instanceof Error ? err.message : "Could not reach vaultd");
  }
  render();
}

// The most recent refresh, so the deeplink flow can wait out a render that
// is already in flight instead of racing it (see runDeeplinkAddFlow).
let inFlightRefresh: Promise<void> | null = null;

function refreshTracked(): Promise<void> {
  const pending = refresh();
  inFlightRefresh = pending;
  const clear = (): void => {
    if (inFlightRefresh === pending) {
      inFlightRefresh = null;
    }
  };
  void pending.then(clear, clear);
  return pending;
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
  window.openvault.onDeeplinkAdd((params) => {
    // Sequenced by runDeeplinkAddFlow: the prefilled Add modal opens only
    // after the Vault render (and any refresh already in flight) has fully
    // completed, replacing any modal that is open. A failure surfaces in
    // the banner instead of silently leaving no modal.
    void runDeeplinkAddFlow(params, {
      switchToVault: () => {
        currentView = "vault";
        document.querySelectorAll<HTMLElement>(".nav-btn").forEach((b) => {
          b.classList.toggle("is-active", b.dataset["view"] === "vault");
        });
      },
      renderVault: async () => {
        if (inFlightRefresh !== null) {
          await inFlightRefresh;
        }
        render();
      },
      closeModalIfOpen: () => {
        if (credentialModal !== null) {
          closeCredentialModal(false);
        }
      },
      openAddModal: (prefill) => {
        openCredentialModal(prefill);
      },
    }).catch((err: unknown) => {
      showBanner(err instanceof Error ? err.message : "Could not open the add-credential dialog");
    });
  });
  document.querySelectorAll<HTMLButtonElement>(".nav-btn").forEach((button) => {
    button.addEventListener("click", () => {
      const next = button.dataset["view"];
      if (next === "approval" || next === "vault" || next === "audit" || next === "policies" || next === "settings") {
        currentView = next;
        notice = null;
        document.querySelectorAll(".nav-btn").forEach((b) => {
          b.classList.toggle("is-active", b === button);
        });
        render();
      }
    });
  });
  void refreshTracked();
  window.setInterval(() => {
    void refreshTracked();
  }, POLL_MS);
  window.setInterval(tickExpiryLabels, 1_000);
}

start();
