import {
  filterAuditGroups,
  paginate,
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
  META_API_MODEL_OPTIONS,
  isKnownMetaApiModel,
  isWardenFormComplete,
  projectWardenKeyStatus,
  projectWardenSettings,
  wardenKeyStatusText,
  projectWardenTestResult,
  wardenTestMessage,
  projectSecurityPosture,
  DEFAULT_LOCAL_AUTH_STATUS,
  projectLocalAuthStatus,
  shouldPromptPinSetupOnEnable,
  shouldLockOnLaunch,
  isBiometricsActive,
  localAuthFactorLabel,
  shouldRequireAuthForApproval,
  shouldRequireAuthForSettings,
  isAutoLockDue,
  canLockSessionNow,
  parseDotEnvWithInference,
  type DotEnvImportItem,
} from "./model.js";
import type {
  AgentSecuritySettingsLike,
  RegisteredAgent,
  AuditEventLike,
  CredentialMeta,
  DeeplinkAddParams,
  PendingApproval,
  PoliciesData,
  SecurityPostureReportLike,
  LocalAuthStatusLike,
  BuiltinAiProgressLike,
  BuiltinAiStatusLike,
  UpdaterStatusLike,
  WardenKeyStatusLike,
  WardenSettingsLike,
} from "./types.js";

// Renderer bootstrap: plain TypeScript over the preload bridge. Every
// daemon payload is projected through model.ts whitelists before it is
// rendered, and all daemon text reaches the page via textContent only.

type ViewName = "approval" | "vault" | "audit" | "policies" | "posture" | "settings";

const POLL_MS = 4_000;

let currentView: ViewName = "vault";
let approvalDialogDismissed = false;
let approvalDialogKey = "";
let approvals: PendingApproval[] = [];
let aliases: string[] = [];
let credentialMeta: CredentialMeta[] = [];
let auditEvents: AuditEventLike[] = [];
let policiesData: PoliciesData = { ceilings: {}, standingApprovals: [] };
let agentSecuritySettings: AgentSecuritySettingsLike = { strictMode: false, verifyCallerProcess: false };
let securityPosture: SecurityPostureReportLike | null = null;
let selectedGrantId: string | null = null;
let knownGrantIds = new Set<string>();
let auditFilter = "";
let auditFilterWasFocused = false;
let auditFilterSelectionStart: number | null = null;
let auditFilterSelectionEnd: number | null = null;
const expandedAuditIds = new Set<string>();
let uiMode: "verbose" | "simple" = localStorage.getItem("metavault_ui_mode") === "simple" ? "simple" : "verbose";
let auditOutcomeFilter = "all";
let auditAgentFilter = "all";
let auditAliasFilter = "all";
let auditDateRangeFilter = "all";
let auditPage = 1;
let auditPageSize = 10;
let activeAgentTab: "claude" | "cursor" | "vscode" | "codex" | "opencode" | "skill" = "claude";
let localAuthStatus: LocalAuthStatusLike = { ...DEFAULT_LOCAL_AUTH_STATUS };
let vaultLocked = false;
let initialAuthChecked = false;
let lastUserActivityTs = Date.now();

function recordActivity(): void {
  lastUserActivityTs = Date.now();
}
window.addEventListener("pointerdown", recordActivity);
window.addEventListener("keydown", recordActivity);
let busy = false;
let notice: string | null = null;
let wardenDraft: WardenSettingsLike = { ...DEFAULT_WARDEN_SETTINGS };
let wardenKeyStatusState: WardenKeyStatusLike = { configured: false, last4: null };
let wardenLoaded = false;
let wardenDirty = false;
let settingsKeyDraft = "";
let settingsBusy = false;
let settingsMessage: { readonly text: string; readonly ok: boolean } | null = null;
let localAuthNotice: { readonly text: string; readonly ok: boolean } | null = null;
let updaterStatus: UpdaterStatusLike = { status: "idle" };
let builtinAiStatus: BuiltinAiStatusLike | null = null;
let builtinAiProgress: BuiltinAiProgressLike | null = null;
type SettingsTab = "general" | "warden" | "daemon" | "security";
let settingsOpen = false;
let settingsTab: SettingsTab = "general";
let settingsFocusOnOpen = false;

const SETTINGS_TAB_LABEL: Record<SettingsTab, string> = {
  general: "General",
  warden: "Warden",
  daemon: "Daemon",
  security: "Security",
};

const VIEW_TITLE: Record<Exclude<ViewName, "settings">, string> = {
  approval: "Approval",
  vault: "Vault",
  audit: "Audit",
  policies: "Policies",
  posture: "Posture",
};

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

function cell(text: string): HTMLTableCellElement {
  const node = el("td", "", text) as HTMLTableCellElement;
  node.title = text;
  return node;
}

function pagerButton(label: string, direction: "prev" | "next"): HTMLButtonElement {
  const button = el("button", "pagination-btn") as HTMLButtonElement;
  button.type = "button";
  const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  icon.setAttribute("viewBox", "0 0 24 24");
  icon.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", direction === "prev" ? "M14.5 6.5 9 12l5.5 5.5" : "M9.5 6.5 15 12l-5.5 5.5");
  path.setAttribute("fill", "none");
  path.setAttribute("stroke", "currentColor");
  path.setAttribute("stroke-width", "1.6");
  path.setAttribute("stroke-linecap", "round");
  path.setAttribute("stroke-linejoin", "round");
  icon.append(path);
  const text = el("span", "", label);
  if (direction === "prev") button.append(icon, text);
  else button.append(text, icon);
  return button;
}

function lockSvg(): SVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  rect.setAttribute("x", "5");
  rect.setAttribute("y", "10");
  rect.setAttribute("width", "14");
  rect.setAttribute("height", "10");
  rect.setAttribute("rx", "2");
  rect.setAttribute("fill", "none");
  rect.setAttribute("stroke", "currentColor");
  rect.setAttribute("stroke-width", "1.6");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", "M8 10V7.5a4 4 0 0 1 8 0V10");
  path.setAttribute("fill", "none");
  path.setAttribute("stroke", "currentColor");
  path.setAttribute("stroke-width", "1.6");
  path.setAttribute("stroke-linecap", "round");
  svg.append(rect, path);
  return svg;
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
  document.querySelector(".sidebar-mark")?.classList.toggle("is-ok", ok);
}

function updateMarshalLine(): void {
  if (wardenLoaded) {
    const line = mustElement("#marshal-line");
    if (wardenDraft.provider === "none") {
      line.textContent = "Marshal \u00B7 Off \u00B7 Policy only";
    } else if (wardenDraft.provider === "meta-api") {
      line.textContent = `Marshal \u00B7 ${wardenDraft.model} \u00B7 Meta API (cloud)`;
    } else if (wardenDraft.provider === "bft") {
      line.textContent = "Marshal · Meta Family of AIs · Dual-Warden BFT (Cloud + Local)";
    } else if (wardenDraft.provider === "builtin") {
      line.textContent = `Marshal \u00B7 ${wardenDraft.model} \u00B7 Built-in (WebGPU)`;
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
    empty.append(el("p", "", "When an agent asks for access, the request opens over whichever page you are on. If this window is closed, requests wait in the tray queue and in vaultd."));
    view.append(empty);
    return;
  }
  view.append(buildApprovalCard(hero));

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

function buildApprovalCard(hero: PendingApproval): HTMLElement {
  const card = el("section", "hero");
  if (!hero.verified) {
    const warnBox = el("div", "alert is-warn");
    warnBox.style.marginBottom = "0.75rem";
    warnBox.textContent = "⚠️ Unverified Agent: This request has no registered agent token. The identity name below was self-reported by the calling process and may be spoofed.";
    card.append(warnBox);
  }
  const want = el("p", "want");
  want.append(document.createTextNode(`${hero.agentId} `));
  const badge = el(
    "span",
    hero.verified ? "status-badge is-ok" : "status-badge is-warn",
    hero.verified ? "Verified" : "⚠️ Unverified",
  );
    badge.style.marginRight = "0.4rem";
  want.append(badge);
  if (hero.clientProcess) {
    const procBadge = el("span", "status-badge is-ok", `Process: ${hero.clientProcess}${hero.clientPid ? ` (${String(hero.clientPid)})` : ""}`);
    procBadge.style.marginRight = "0.4rem";
    want.append(procBadge);
  }
  want.append(document.createTextNode(`in ${hero.ide} wants `));
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
    const executeApproval = () => {
      void runAction(() => window.metavault.approve(hero.grantId), "Approved — the grant executed inside vaultd and expired.");
    };
    if (shouldRequireAuthForApproval(localAuthStatus, hero.allowedScope, hero.risk)) {
      void confirmLocalPresence("Authenticate to approve capability", executeApproval);
    } else {
      executeApproval();
    }
  });
  const denyBtn = el("button", "action btn-deny", "Deny") as HTMLButtonElement;
  denyBtn.type = "button";
  denyBtn.disabled = busy;
  denyBtn.addEventListener("click", () => {
    void runAction(() => window.metavault.deny(hero.grantId), "Denied — the agent was told no, with the allowed ceiling.");
  });
  const blockBtn = el("button", "action btn-deny", "Block agent") as HTMLButtonElement;
  blockBtn.type = "button";
  blockBtn.disabled = busy;
  blockBtn.title = `Block ${hero.agentId} and cancel all its pending requests`;
  blockBtn.addEventListener("click", () => {
    void runAction(
      () => window.metavault.revoke(hero.agentId),
      `Blocked ${hero.agentId} — pending grants cancelled, all future requests denied.`,
    );
  });
  buttons.append(approveBtn, denyBtn, blockBtn);
  // Always allow is offered only for read-only low-risk grants; the daemon
  // re-checks the same rule before creating a standing approval.
  if (canAlwaysAllow(hero)) {
    const alwaysBtn = el("button", "action btn-always", "Always allow") as HTMLButtonElement;
    alwaysBtn.type = "button";
    alwaysBtn.disabled = busy;
    alwaysBtn.addEventListener("click", () => {
      void runAction(
        () => window.metavault.approveAlways(hero.grantId),
        `Standing approval saved for ${hero.agentId} · ${hero.allowedScope}. Read-only low-risk only; writes still ask every time.`,
      );
    });
    buttons.append(alwaysBtn);
  }
  card.append(buttons);
  return card;
}

function dismissApprovalDialog(): void {
  approvalDialogDismissed = true;
  approvalDialogKey = "";
  document.querySelector("#approval-dialog")?.remove();
}

function paintApprovalDialog(): void {
  const existing = document.querySelector("#approval-dialog");
  const hero = vaultLocked || approvalDialogDismissed || currentView === "approval" ? null : selectedApproval();
  if (hero === null) {
    existing?.remove();
    approvalDialogKey = "";
    return;
  }
  const key = `${hero.grantId}|${String(approvals.length)}|${busy ? "1" : "0"}`;
  if (existing !== null && approvalDialogKey === key) return;
  const previousGrant = approvalDialogKey.split("|")[0] ?? "";
  approvalDialogKey = key;
  existing?.remove();
  const overlay = el("div", "approval-overlay");
  overlay.id = "approval-dialog";
  const dialog = el("div", "approval-dialog");
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-labelledby", "approval-dialog-title");
  const head = el("div", "approval-dialog-head");
  const title = el("h2", "", "Approval needed");
  title.id = "approval-dialog-title";
  const closeBtn = el("button", "icon-btn") as HTMLButtonElement;
  closeBtn.type = "button";
  closeBtn.setAttribute("aria-label", "Close");
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", "M7 7l10 10M17 7 7 17");
  path.setAttribute("fill", "none");
  path.setAttribute("stroke", "currentColor");
  path.setAttribute("stroke-width", "1.6");
  path.setAttribute("stroke-linecap", "round");
  svg.append(path);
  closeBtn.append(svg);
  closeBtn.addEventListener("click", dismissApprovalDialog);
  head.append(title, closeBtn);
  dialog.append(head);
  const waiting = approvals.length;
  dialog.append(el("p", "approval-dialog-count", waiting === 1 ? "1 request needs a decision" : `${String(waiting)} requests need a decision`));
  dialog.append(buildApprovalCard(hero));
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) dismissApprovalDialog();
  });
  overlay.append(dialog);
  document.body.append(overlay);
  if (previousGrant !== hero.grantId) {
    dialog.querySelector<HTMLButtonElement>(".btn-approve")?.focus();
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
  const secretInput = makeField("Value", "password", "Credential value", "new-password");
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
        await window.metavault.addCredential(
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
  const secretInput = makeField("Value", "password", "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022", "");
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
        await window.metavault.deleteCredential(card.alias);
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
        await window.metavault.updateCredential(
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


function promptVerifyPin(title: string, onVerified: () => void): void {
  if (credentialModal !== null) return;
  const overlay = el("div", "vault-modal-overlay");
  const dialog = el("div", "vault-modal");
  dialog.style.maxWidth = "400px";

  const header = el("div", "vault-modal-header");
  header.append(el("h2", "vault-modal-title", title));
  const closeBtn = el("button", "vault-modal-close", "\u00D7") as HTMLButtonElement;
  header.append(closeBtn);
  dialog.append(header);

  const sub = el("p", "vault-modal-sub", "Local authentication required. Enter your vault PIN to proceed.");
  dialog.append(sub);

  const errorBox = el("p", "vault-modal-error");
  errorBox.hidden = true;
  dialog.append(errorBox);

  const wrap = el("label", "vault-field");
  wrap.append(el("span", "vault-field-label", "PIN"));
  const input = document.createElement("input");
  input.className = "vault-input";
  input.type = "password";
  input.placeholder = "Enter PIN";
  input.autocomplete = "current-password";
  wrap.append(input);
  dialog.append(wrap);

  const actions = el("div", "vault-modal-actions");
  const cancelBtn = el("button", "vault-btn vault-btn-ghost", "Cancel") as HTMLButtonElement;
  const confirmBtn = el("button", "vault-btn vault-btn-primary", "Confirm") as HTMLButtonElement;
  if (isBiometricsActive(localAuthStatus)) {
    const bioBtn = el("button", "vault-btn vault-btn-primary", "Windows Hello") as HTMLButtonElement;
    bioBtn.style.marginRight = "auto";
    bioBtn.addEventListener("click", () => {
      void (async () => {
        bioBtn.disabled = true;
        const res = await window.metavault.verifyWindowsHello("unlock");
        if (res.ok) {
          close();
          onVerified();
          return;
        }
        errorBox.textContent = "Windows Hello was not confirmed.";
        errorBox.hidden = false;
        bioBtn.disabled = false;
      })();
    });
    actions.append(bioBtn);
  }
  actions.append(cancelBtn, confirmBtn);
  dialog.append(actions);

  const close = () => { closeCredentialModal(); };
  closeBtn.addEventListener("click", close);
  cancelBtn.addEventListener("click", close);

  const submit = async () => {
    const pin = input.value.trim();
    if (!pin) return;
    confirmBtn.disabled = true;
    try {
      const res = (await window.metavault.verifyLocalPin(pin)) as { ok?: boolean } | null;
      if (res?.ok) {
        close();
        onVerified();
      } else {
        errorBox.textContent = "Incorrect PIN. Verification failed.";
        errorBox.hidden = false;
        confirmBtn.disabled = false;
        input.value = "";
        input.focus();
      }
    } catch {
      errorBox.textContent = "Could not verify PIN.";
      errorBox.hidden = false;
      confirmBtn.disabled = false;
    }
  };

  confirmBtn.addEventListener("click", () => { void submit(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") void submit();
  });

  overlay.append(dialog);
  document.body.append(overlay);
  credentialModal = overlay;
  input.focus();
}

async function confirmLocalPresence(title: string, onVerified: () => void): Promise<void> {
  if (isBiometricsActive(localAuthStatus)) {
    const result = await window.metavault.verifyWindowsHello("unlock");
    if (result.ok) {
      onVerified();
      return;
    }
    if (result.reason === "canceled" || !localAuthStatus.configured) {
      notice = "Windows Hello was not confirmed.";
      render();
      return;
    }
  }
  promptVerifyPin(title, onVerified);
}

async function tryEnableWindowsHello(): Promise<"on" | "unavailable" | "canceled"> {
  const availability = await window.metavault.windowsHelloAvailability();
  if (!availability.available) {
    localAuthNotice = {
      text: "Windows Hello is not set up on this PC. Add a Windows Hello PIN in Windows Settings, or set an app PIN below.",
      ok: false,
    };
    render();
    return "unavailable";
  }
  const verified = await window.metavault.verifyWindowsHello("setup");
  if (!verified.ok) {
    localAuthNotice = { text: "Windows Hello was not confirmed.", ok: false };
    render();
    return verified.reason === "canceled" ? "canceled" : "unavailable";
  }
  await runSettingsAction(async () => {
    const raw = await window.metavault.updateLocalAuthSettings({ enabled: true, biometricEnabled: true });
    const projected = projectLocalAuthStatus(raw);
    if (projected !== null) localAuthStatus = projected;
    localAuthNotice = { text: "Windows Hello is on. MetaVault never sees that PIN.", ok: true };
  });
  return localAuthStatus.biometricEnabled ? "on" : "unavailable";
}

function openPinModal(onSuccess?: () => void): void {
  if (credentialModal !== null) return;
  const overlay = el("div", "vault-modal-overlay");
  const dialog = el("div", "vault-modal");
  dialog.style.maxWidth = "420px";

  const header = el("div", "vault-modal-header");
  header.append(el("h2", "vault-modal-title", localAuthStatus.configured ? "Change local PIN" : "Set local PIN"));
  const closeBtn = el("button", "vault-modal-close", "\u00D7") as HTMLButtonElement;
  header.append(closeBtn);
  dialog.append(header);

  const sub = el("p", "vault-modal-sub", "App PIN fallback, 4-8 characters. Windows Hello is the lock when it is on. MetaVault stores a hash of this PIN, never the Windows Hello PIN.");
  dialog.append(sub);

  const errorBox = el("p", "vault-modal-error");
  errorBox.hidden = true;
  dialog.append(errorBox);

  let curInput: HTMLInputElement | null = null;
  if (localAuthStatus.configured) {
    const curWrap = el("label", "vault-field");
    curWrap.append(el("span", "vault-field-label", "Current PIN"));
    curInput = document.createElement("input");
    curInput.className = "vault-input";
    curInput.type = "password";
    curInput.placeholder = "Enter current PIN";
    curWrap.append(curInput);
    dialog.append(curWrap);
  }

  const newWrap = el("label", "vault-field");
  newWrap.append(el("span", "vault-field-label", "New PIN"));
  const newInput = document.createElement("input");
  newInput.className = "vault-input";
  newInput.type = "password";
  newInput.placeholder = "Enter new PIN (min 4 chars)";
  newWrap.append(newInput);
  dialog.append(newWrap);

  const confirmWrap = el("label", "vault-field");
  confirmWrap.append(el("span", "vault-field-label", "Confirm New PIN"));
  const confirmInput = document.createElement("input");
  confirmInput.className = "vault-input";
  confirmInput.type = "password";
  confirmInput.placeholder = "Re-enter new PIN";
  confirmWrap.append(confirmInput);
  dialog.append(confirmWrap);

  const actions = el("div", "vault-modal-actions");
  const cancelBtn = el("button", "vault-btn vault-btn-ghost", "Cancel") as HTMLButtonElement;
  const saveBtn = el("button", "vault-btn vault-btn-primary", "Save PIN") as HTMLButtonElement;
  actions.append(cancelBtn, saveBtn);
  dialog.append(actions);

  const close = () => { closeCredentialModal(); };
  closeBtn.addEventListener("click", close);
  cancelBtn.addEventListener("click", close);

  const submit = async () => {
    const newPin = newInput.value.trim();
    const conf = confirmInput.value.trim();
    if (newPin.length < 4) {
      errorBox.textContent = "New PIN must be at least 4 characters.";
      errorBox.hidden = false;
      return;
    }
    if (newPin !== conf) {
      errorBox.textContent = "New PINs do not match.";
      errorBox.hidden = false;
      return;
    }
    saveBtn.disabled = true;
    try {
      const res = (await window.metavault.setLocalPin(newPin, curInput?.value.trim())) as { ok?: boolean } | null;
      if (res?.ok) {
        close();
        onSuccess?.();
        showBanner("Local PIN updated successfully.");
      } else {
        errorBox.textContent = "Could not update PIN. Verify your current PIN.";
        errorBox.hidden = false;
        saveBtn.disabled = false;
      }
    } catch {
      errorBox.textContent = "Invalid current PIN or server error.";
      errorBox.hidden = false;
      saveBtn.disabled = false;
    }
  };

  saveBtn.addEventListener("click", () => { void submit(); });
  overlay.append(dialog);
  document.body.append(overlay);
  credentialModal = overlay;
  (curInput ?? newInput).focus();
}

function openDotEnvModal(): void {
  if (credentialModal !== null) {
    return;
  }
  const overlay = el("div", "vault-modal-overlay");
  const dialog = el("div", "vault-modal");
  dialog.style.maxWidth = "660px";
  dialog.style.width = "90%";
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");

  const header = el("div", "vault-modal-header");
  const title = el("h2", "vault-modal-title", "Import .env file");
  const closeBtn = el("button", "vault-modal-close", "\u00D7") as HTMLButtonElement;
  closeBtn.type = "button";
  closeBtn.setAttribute("aria-label", "Close");
  header.append(title, closeBtn);
  dialog.append(header);

  const sub = el("p", "vault-modal-sub", "Select or paste a .env file. MetaVault parses your environment keys, infers least-privilege scope ceilings, and encrypts secrets directly into vault storage.");
  dialog.append(sub);

  const errorBox = el("p", "vault-modal-error");
  errorBox.hidden = true;
  dialog.append(errorBox);

  const dropZone = el("div", "vault-field");
  dropZone.style.border = "1px dashed var(--border)";
  dropZone.style.borderRadius = "8px";
  dropZone.style.padding = "14px";
  dropZone.style.textAlign = "center";
  dropZone.style.cursor = "pointer";
  dropZone.style.marginBottom = "10px";

  const fileInput = document.createElement("input");
  fileInput.type = "file";
  fileInput.accept = ".env,.env.*,text/plain";
  fileInput.style.display = "none";

  const dropText = el("p", "", "Click to select a .env file, or paste contents below");
  dropText.style.margin = "0";
  dropText.style.fontSize = "13px";
  dropText.style.color = "var(--muted)";
  dropZone.append(fileInput, dropText);
  dropZone.addEventListener("click", () => { fileInput.click(); });
  dialog.append(dropZone);

  const textWrap = el("label", "vault-field");
  textWrap.append(el("span", "vault-field-label", "Or paste .env contents:"));
  const textarea = document.createElement("textarea");
  textarea.className = "vault-input";
  textarea.style.height = "85px";
  textarea.style.fontFamily = "monospace";
  textarea.style.fontSize = "12px";
  textarea.placeholder = "STRIPE_SECRET_KEY=sk_live_...\nOPENAI_API_KEY=sk-proj-...\nDATABASE_URL=postgresql://...";
  textWrap.append(textarea);
  dialog.append(textWrap);

  const previewContainer = el("div", "dotenv-preview-container");
  previewContainer.style.marginTop = "10px";
  previewContainer.style.maxHeight = "220px";
  previewContainer.style.overflowY = "auto";
  dialog.append(previewContainer);

  let parsedItems: DotEnvImportItem[] = [];

  const actions = el("div", "vault-modal-actions");
  const cancelBtn = el("button", "vault-btn vault-btn-ghost", "Cancel") as HTMLButtonElement;
  cancelBtn.type = "button";
  const saveBtn = el("button", "vault-btn vault-btn-primary", "Import Selected Secrets") as HTMLButtonElement;
  saveBtn.type = "button";
  saveBtn.disabled = true;
  actions.append(cancelBtn, saveBtn);
  dialog.append(actions);

  const updatePreview = (text: string) => {
    previewContainer.replaceChildren();
    parsedItems = parseDotEnvWithInference(text);

    if (parsedItems.length === 0) {
      if (text.trim()) {
        const noItems = el("p", "vault-muted", "No valid environment variables detected.");
        noItems.style.padding = "8px 0";
        previewContainer.append(noItems);
      }
      saveBtn.disabled = true;
      return;
    }

    saveBtn.disabled = false;
    const table = el("table", "data-table");

    const thead = el("thead", "");
    const headerRow = el("tr", "");
    const thCheck = el("th", "", "Use");
    const thKey = el("th", "", "Variable");
    const thAlias = el("th", "", "Inferred Alias");
    const thScope = el("th", "", "Ceiling Scope");
    const thSecret = el("th", "", "Value");
    headerRow.append(thCheck, thKey, thAlias, thScope, thSecret);
    thead.append(headerRow);
    table.append(thead);

    const tbody = el("tbody", "");
    for (const item of parsedItems) {
      const tr = el("tr", "");

      const tdCheck = el("td", "");
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = item.included;
      cb.addEventListener("change", () => {
        item.included = cb.checked;
        saveBtn.disabled = !parsedItems.some((i) => i.included);
      });
      tdCheck.append(cb);

      const tdKey = el("td", "", item.rawKey);
      tdKey.style.fontWeight = "600";

      const tdAlias = el("td", "");
      const aliasInp = document.createElement("input");
      aliasInp.className = "vault-input";
      aliasInp.value = item.alias;
      aliasInp.addEventListener("input", () => {
        item.alias = aliasInp.value.trim();
      });
      tdAlias.append(aliasInp);

      const tdScope = el("td", "");
      const scopeInp = document.createElement("input");
      scopeInp.className = "vault-input";
      scopeInp.value = item.scope;
      scopeInp.addEventListener("input", () => {
        item.scope = scopeInp.value.trim();
      });
      tdScope.append(scopeInp);

      const tdSecret = el("td", "vault-muted", "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022");

      tr.append(tdCheck, tdKey, tdAlias, tdScope, tdSecret);
      tbody.append(tr);
    }
    table.append(tbody);
    previewContainer.append(table);
  };

  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = () => {
        const text = typeof reader.result === "string" ? reader.result : "";
        textarea.value = text;
        updatePreview(text);
      };
      reader.readAsText(file);
    }
  });

  textarea.addEventListener("input", () => {
    updatePreview(textarea.value);
  });

  const close = (): void => {
    closeCredentialModal();
  };
  closeBtn.addEventListener("click", close);
  cancelBtn.addEventListener("click", close);

  saveBtn.addEventListener("click", () => {
    const toImport = parsedItems.filter((i) => i.included && i.alias && i.scope && i.value);
    if (toImport.length === 0) {
      return;
    }
    saveBtn.disabled = true;
    cancelBtn.disabled = true;

    void (async () => {
      let count = 0;
      for (const item of toImport) {
        try {
          await window.metavault.addCredential(
            item.alias,
            item.scope,
            item.value,
            `env:${item.rawKey}`
          );
          count += 1;
        } catch {
          // ignore duplicate conflicts
        }
      }
      close();
      await refresh();
      render();
      showBanner(`Successfully imported ${String(count)} credential${count === 1 ? "" : "s"} into vault.`);
    })();
  });

  overlay.append(dialog);
  document.body.append(overlay);
  credentialModal = overlay;
}

function renderVault(view: HTMLElement): void {
  const panel = el("section", "vault-panel");
  const headerRow = el("div", "vault-section-header");
  headerRow.append(el("h2", "vault-title", "Agent credentials"));

  const actionGroup = el("div", "vault-header-actions");
  actionGroup.style.display = "flex";
  actionGroup.style.gap = "8px";
  actionGroup.style.alignItems = "center";

  const importBtn = el("button", "action btn-import-dotenv", "Import .env") as HTMLButtonElement;
  importBtn.type = "button";
  importBtn.addEventListener("click", () => {
    openDotEnvModal();
  });
  actionGroup.append(importBtn);

  const addBtn = el("button", "vault-add-btn", "+") as HTMLButtonElement;
  addBtn.type = "button";
  addBtn.setAttribute("aria-label", "Add credential");
  addBtn.title = "Add credential";
  addBtn.addEventListener("click", () => {
    openCredentialModal();
  });
  actionGroup.append(addBtn);

  headerRow.append(actionGroup);
  panel.append(headerRow);
  panel.append(el("p", "vault-sub", "Aliases and scopes only \u2014 values are never displayed, copied, or sent to this window."));
  if (aliases.length === 0) {
    panel.append(el("p", "vault-empty", "No credentials saved"));
    view.append(panel);
    return;
  }
  const wrap = el("div", "data-table-wrap");
  const table = el("table", "data-table");
  const head = el("tr", "");
  head.append(el("th", "", "Alias"), el("th", "", "Scopes"), el("th", "", "Site"), el("th", "", "Last used"));
  const thead = el("thead", "");
  thead.append(head);
  const tbody = el("tbody", "");
  for (const card of deriveVaultCards(aliases, auditEvents, credentialMeta)) {
    const scopes = card.scopes.length === 0 ? "No requests yet" : card.scopes.join(", ");
    const site = card.website === "" ? "—" : card.website;
    const last = formatLastUsed(card.lastUsedTs, Date.now());
    const tr = el("tr", "is-clickable");
    tr.tabIndex = 0;
    tr.setAttribute("role", "button");
    tr.setAttribute("aria-label", `Edit credential ${card.alias}`);
    const aliasCell = el("td", "");
    const aliasMain = el("div", "cell-with-mark");
    aliasMain.append(faviconNode(card.website, card.alias));
    const aliasText = el("span", "", card.alias);
    aliasMain.append(aliasText);
    aliasCell.append(aliasMain);
    aliasCell.title = card.alias;
    const scopeCell = cell(scopes);
    const siteCell = cell(site);
    const lastCell = cell(last);
    tr.append(aliasCell, scopeCell, siteCell, lastCell);
    const open = (): void => {
      openCredentialDetail(card);
    };
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        open();
      }
    });
    tbody.append(tr);
  }
  table.append(thead, tbody);
  wrap.append(table);
  panel.append(wrap);
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

  const controls = el("div", "audit-controls");

  // Search input row
  const searchRow = el("div", "audit-search-row");
  const searchInput = document.createElement("input");
  searchInput.id = "audit-filter";
  searchInput.className = "audit-search-input";
  searchInput.type = "text";
  searchInput.placeholder = "Filter by agent, alias, scope, or outcome";
  searchInput.value = auditFilter;
  searchInput.setAttribute("aria-label", "Search audit requests");
  searchRow.append(searchInput);
  controls.append(searchRow);

  // Filters grid
  const filtersGrid = el("div", "audit-filters-grid");

  // 1. Outcome filter
  const outcomeItem = el("div", "audit-filter-item");
  const outcomeLabel = el("label", "audit-select-label", "Outcome");
  outcomeLabel.setAttribute("for", "audit-outcome-select");
  const outcomeSelect = document.createElement("select");
  outcomeSelect.id = "audit-outcome-select";
  outcomeSelect.className = "audit-select";
  const outcomeOptions = [
    { value: "all", text: "All Outcomes" },
    { value: "executed", text: "Executed" },
    { value: "denied", text: "Denied" },
    { value: "expired", text: "Expired" },
    { value: "revoked", text: "Revoked" },
    { value: "pending", text: "Pending" },
  ];
  for (const opt of outcomeOptions) {
    const o = document.createElement("option");
    o.value = opt.value;
    o.textContent = opt.text;
    outcomeSelect.append(o);
  }
  outcomeSelect.value = auditOutcomeFilter;
  outcomeItem.append(outcomeLabel, outcomeSelect);
  filtersGrid.append(outcomeItem);

  // Derive distinct agents and aliases from all groups
  const allGroups = groupAuditByRequest(auditEvents);
  const distinctAgents = [...new Set(allGroups.map((g) => g.agentId).filter(Boolean))].sort();
  const distinctAliases = [...new Set(allGroups.map((g) => g.alias).filter(Boolean))].sort();

  // 2. Caller filter
  const agentItem = el("div", "audit-filter-item");
  const agentLabel = el("label", "audit-select-label", "Caller / Agent");
  agentLabel.setAttribute("for", "audit-agent-select");
  const agentSelect = document.createElement("select");
  agentSelect.id = "audit-agent-select";
  agentSelect.className = "audit-select";
  const allAgentsOpt = document.createElement("option");
  allAgentsOpt.value = "all";
  allAgentsOpt.textContent = "All Callers";
  agentSelect.append(allAgentsOpt);
  for (const agent of distinctAgents) {
    const o = document.createElement("option");
    o.value = agent;
    o.textContent = agent;
    agentSelect.append(o);
  }
  agentSelect.value = auditAgentFilter;
  agentItem.append(agentLabel, agentSelect);
  filtersGrid.append(agentItem);

  // 3. Credential / Alias filter
  const aliasItem = el("div", "audit-filter-item");
  const aliasLabel = el("label", "audit-select-label", "Credential / Alias");
  aliasLabel.setAttribute("for", "audit-alias-select");
  const aliasSelect = document.createElement("select");
  aliasSelect.id = "audit-alias-select";
  aliasSelect.className = "audit-select";
  const allAliasesOpt = document.createElement("option");
  allAliasesOpt.value = "all";
  allAliasesOpt.textContent = "All Credentials";
  aliasSelect.append(allAliasesOpt);
  for (const a of distinctAliases) {
    const o = document.createElement("option");
    o.value = a;
    o.textContent = a;
    aliasSelect.append(o);
  }
  aliasSelect.value = auditAliasFilter;
  aliasItem.append(aliasLabel, aliasSelect);
  filtersGrid.append(aliasItem);

  // 4. Date range filter
  const dateItem = el("div", "audit-filter-item");
  const dateLabel = el("label", "audit-select-label", "Date Range");
  dateLabel.setAttribute("for", "audit-date-select");
  const dateSelect = document.createElement("select");
  dateSelect.id = "audit-date-select";
  dateSelect.className = "audit-select";
  const dateOptions = [
    { value: "all", text: "All Time" },
    { value: "today", text: "Today" },
    { value: "24h", text: "Last 24 Hours" },
    { value: "7d", text: "Last 7 Days" },
    { value: "30d", text: "Last 30 Days" },
  ];
  for (const opt of dateOptions) {
    const o = document.createElement("option");
    o.value = opt.value;
    o.textContent = opt.text;
    dateSelect.append(o);
  }
  dateSelect.value = auditDateRangeFilter;
  dateItem.append(dateLabel, dateSelect);
  filtersGrid.append(dateItem);

  // Reset button
  const hasActiveFilter =
    auditFilter.trim() !== "" ||
    auditOutcomeFilter !== "all" ||
    auditAgentFilter !== "all" ||
    auditAliasFilter !== "all" ||
    auditDateRangeFilter !== "all";

  if (hasActiveFilter) {
    const resetBtn = el("button", "audit-reset-btn", "Reset filters") as HTMLButtonElement;
    resetBtn.type = "button";
    resetBtn.addEventListener("click", () => {
      auditFilter = "";
      auditOutcomeFilter = "all";
      auditAgentFilter = "all";
      auditAliasFilter = "all";
      auditDateRangeFilter = "all";
      auditPage = 1;
      render();
    });
    filtersGrid.append(resetBtn);
  }

  controls.append(filtersGrid);
  view.append(controls);

  const list = el("div", "data-table-wrap");
  view.append(list);

  const paginationContainer = el("div", "pagination-wrap");
  view.append(paginationContainer);

  const renderList = (): void => {
    list.replaceChildren();
    paginationContainer.replaceChildren();

    const filtered = filterAuditGroups(allGroups, {
      query: auditFilter,
      outcome: auditOutcomeFilter,
      agentId: auditAgentFilter,
      alias: auditAliasFilter,
      dateRange: auditDateRangeFilter,
    });

    if (auditEvents.length === 0) {
      list.append(el("div", "empty", "No audit events yet."));
      return;
    }
    if (filtered.length === 0) {
      list.append(el("div", "empty", "No requests match the active filters."));
      return;
    }

    const paginated = paginate(filtered, auditPage, auditPageSize);
    auditPage = paginated.currentPage;

    const table = el("table", "data-table");
    const headRow = el("tr", "");
    for (const label of ["When", "Caller", "Alias", "Scope", "Outcome", "Warden", ""]) {
      headRow.append(el("th", label === "" ? "data-table-action" : "", label));
    }
    const thead = el("thead", "");
    thead.append(headRow);
    const tbody = el("tbody", "");
    for (const group of paginated.items) {
      const verdict = wardenVerdict(group);
      const expanded = expandedAuditIds.has(group.requestId);
      const allowedText = group.allowedScope ?? "—";
      const scopeText =
        group.requestedScope !== "" && group.requestedScope !== allowedText
          ? `${group.requestedScope} → ${allowedText}`
          : allowedText || group.requestedScope;
      const tr = el("tr", "");
      tr.append(cell(group.lastTs));
      tr.append(cell(group.isLegacy ? "Earlier activity" : group.agentId));
      tr.append(cell(group.isLegacy ? "—" : group.alias));
      tr.append(cell(group.isLegacy ? `${String(group.events.length)} events` : scopeText));
      const outcomeCell = el("td", "");
      if (group.isLegacy) {
        outcomeCell.textContent = "—";
      } else {
        const badgeClass =
          verdict.outcome === "executed"
            ? "status-badge is-ok"
            : verdict.outcome === "denied" || verdict.outcome === "revoked"
              ? "status-badge is-danger"
              : verdict.outcome === "expired"
                ? "status-badge is-warn"
                : "status-badge";
        outcomeCell.append(el("span", badgeClass, verdict.outcomeLabel));
        outcomeCell.title = verdict.outcomeLabel;
      }
      const wardenBits = group.isLegacy
        ? ["—"]
        : [verdict.wardenLabel, verdict.escalated ? "escalated" : "", verdict.narrowed ? "narrowed" : ""].filter(
            (part) => part !== "",
          );
      tr.append(outcomeCell, cell(wardenBits.join(" · ")));
      const action = el("td", "data-table-action");
      const toggle = el("button", "text-action", expanded ? "Hide" : "Details") as HTMLButtonElement;
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
      action.append(toggle);
      tr.append(action);
      tbody.append(tr);

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
        if (group.agentId !== "human") {
          const blockAgentBtn = el("button", "text-revoke", "Revoke") as HTMLButtonElement;
          blockAgentBtn.type = "button";
          blockAgentBtn.disabled = busy;
          blockAgentBtn.addEventListener("click", () => {
            void runAction(
              () => window.metavault.revoke(group.agentId),
              `Revoked ${group.agentId} — pending grants cancelled, new requests denied.`,
            );
          });
          timeline.append(blockAgentBtn);
        }
        const detail = el("tr", "is-detail");
        const detailCell = el("td", "") as HTMLTableCellElement;
        detailCell.colSpan = 7;
        detailCell.append(timeline);
        detail.append(detailCell);
        tbody.append(detail);
      }
    }
    table.append(thead, tbody);
    list.append(table);

    // Pagination controls bar
    const paginationBar = el("div", "pagination-bar");
    const info = el(
      "div",
      "pagination-info",
      `Showing ${String(paginated.startIndex)}-${String(paginated.endIndex)} of ${String(paginated.totalItems)} requests`,
    );

    const controlsGroup = el("div", "pagination-controls");

    const prevBtn = pagerButton("Previous", "prev");
    prevBtn.disabled = paginated.currentPage <= 1;
    prevBtn.addEventListener("click", () => {
      if (auditPage > 1) {
        auditPage -= 1;
        renderList();
      }
    });

    const pageIndicator = el(
      "span",
      "pagination-page-indicator",
      `Page ${String(paginated.currentPage)} of ${String(paginated.totalPages)}`,
    );

    const nextBtn = pagerButton("Next", "next");
    nextBtn.disabled = paginated.currentPage >= paginated.totalPages;
    nextBtn.addEventListener("click", () => {
      if (auditPage < paginated.totalPages) {
        auditPage += 1;
        renderList();
      }
    });

    const pageSizeSelect = document.createElement("select");
    pageSizeSelect.className = "audit-select";
    pageSizeSelect.style.marginLeft = "8px";
    for (const size of [10, 25, 50]) {
      const opt = document.createElement("option");
      opt.value = String(size);
      opt.textContent = `${String(size)} / page`;
      pageSizeSelect.append(opt);
    }
    pageSizeSelect.value = String(auditPageSize);
    pageSizeSelect.addEventListener("change", () => {
      auditPageSize = Number(pageSizeSelect.value) || 10;
      auditPage = 1;
      renderList();
    });

    controlsGroup.append(prevBtn, pageIndicator, nextBtn, pageSizeSelect);
    paginationBar.append(info, controlsGroup);
    paginationContainer.append(paginationBar);
  };

  const rememberSelection = (): void => {
    auditFilterSelectionStart = searchInput.selectionStart;
    auditFilterSelectionEnd = searchInput.selectionEnd;
  };
  searchInput.addEventListener("input", () => {
    auditFilter = searchInput.value;
    auditPage = 1;
    rememberSelection();
    renderList();
  });
  searchInput.addEventListener("select", rememberSelection);
  searchInput.addEventListener("keyup", rememberSelection);
  searchInput.addEventListener("click", rememberSelection);
  searchInput.addEventListener("focus", () => {
    auditFilterWasFocused = true;
    rememberSelection();
  });
  searchInput.addEventListener("blur", () => {
    auditFilterWasFocused = false;
  });

  outcomeSelect.addEventListener("change", () => {
    auditOutcomeFilter = outcomeSelect.value;
    auditPage = 1;
    renderList();
  });
  agentSelect.addEventListener("change", () => {
    auditAgentFilter = agentSelect.value;
    auditPage = 1;
    renderList();
  });
  aliasSelect.addEventListener("change", () => {
    auditAliasFilter = aliasSelect.value;
    auditPage = 1;
    renderList();
  });
  dateSelect.addEventListener("change", () => {
    auditDateRangeFilter = dateSelect.value;
    auditPage = 1;
    renderList();
  });

  renderList();
  if (auditFilterWasFocused) {
    searchInput.focus();
    const start = Math.min(auditFilterSelectionStart ?? searchInput.value.length, searchInput.value.length);
    const end = Math.min(auditFilterSelectionEnd ?? start, searchInput.value.length);
    searchInput.setSelectionRange(start, end);
  }
}
function settingsSection(title: string, copy: string, tab: SettingsTab): HTMLElement {
  const section = el("section", "settings-section");
  section.dataset["settingsTab"] = tab;
  section.append(el("h2", "settings-title", title));
  if (copy !== "") {
    section.append(el("p", "settings-copy", copy));
  }
  return section;
}

function applySettingsTab(): void {
  const body = document.querySelector("#settings-body");
  if (body !== null) {
    body.querySelectorAll<HTMLElement>("[data-settings-tab]").forEach((node) => {
      node.hidden = node.dataset["settingsTab"] !== settingsTab;
    });
  }
  document.querySelectorAll<HTMLButtonElement>(".settings-tab").forEach((btn) => {
    const on = btn.dataset["settingsTab"] === settingsTab;
    btn.classList.toggle("is-active", on);
    btn.setAttribute("aria-selected", on ? "true" : "false");
  });
  const label = document.querySelector("#settings-tab-label");
  if (label !== null) label.textContent = SETTINGS_TAB_LABEL[settingsTab];
}

function openSettings(tab?: SettingsTab): void {
  if (tab !== undefined) settingsTab = tab;
  settingsFocusOnOpen = !settingsOpen;
  settingsOpen = true;
  if (typeof window.metavault.getBuiltinAiStatus === "function") {
    void window.metavault.getBuiltinAiStatus().then((s) => {
      builtinAiStatus = s;
      render();
    });
  }
  render();
}

function closeSettings(): void {
  if (!settingsOpen) return;
  const liveKey = document.querySelector<HTMLInputElement>("#warden-key-input");
  if (liveKey !== null) settingsKeyDraft = liveKey.value;
  settingsOpen = false;
  render();
}

function syncChrome(): void {
  const page = currentView === "settings" ? "policies" : currentView;
  document.querySelectorAll<HTMLElement>(".nav-btn").forEach((button) => {
    button.classList.toggle("is-active", button.dataset["view"] === page);
  });
  document.querySelector("#open-settings")?.classList.toggle("is-active", settingsOpen && !vaultLocked);
  const badge = document.querySelector<HTMLElement>("#approval-count");
  const approvalBtn = document.querySelector<HTMLElement>(".nav-btn[data-view='approval']");
  const waiting = approvals.length;
  if (badge !== null) {
    badge.textContent = waiting > 99 ? "99+" : String(waiting);
    badge.hidden = waiting === 0;
  }
  if (approvalBtn !== null) {
    approvalBtn.setAttribute("aria-label", waiting === 0 ? "Approval" : `Approval, ${String(waiting)} waiting`);
  }
}

function paintSettingsModal(): void {
  const modal = document.querySelector<HTMLElement>("#settings-modal");
  const settingsBody = document.querySelector<HTMLElement>("#settings-body");
  if (modal === null || settingsBody === null) return;
  if (!settingsOpen || vaultLocked) {
    modal.hidden = true;
    settingsBody.replaceChildren();
    return;
  }
  settingsBody.replaceChildren();
  renderSettings(settingsBody);
  applySettingsTab();
  modal.hidden = false;
  if (settingsFocusOnOpen) {
    settingsFocusOnOpen = false;
    document.querySelector<HTMLButtonElement>(".settings-tab.is-active")?.focus();
  }
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
  const settingsHeading = el("h1", "settings-page-title", "Settings");
  settingsHeading.setAttribute("aria-hidden", "true");
  view.append(settingsHeading);
  const intro = el("p", "settings-copy", "Choose who judges capability requests. Deterministic policy stays the floor: the warden can narrow or escalate, never widen.");
  intro.dataset["settingsTab"] = "warden";
  view.append(intro);
  if (!wardenLoaded) {
    view.append(el("div", "empty", "Loading warden settings from vaultd\u2026"));
  }

  // 0. Interface Mode (Verbose vs Simple)
  const modeSection = settingsSection("Interface mode", "Choose between a simplified, minimal UI and the full security-first interface.", "general");
  const modeGroup = el("div", "mode-toggle-group");

  const simpleCard = el("div", `mode-option-card ${uiMode === "simple" ? "is-selected" : ""}`);
  const simpleRadio = document.createElement("input");
  simpleRadio.type = "radio";
  simpleRadio.name = "ui-mode-toggle";
  simpleRadio.checked = uiMode === "simple";
  const simpleText = el("div", "");
  simpleText.append(el("div", "mode-option-title", "Simple mode"));
  simpleText.append(el("div", "mode-option-desc", "Streamlined view. Text blocks, instructional walls, and background copy are hidden for a clean, distraction-free view."));
  simpleCard.append(simpleRadio, simpleText);
  simpleCard.addEventListener("click", () => {
    uiMode = "simple";
    localStorage.setItem("metavault_ui_mode", "simple");
    document.body.classList.add("is-simple-mode");
    render();
  });

  const verboseCard = el("div", `mode-option-card ${uiMode === "verbose" ? "is-selected" : ""}`);
  const verboseRadio = document.createElement("input");
  verboseRadio.type = "radio";
  verboseRadio.name = "ui-mode-toggle";
  verboseRadio.checked = uiMode === "verbose";
  const verboseText = el("div", "");
  verboseText.append(el("div", "mode-option-title", "Verbose mode (Security-first)"));
  verboseText.append(el("div", "mode-option-desc", "Security-first interface. Honest, helpful, and proactive guidance with architectural notes, policy ceilings, and full risk explanations."));
  verboseCard.append(verboseRadio, verboseText);
  verboseCard.addEventListener("click", () => {
    uiMode = "verbose";
    localStorage.setItem("metavault_ui_mode", "verbose");
    document.body.classList.remove("is-simple-mode");
    render();
  });

  modeGroup.append(simpleCard, verboseCard);
  modeSection.append(modeGroup);
  view.append(modeSection);

  // Hardware Capacity Check Banner
  interface HardwareCapacityProfile {
    readonly hasWebGpu: boolean;
    readonly cpuCores: number;
    readonly recommendedProvider: WardenSettingsLike["provider"];
    readonly tierBadge: string;
    readonly recommendationCopy: string;
  }

  function detectCapacityProfile(): HardwareCapacityProfile {
    const hasWebGpu = typeof navigator !== "undefined" && "gpu" in navigator && (navigator as { gpu?: unknown }).gpu !== undefined;
    const cpuCores = typeof navigator !== "undefined" && typeof navigator.hardwareConcurrency === "number"
      ? navigator.hardwareConcurrency
      : 4;

    if (!hasWebGpu || cpuCores < 4) {
      return {
        hasWebGpu,
        cpuCores,
        recommendedProvider: "meta-api",
        tierBadge: "Recommended: Meta API",
        recommendationCopy:
          "Limited local GPU acceleration detected. Meta API (Cloud) is recommended: zero download footprint, zero VRAM overhead, instant 70B parameter reasoning.",
      };
    }

    return {
      hasWebGpu,
      cpuCores,
      recommendedProvider: "bft",
      tierBadge: "Recommended: Meta BFT",
      recommendationCopy:
        "Hardware acceleration detected. Meta BFT Consensus is recommended: cloud 70B intelligence cross-verified with on-device Llama 3.2 1B (WebGPU) for offline resilience.",
    };
  }

  const profile = detectCapacityProfile();
  const capacityCard = el("div", "capacity-card");
  capacityCard.dataset["settingsTab"] = "warden";

  const capHead = el("div", "capacity-head");
  const capTitle = el("div", "capacity-title");
  capTitle.textContent = "Hardware Capacity & Profile Recommendation";
  capHead.append(capTitle);
  capHead.append(el("span", profile.hasWebGpu ? "status-badge is-ok" : "status-badge", profile.tierBadge));
  capacityCard.append(capHead);

  const capDesc = el("div", "capacity-details", profile.recommendationCopy);
  capacityCard.append(capDesc);

  const capSpecs = el("div", "capacity-specs");
  capSpecs.append(el("span", "capacity-pill", `WebGPU: ${profile.hasWebGpu ? "Available" : "Not detected"}`));
  capSpecs.append(el("span", "capacity-pill", `CPU: ${String(profile.cpuCores)} cores`));
  capacityCard.append(capSpecs);

  if (wardenDraft.provider !== profile.recommendedProvider) {
    const capActions = el("div", "capacity-actions");
    const applyBtn = el("button", "action btn-approve", `Switch to Recommended (${profile.recommendedProvider === "bft" ? "Meta BFT" : "Meta API"})`) as HTMLButtonElement;
    applyBtn.type = "button";
    applyBtn.addEventListener("click", () => {
      const nextModel = profile.recommendedProvider === "builtin" ? "llama3.2:1b" : "llama-3.3-70b-instruct";
      wardenDraft = { ...wardenDraft, provider: profile.recommendedProvider, model: nextModel };
      wardenDirty = true;
      settingsMessage = null;
      render();
    });
    capActions.append(applyBtn);
    capacityCard.append(capActions);
  }

  view.append(capacityCard);

  // 1. Provider
  const providerSection = settingsSection("Warden provider", "", "warden");
  const providerCopy: Record<WardenSettingsLike["provider"], string> = {
    bft: "Meta BFT Consensus: Dual-warden quorum combining Meta API (Cloud 70B) + Local Llama (WebGPU 1B) for Byzantine fault tolerance, cross-verification, and offline fallback.",
    "meta-api": "Meta API (Cloud): Lightweight cloud inference (Llama 3.3 70B). Zero model download, 0 VRAM required, instant evaluation. Recommended for all machines.",
    builtin: "Built-in AI (WebGPU): Local WebGPU acceleration (Llama 3.2 1B INT4). 100% private on-device execution with automatic offline fallback.",
    ollama: "Local — Ollama runs on this device. Request metadata stays on-device.",
    none: "No model judges requests. Deterministic policy alone decides, and anything needing approval comes to you.",
  };
  for (const provider of WARDEN_PROVIDERS) {
    const label = el("label", "settings-radio");
    const radio = document.createElement("input");
    radio.type = "radio";
    radio.name = "warden-provider";
    radio.value = provider.id;
    radio.checked = wardenDraft.provider === provider.id;
    radio.addEventListener("change", () => {
      const nextModel = provider.id === "builtin" ? "llama3.2:1b" : wardenDraft.model;
      wardenDraft = { ...wardenDraft, provider: provider.id, model: nextModel };
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
  const modelSection = settingsSection("Model", "", "warden");
  if (wardenDraft.provider === "none") {
    modelSection.append(el("p", "settings-copy", "No model \u2014 policy only. Choose Built-in AI, Ollama, or Meta API to enable a warden model."));
    } else if (wardenDraft.provider === "bft") {
    const card = el("div", "bft-card");
    const head = el("div", "bft-head");
    const info = el("div", "");
    info.append(el("div", "bft-title", "Meta Dual-Warden BFT Consensus"));
    info.append(el("div", "bft-desc", "Byzantine fault-tolerant consensus across Meta's cloud and local AI architectures. Meta API provides 70B parameter reasoning, while on-device Llama 3.2 co-audits and provides instant offline resilience."));
    head.append(info);
    head.append(el("span", "status-badge is-ok", "\u25CF BFT Active"));
    card.append(head);

    const pillars = el("div", "bft-pillars");

    // Pillar 1: Meta API (Cloud Chief Justice)
    const activeCloudModel = wardenDraft.model && wardenDraft.model !== "llama3.2:1b" ? wardenDraft.model : "llama-3.3-70b-instruct";
    const metaPillar = el("div", "bft-pillar-item");
    metaPillar.append(createMetaLogo());
    const metaDetails = el("div", "bft-pillar-details");
    metaDetails.append(el("div", "bft-pillar-title", `Meta API Cloud Warden: ${activeCloudModel}`));
    metaDetails.append(el("div", "bft-pillar-sub", "Cloud High-Capacity Reasoning \u00B7 Primary Policy Evaluator"));
    metaPillar.append(metaDetails);
    metaPillar.append(el("span", "status-badge is-ok", "Cloud Primary"));

    // Pillar 2: Meta Local Fallback (On-Device Co-Auditor)
    const localPillar = el("div", "bft-pillar-item");
    localPillar.append(createMetaLogo());
    const localDetails = el("div", "bft-pillar-details");
    localDetails.append(el("div", "bft-pillar-title", "Meta Llama 3.2 1B (INT4 WebGPU)"));
    localDetails.append(el("div", "bft-pillar-sub", "On-Device Zero-Egress Fallback \u00B7 Offline & Divergence Guard"));
    localPillar.append(localDetails);
    localPillar.append(el("span", "status-badge is-ok", "Local Fallback"));

    pillars.append(metaPillar, localPillar);
    card.append(pillars);
    modelSection.append(card);

    // Cloud Warden Model Selector & Custom Free-Text Input
    const configHeading = el("p", "settings-copy", "Choose or type ANY Meta AI model for your Cloud Warden:");
    modelSection.append(configHeading);

    const selectLabel = el("label", "vault-field");
    selectLabel.append(el("span", "vault-field-label", "Meta API cloud model"));
    const select = document.createElement("select");
    select.className = "vault-input";
    select.id = "warden-meta-model-select";
    for (const option of META_API_MODEL_OPTIONS) {
      const opt = document.createElement("option");
      opt.value = option.id;
      opt.textContent = option.label;
      select.append(opt);
    }
    if (!isKnownMetaApiModel(activeCloudModel)) {
      const custom = document.createElement("option");
      custom.value = activeCloudModel;
      custom.textContent = `${activeCloudModel} \u2014 Custom`;
      select.append(custom);
    }
    select.value = activeCloudModel;
    select.addEventListener("change", () => {
      wardenDraft = { ...wardenDraft, model: select.value };
      wardenDirty = true;
      render();
    });
    selectLabel.append(select);
    modelSection.append(selectLabel);

    const modelLabel = el("label", "vault-field");
    modelLabel.append(el("span", "vault-field-label", "Custom Meta API model id (free text)"));
    const modelInput = document.createElement("input");
    modelInput.className = "vault-input";
    modelInput.id = "warden-model-input";
    modelInput.type = "text";
    modelInput.value = activeCloudModel;
    modelInput.placeholder = "llama-3.3-70b-instruct";
    modelInput.autocomplete = "off";
    modelInput.addEventListener("input", () => {
      wardenDraft = { ...wardenDraft, model: modelInput.value };
      wardenDirty = true;
    });
    modelLabel.append(modelInput);
    modelSection.append(modelLabel);

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
  } else if (wardenDraft.provider === "builtin") {
    const card = el("div", "builtin-ai-card");
    const head = el("div", "builtin-ai-head");
    const info = el("div", "");
    info.append(el("div", "builtin-ai-title", "Llama 3.2 1B Instruct (INT4 WebGPU)"));
    info.append(el("div", "builtin-ai-desc", "Compact ~680 MB edge model running locally via WebGPU on Direct3D 12 / Vulkan. Zero network egress."));
    head.append(info);

    const isDownloading = builtinAiProgress?.state === "downloading" || builtinAiProgress?.state === "verifying";
    const resolverState = builtinAiStatus?.resolverStatus.state ?? "missing";

    let badgeClass = "status-badge";
    let badgeText = "Checking...";

    if (isDownloading) {
      badgeClass = "status-badge is-warn";
      badgeText = builtinAiProgress?.state === "verifying" ? "Verifying..." : `Downloading (${String(Math.round(builtinAiProgress?.percent ?? 0))}%)`;
    } else if (resolverState === "bundled") {
      badgeClass = "status-badge is-ok";
      badgeText = "\u25CF Ready \u00B7 Baked-in";
    } else if (resolverState === "cached") {
      badgeClass = "status-badge is-ok";
      badgeText = "\u25CF Ready \u00B7 Cached";
    } else {
      badgeClass = "status-badge";
      badgeText = "\u25CB Download Available (~680 MB)";
    }

    head.append(el("span", badgeClass, badgeText));
    card.append(head);

    if (isDownloading && builtinAiProgress !== null) {
      const prog = el("div", "builtin-ai-progress");
      const track = el("div", "builtin-ai-progress-track");
      const fill = el("div", "builtin-ai-progress-fill") as HTMLDivElement;
      fill.style.width = `${String(builtinAiProgress.percent)}%`;
      track.append(fill);
      prog.append(track);

      const stats = el("div", "builtin-ai-progress-stats");
      const dlMb = (builtinAiProgress.downloadedBytes / (1024 * 1024)).toFixed(1);
      const totMb = (builtinAiProgress.totalBytes / (1024 * 1024)).toFixed(1);
      const speedMb = (builtinAiProgress.speedBytesPerSec / (1024 * 1024)).toFixed(1);
      stats.append(el("span", "mono", `${dlMb} / ${totMb} MB (${String(Math.round(builtinAiProgress.percent))}%) \u00B7 ${speedMb} MB/s`));

      const cancelBtn = el("button", "action btn-deny", "Cancel") as HTMLButtonElement;
      cancelBtn.type = "button";
      cancelBtn.addEventListener("click", () => {
        void window.metavault.cancelBuiltinAiDownload().then(() => {
          builtinAiProgress = null;
          render();
        });
      });
      stats.append(cancelBtn);
      prog.append(stats);
      card.append(prog);
    } else if (resolverState === "missing") {
      const actions = el("div", "builtin-ai-actions");
      const dlBtn = el("button", "action btn-approve", "Download Model (~680 MB)") as HTMLButtonElement;
      dlBtn.type = "button";
      dlBtn.disabled = settingsBusy;
      dlBtn.addEventListener("click", () => {
        void window.metavault.startBuiltinAiDownload().then((started) => {
          if (started) {
            render();
          }
        });
      });
      actions.append(dlBtn);
      card.append(actions);
      card.append(el("p", "settings-copy", "Model files will be cached locally in your user profile for fast on-device inference."));
    } else {
      const pathText = builtinAiStatus?.resolverStatus.path ?? "Default storage location";
      const infoP = el("p", "settings-copy", "Local model weights are verified and ready for WebGPU execution.");
      const pathLine = el("p", "settings-status mono", `Path: ${pathText}`);
      card.append(infoP, pathLine);
    }

    modelSection.append(card);
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
  const effortSection = settingsSection("Effort", "", "warden");
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
    const doSave = () => {
      void runSettingsAction(async () => {
        const raw = await window.metavault.updateWardenSettings(buildWardenPatch(wardenDraft));
        const projected = projectWardenSettings(raw);
        if (projected !== null) {
          wardenDraft = projected;
        }
        wardenDirty = false;
        wardenLoaded = true;
        updateMarshalLine();
        settingsMessage = { text: "Warden settings saved. They apply on the next request \u2014 no daemon restart needed.", ok: true };
      });
    };
    if (shouldRequireAuthForSettings(localAuthStatus)) {
      void confirmLocalPresence("Authenticate to modify settings", doSave);
    } else {
      doSave();
    }
  });
  const saveRow = el("div", "settings-row");
  saveRow.append(el("span", "settings-row-label", "Save warden settings"));
  saveRow.append(saveBtn);
  effortSection.append(saveRow);
  view.append(effortSection);

  // 4. Meta API key
  const keySection = settingsSection("Meta API key", "The key is stored encrypted and decrypted in daemon memory at call time. It is never shown again after saving.", "warden");
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
    const doSaveKey = () => {
      void runSettingsAction(async () => {
        const key = settingsKeyDraft;
        const raw = await window.metavault.setWardenKey(key);
        const projected = projectWardenKeyStatus(raw);
        if (projected !== null) wardenKeyStatusState = projected;
        // Clear the field and never repopulate it from the daemon response.
        settingsKeyDraft = "";
        const live = document.querySelector<HTMLInputElement>("#warden-key-input");
        if (live !== null) live.value = "";
        settingsMessage = { text: "Meta API key saved. The field has been cleared; the key is never shown again.", ok: true };
      });
    };
    if (shouldRequireAuthForSettings(localAuthStatus)) {
      void confirmLocalPresence("Authenticate to save key", doSaveKey);
    } else {
      doSaveKey();
    }
  });
  const testBtn = el("button", "action btn-always", "Test connection") as HTMLButtonElement;
  testBtn.type = "button";
  testBtn.disabled = settingsBusy;
  testBtn.addEventListener("click", () => {
    void runSettingsAction(async () => {
      const raw = await window.metavault.testWarden();
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
    const doDeleteKey = () => {
      void runSettingsAction(async () => {
        const raw = await window.metavault.deleteWardenKey();
        const projected = projectWardenKeyStatus(raw);
        wardenKeyStatusState = projected ?? { configured: false, last4: null };
        settingsKeyDraft = "";
        settingsMessage = { text: "Meta API key deleted.", ok: true };
      });
    };
    if (shouldRequireAuthForSettings(localAuthStatus)) {
      void confirmLocalPresence("Authenticate to delete key", doDeleteKey);
    } else {
      doDeleteKey();
    }
  });
  keyBtns.append(saveKeyBtn, testBtn, deleteKeyBtn);
  const keyRow = el("div", "settings-row");
  keyRow.append(el("span", "settings-row-label", "Key actions"));
  keyRow.append(keyBtns);
  keySection.append(keyRow);
  keySection.append(el("p", "settings-copy", "Test connection runs one metadata-only warden self-check through vaultd using the saved provider and model (save settings changes first to test them). It creates no grants and writes no audit entries."));
  view.append(keySection);

  if (settingsMessage !== null) {
    const msg = el("p", settingsMessage.ok ? "settings-message is-ok" : "settings-message is-error", settingsMessage.text);
    msg.dataset["settingsTab"] = "warden";
    view.append(msg);
  }

  // 4b. Local authentication & security gates (#19)
  const authSection = settingsSection(
    "Local authentication & security gates",
    "Windows Hello is the lock. It uses the PIN, face, or fingerprint on this PC, and MetaVault never sees that PIN. An app PIN is only a fallback.",
    "general",
  );

  const authStatusP = el("p", "settings-status", localAuthFactorLabel(localAuthStatus));
  authSection.append(authStatusP);
  if (localAuthNotice !== null) {
    authSection.append(el(
      "p",
      localAuthNotice.ok ? "settings-message is-ok" : "settings-message is-error",
      localAuthNotice.text,
    ));
  }

  const helloRow = el("div", "settings-row");
  helloRow.append(el("span", "settings-row-label", "Windows Hello"));
  const helloBtns = el("div", "settings-btns");
  if (isBiometricsActive(localAuthStatus)) {
    const offBtn = el("button", "action", "Turn off") as HTMLButtonElement;
    offBtn.type = "button";
    offBtn.addEventListener("click", () => {
      void runSettingsAction(async () => {
        const raw = await window.metavault.updateLocalAuthSettings(
          localAuthStatus.configured
            ? { biometricEnabled: false }
            : { biometricEnabled: false, enabled: false },
        );
        const projected = projectLocalAuthStatus(raw);
        if (projected !== null) localAuthStatus = projected;
        localAuthNotice = null;
      });
    });
    helloBtns.append(offBtn);
  } else {
    const helloBtn = el("button", "action btn-approve", "Use Windows Hello") as HTMLButtonElement;
    helloBtn.type = "button";
    helloBtn.addEventListener("click", () => {
      void tryEnableWindowsHello();
    });
    helloBtns.append(helloBtn);
  }
  helloRow.append(helloBtns);
  authSection.append(helloRow);

  const authToggleRow = el("div", "settings-row");
  const authToggleLabel = el(
    "span",
    "settings-row-label",
    "Enable local authentication gate (Off by default)",
  );
  const authToggle = document.createElement("input");
  authToggle.type = "checkbox";
  authToggle.checked = localAuthStatus.enabled;
  authToggle.addEventListener("change", () => {
    if (authToggle.checked && !isBiometricsActive(localAuthStatus) && shouldPromptPinSetupOnEnable(localAuthStatus)) {
      void (async () => {
        const outcome = await tryEnableWindowsHello();
        if (outcome === "on" || outcome === "canceled" || localAuthStatus.configured) return;
        openPinModal(() => {
          void runSettingsAction(async () => {
            const raw = await window.metavault.updateLocalAuthSettings({ enabled: true });
            const projected = projectLocalAuthStatus(raw);
            if (projected !== null) localAuthStatus = projected;
            render();
          });
        });
      })();
      authToggle.checked = false;
      return;
    }
    void runSettingsAction(async () => {
      const raw = await window.metavault.updateLocalAuthSettings({ enabled: authToggle.checked });
      const projected = projectLocalAuthStatus(raw);
      if (projected !== null) localAuthStatus = projected;
      render();
    });
  });
  authToggleRow.append(authToggleLabel, authToggle);
  authSection.append(authToggleRow);

  if (localAuthStatus.enabled) {
    // 1. Require on Launch
    const launchRow = el("div", "settings-row");
    const launchLabel = el(
      "span",
      "settings-row-label",
      "Require verification on app launch / initial unlock (Off by default)",
    );
    const launchToggle = document.createElement("input");
    launchToggle.type = "checkbox";
    launchToggle.checked = localAuthStatus.requireOnLaunch;
    launchToggle.addEventListener("change", () => {
      void runSettingsAction(async () => {
        const raw = await window.metavault.updateLocalAuthSettings({ requireOnLaunch: launchToggle.checked });
        const projected = projectLocalAuthStatus(raw);
        if (projected !== null) localAuthStatus = projected;
      });
    });
    launchRow.append(launchLabel, launchToggle);
    authSection.append(launchRow);

    // 2. Require on Approval
    const apprRow = el("div", "settings-row");
    const apprLabel = el(
      "span",
      "settings-row-label",
      "Require verification on capability approvals (Off by default)",
    );
    const apprToggle = document.createElement("input");
    apprToggle.type = "checkbox";
    apprToggle.checked = localAuthStatus.requireOnApproval;
    apprToggle.addEventListener("change", () => {
      void runSettingsAction(async () => {
        const raw = await window.metavault.updateLocalAuthSettings({ requireOnApproval: apprToggle.checked });
        const projected = projectLocalAuthStatus(raw);
        if (projected !== null) localAuthStatus = projected;
      });
    });
    apprRow.append(apprLabel, apprToggle);
    authSection.append(apprRow);

    // 3. Require on Settings & Policy mutation
    const settingsRow = el("div", "settings-row");
    const settingsLabel = el(
      "span",
      "settings-row-label",
      "Require verification to edit security settings & policies (Off by default)",
    );
    const settingsToggle = document.createElement("input");
    settingsToggle.type = "checkbox";
    settingsToggle.checked = localAuthStatus.requireOnSettings;
    settingsToggle.addEventListener("change", () => {
      void runSettingsAction(async () => {
        const raw = await window.metavault.updateLocalAuthSettings({ requireOnSettings: settingsToggle.checked });
        const projected = projectLocalAuthStatus(raw);
        if (projected !== null) localAuthStatus = projected;
      });
    });
    settingsRow.append(settingsLabel, settingsToggle);
    authSection.append(settingsRow);

    const lockRow = el("div", "settings-row");
    const lockLabel = el("span", "settings-row-label", "Auto-lock inactive session (Off by default)");
    const lockSelect = document.createElement("select");
    lockSelect.className = "vault-input";
    lockSelect.style.width = "auto";
    const options = [
      { min: 0, label: "Disabled (Off by default)" },
      { min: 1, label: "After 1 minute" },
      { min: 5, label: "After 5 minutes" },
      { min: 15, label: "After 15 minutes" },
      { min: 30, label: "After 30 minutes" },
      { min: 60, label: "After 60 minutes" },
    ];
    for (const opt of options) {
      const optEl = document.createElement("option");
      optEl.value = String(opt.min);
      optEl.textContent = opt.label;
      if (localAuthStatus.autoLockMinutes === opt.min) optEl.selected = true;
      lockSelect.append(optEl);
    }
    lockSelect.addEventListener("change", () => {
      const mins = Number(lockSelect.value);
      void runSettingsAction(async () => {
        const raw = await window.metavault.updateLocalAuthSettings({ autoLockMinutes: mins });
        const projected = projectLocalAuthStatus(raw);
        if (projected !== null) localAuthStatus = projected;
      });
    });
    lockRow.append(lockLabel, lockSelect);
    authSection.append(lockRow);
  }

  const authBtns = el("div", "settings-btns");
  const pinBtn = el(
    "button",
    "action",
    localAuthStatus.configured ? "Change local PIN" : "Set local PIN",
  ) as HTMLButtonElement;
  pinBtn.type = "button";
  pinBtn.addEventListener("click", () => {
    openPinModal(() => {
      void refresh().then(render);
    });
  });
  authBtns.append(pinBtn);

  if (canLockSessionNow(localAuthStatus)) {
    const lockNowBtn = el("button", "action btn-deny", "Lock session now") as HTMLButtonElement;
    lockNowBtn.type = "button";
    lockNowBtn.addEventListener("click", () => {
      vaultLocked = true;
      render();
    });
    authBtns.append(lockNowBtn);
  }

  const authActionRow = el("div", "settings-row");
  authActionRow.append(el("span", "settings-row-label", "App PIN"));
  authActionRow.append(authBtns);
  authSection.append(authActionRow);
  view.append(authSection);

  // 5. Daemon (read-only)
  const daemonSection = settingsSection("Daemon", "", "daemon");
  const rows: readonly (readonly [string, string])[] = [
    ["Daemon URL", DAEMON_URL_DISPLAY],
    ["Vault path", VAULT_PATH_DISPLAY],
    ["Version", `MetaVault OSS ${APP_VERSION_DISPLAY}`],
  ];
  for (const [label, value] of rows) {
    const row = el("div", "settings-row");
    row.append(el("span", "settings-row-label", label));
    row.append(el("span", "mono settings-row-value", value));
    daemonSection.append(row);
  }
  daemonSection.append(el("p", "settings-copy", "Read-only. Warden settings apply on the next request, so no restart is needed after saving. If vaultd is unreachable, restart it from the terminal where it was launched, then reopen this page."));
  view.append(daemonSection);

  // 5b. Agent Integration & MCP
  const agentSection = settingsSection(
    "Agent Integration & MCP",
    "Connect AI coding agents to MetaVault OSS via the Model Context Protocol (MCP) or built-in agent skills. All requests route to vaultd for policy enforcement and human approval.",
    "daemon",
  );

  const tabsRow = el("div", "agent-tab-btns");
  const tabs = [
    { id: "claude", label: "Claude Code" },
    { id: "cursor", label: "Cursor" },
    { id: "vscode", label: "VS Code" },
    { id: "codex", label: "Codex" },
    { id: "opencode", label: "OpenCode" },
    { id: "skill", label: "Skill: add-secret" },
  ] as const;

  for (const tab of tabs) {
    const tabBtn = el("button", `agent-tab-btn ${activeAgentTab === tab.id ? "is-active" : ""}`, tab.label) as HTMLButtonElement;
    tabBtn.type = "button";
    tabBtn.addEventListener("click", () => {
      activeAgentTab = tab.id;
      render();
    });
    tabsRow.append(tabBtn);
  }
  agentSection.append(tabsRow);

  const codeBox = el("div", "agent-code-block");
  let codeSnippet = "";
  let configPath = "";

  const findAgentToken = (id: string): string => {
    const found = policiesData.agents?.find((a: RegisteredAgent) => a.id === id);
    return found?.token ?? "<token-generated-on-start>";
  };

  if (activeAgentTab === "claude") {
    configPath = ".mcp.json in workspace or ~/.claude.json";
    codeSnippet = JSON.stringify(
      {
        mcpServers: {
          metavault: {
            command: "node",
            args: ["<path-to-repo>/dist/packages/mcp/src/server.js"],
            env: {
              METAVAULT_DAEMON_URL: "http://127.0.0.1:7077",
              METAVAULT_AGENT_ID: "claude-code",
              METAVAULT_AGENT_TOKEN: findAgentToken("claude-code"),
              METAVAULT_IDE: "Claude Code",
            },
          },
        },
      },
      null,
      2,
    );
  } else if (activeAgentTab === "cursor") {
    configPath = ".cursor/mcp.json or ~/.cursor/mcp.json";
    codeSnippet = JSON.stringify(
      {
        mcpServers: {
          metavault: {
            command: "node",
            args: ["<path-to-repo>/dist/packages/mcp/src/server.js"],
            env: {
              METAVAULT_DAEMON_URL: "http://127.0.0.1:7077",
              METAVAULT_AGENT_ID: "cursor",
              METAVAULT_AGENT_TOKEN: findAgentToken("cursor"),
              METAVAULT_IDE: "Cursor",
            },
          },
        },
      },
      null,
      2,
    );
  } else if (activeAgentTab === "vscode") {
    configPath = ".vscode/mcp.json";
    codeSnippet = JSON.stringify(
      {
        servers: {
          metavault: {
            type: "stdio",
            command: "node",
            args: ["<path-to-repo>/dist/packages/mcp/src/server.js"],
            env: {
              METAVAULT_DAEMON_URL: "http://127.0.0.1:7077",
              METAVAULT_AGENT_ID: "vscode",
              METAVAULT_AGENT_TOKEN: findAgentToken("vscode"),
              METAVAULT_IDE: "VS Code",
            },
          },
        },
      },
      null,
      2,
    );
  } else if (activeAgentTab === "codex") {
    configPath = "~/.codex/config.toml";
    codeSnippet = [
      "[mcp_servers.metavault]",
      "command = \"node\"",
      "args = [\"<path-to-repo>/dist/packages/mcp/src/server.js\"]",
      "",
      "[mcp_servers.metavault.env]",
      "METAVAULT_DAEMON_URL = \"http://127.0.0.1:7077\"",
      "METAVAULT_AGENT_ID = \"codex\"",
      `METAVAULT_AGENT_TOKEN = \"${findAgentToken("codex")}\"`,
      "METAVAULT_IDE = \"Codex\"",
    ].join("\n");
  } else if (activeAgentTab === "opencode") {
    configPath = "opencode.json";
    codeSnippet = JSON.stringify(
      {
        $schema: "https://opencode.ai/config.json",
        mcp: {
          metavault: {
            type: "local",
            command: ["node", "<path-to-repo>/dist/packages/mcp/src/server.js"],
            enabled: true,
            environment: {
              METAVAULT_DAEMON_URL: "http://127.0.0.1:7077",
              METAVAULT_AGENT_ID: "opencode",
              METAVAULT_IDE: "OpenCode",
            },
          },
        },
      },
      null,
      2,
    );
  } else {
    configPath = "Built-in Skill: add-secret-to-vault";
    codeSnippet = [
      "# Add Secret to MetaVault OSS (Agent Workflow)",
      "When you need an API key or token not in MetaVault OSS:",
      "1. Call MCP request_enrollment(alias, scope, reason)",
      "2. Present deeplink (metavault://add?...) to the user",
      "3. Only the user types the secret in the MetaVault OSS window",
      "4. Poll enrollment_status(enrollmentId) until completed",
      "5. Call request_capability to verify granted access",
    ].join("\n");
  }

  const copyBtn = el("button", "agent-code-copy-btn", "Copy Config") as HTMLButtonElement;
  copyBtn.type = "button";
  copyBtn.addEventListener("click", () => {
    void navigator.clipboard.writeText(codeSnippet);
    copyBtn.textContent = "Copied!";
    window.setTimeout(() => {
      copyBtn.textContent = "Copy Config";
    }, 2000);
  });

  const pre = el("pre", "");
  pre.textContent = codeSnippet;
  codeBox.append(copyBtn, pre);
  agentSection.append(el("p", "settings-copy", `Configuration location: ${configPath}`));
  agentSection.append(codeBox);

  const skillInfo = el("div", "agent-skill-box");
  skillInfo.append(el("div", "agent-skill-title", "Zero Secret Leakage Invariant"));
  skillInfo.append(
    el(
      "div",
      "agent-skill-step",
      "Secrets never pass through MCP, agents, terminal stdout, or audit trails. AI agents request scoped capabilities; vaultd holds the encrypted secrets and executes calls; the MetaVault OSS UI prompts the human for approval."
    )
  );
  agentSection.append(skillInfo);
  view.append(agentSection);

  // 6. Security defaults (read-only summary)
  const policySection = settingsSection("Security defaults", "", "security");
  const ceilingCount = Object.keys(policiesData.ceilings).length;
  policySection.append(el("p", "settings-copy", `Deterministic policy is the floor and never moves: ${String(ceilingCount)} alias ceiling${ceilingCount === 1 ? "" : "s"} on record, ${String(policiesData.standingApprovals.length)} standing approval${policiesData.standingApprovals.length === 1 ? "" : "s"} in force. The warden may narrow or escalate a request, never widen it. Editing policy stays on the Policies view.`));
  const policiesBtn = el("button", "action settings-link", "Open Policies") as HTMLButtonElement;
  policiesBtn.type = "button";
  policiesBtn.addEventListener("click", () => {
    settingsOpen = false;
    currentView = "policies";
    render();
  });
  const policiesRow = el("div", "settings-row");
  policiesRow.append(el("span", "settings-row-label", "Ceilings and standing approvals"));
  policiesRow.append(policiesBtn);
  policySection.append(policiesRow);
  view.append(policySection);


  // 6b. Agent Anti-Spoofing & Process Protection
  const agentSecSection = settingsSection(
    "Agent Anti-Spoofing & Process Protection",
    "Defense-in-depth security layers to prevent agent identity spoofing, token theft, and unauthorized script injection.",
    "security",
  );

  const strictRow = el("div", "settings-row");
  const strictLabel = el(
    "span",
    "settings-row-label",
    "Strict Agent Verification Mode (Reject unverified callers without token)",
  );
  const strictToggle = document.createElement("input");
  strictToggle.type = "checkbox";
  strictToggle.checked = agentSecuritySettings.strictMode;
  strictToggle.addEventListener("change", () => {
    void runSettingsAction(async () => {
      await window.metavault.updateAgentSecuritySettings({ strictMode: strictToggle.checked });
      agentSecuritySettings = { ...agentSecuritySettings, strictMode: strictToggle.checked };
      render();
    });
  });
  strictRow.append(strictLabel, strictToggle);
  agentSecSection.append(strictRow);

  const procRow = el("div", "settings-row");
  const procLabel = el(
    "span",
    "settings-row-label",
    "Caller Process Inspection (Verify PID & binary against approved agent runtimes)",
  );
  const procToggle = document.createElement("input");
  procToggle.type = "checkbox";
  procToggle.checked = agentSecuritySettings.verifyCallerProcess;
  procToggle.addEventListener("change", () => {
    void runSettingsAction(async () => {
      await window.metavault.updateAgentSecuritySettings({ verifyCallerProcess: procToggle.checked });
      agentSecuritySettings = { ...agentSecuritySettings, verifyCallerProcess: procToggle.checked };
      render();
    });
  });
  procRow.append(procLabel, procToggle);
  agentSecSection.append(procRow);
  view.append(agentSecSection);
  // 7. Auto-updater & releases (#16)
  const updateSection = settingsSection("Auto-updater & releases", "Keep MetaVault OSS secure with signed background updates directly from GitHub Releases.", "general");
  const updateStatusRow = el("div", "settings-row");
  let statusText = `Current version: v${APP_VERSION_DISPLAY}`;
  let statusBadgeClass = "tag-ok";

  if (updaterStatus.status === "checking") {
    statusText = "Checking for updates...";
    statusBadgeClass = "tag-policy";
  } else if (updaterStatus.status === "available") {
    statusText = `Update available: v${updaterStatus.version ?? ""}`;
    statusBadgeClass = "tag-warn";
  } else if (updaterStatus.status === "downloading") {
    statusText = `Downloading update: ${String(updaterStatus.percent ?? 0)}%`;
    statusBadgeClass = "tag-policy";
  } else if (updaterStatus.status === "downloaded") {
    statusText = `Update v${updaterStatus.version ?? ""} ready to install!`;
    statusBadgeClass = "tag-ok";
  } else if (updaterStatus.status === "error") {
    statusText = updaterStatus.message ?? "Update check failed";
    statusBadgeClass = "tag-danger";
  }

  updateStatusRow.append(el("span", "settings-row-label", "Version & release status"));
  updateStatusRow.append(el("span", `tag ${statusBadgeClass}`, statusText));
  updateSection.append(updateStatusRow);

  const updateBtns = el("div", "settings-btns");
  const checkUpdateBtn = el("button", "action", "Check for updates") as HTMLButtonElement;
  checkUpdateBtn.type = "button";
  checkUpdateBtn.disabled = updaterStatus.status === "checking" || updaterStatus.status === "downloading";
  checkUpdateBtn.addEventListener("click", () => {
    updaterStatus = { status: "checking" };
    render();
    if (typeof window.metavault.checkForUpdates === "function") {
      void window.metavault.checkForUpdates();
    }
  });
  updateBtns.append(checkUpdateBtn);

  if (updaterStatus.status === "downloaded") {
    const installBtn = el("button", "action btn-always", "Restart & install update") as HTMLButtonElement;
    installBtn.type = "button";
    installBtn.addEventListener("click", () => {
      if (typeof window.metavault.quitAndInstallUpdate === "function") {
        void window.metavault.quitAndInstallUpdate();
      }
    });
    updateBtns.append(installBtn);
  }

  const updateActionRow = el("div", "settings-row");
  updateActionRow.append(el("span", "settings-row-label", "Updates"));
  updateActionRow.append(updateBtns);
  updateSection.append(updateActionRow);
  view.append(updateSection);
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
    view.append(el("div", "data-table-caption", "Enforced ceilings"));
    const wrap = el("div", "data-table-wrap");
    const table = el("table", "data-table");
    const head = el("tr", "");
    head.append(el("th", "", "Alias"), el("th", "", "Ceiling"));
    const thead = el("thead", "");
    thead.append(head);
    const tbody = el("tbody", "");
    for (const [alias, ceiling] of ceilingEntries) {
      const tr = el("tr", "");
      tr.append(cell(alias), cell(ceiling));
      tbody.append(tr);
    }
    table.append(thead, tbody);
    wrap.append(table);
    view.append(wrap);
  }
  if (rows.length > 0) {
    view.append(el("div", "data-table-caption", "Agents"));
    const wrap = el("div", "data-table-wrap");
    const table = el("table", "data-table");
    const head = el("tr", "");
    for (const label of ["Agent", "Status", "Requests", "Last seen", "Observed", "Ceilings", "Standing", ""]) {
      head.append(el("th", label === "" ? "data-table-action" : "", label));
    }
    const thead = el("thead", "");
    thead.append(head);
    const tbody = el("tbody", "");
    for (const row of rows) {
      const observed = row.scopes.length === 0 ? "none" : row.scopes.join(", ");
      const ceilings = row.ceilings.length === 0 ? "—" : row.ceilings.map((entry) => `${entry.alias}: ${entry.ceiling}`).join(", ");
      const standing = row.standingApprovals.length === 0 ? "—" : row.standingApprovals.map((approval) => `${approval.alias}: ${approval.scope}`).join(", ");
      const tr = el("tr", "");
      const statusCell = el("td", "");
      statusCell.append(
        el(
          "span",
          row.verified ? "status-badge is-ok" : "status-badge is-warn",
          row.verified ? "Verified" : "⚠️ Unverified",
        ),
      );
      tr.append(
        cell(row.agentId),
        statusCell,
        cell(String(row.requestCount)),
        cell(formatLastUsed(row.lastSeenTs, Date.now())),
        cell(observed),
        cell(ceilings),
        cell(standing),
      );
      const action = el("td", "data-table-action");
      const revokeBtn = el("button", "text-revoke", "Revoke") as HTMLButtonElement;
      revokeBtn.type = "button";
      revokeBtn.disabled = busy;
      revokeBtn.addEventListener("click", () => {
        void runAction(() => window.metavault.revoke(row.agentId), `Revoked ${row.agentId} — pending grants cancelled, new requests denied.`);
      });
      action.append(revokeBtn);
      tr.append(action);
      tbody.append(tr);
    }
    table.append(thead, tbody);
    wrap.append(table);
    view.append(wrap);
  }
  const note = el("p", "fine", `Stages: ${(["requested", "marshal", "policy", "approved", "denied", "executed", "expired", "revoked", "credential-added", "credential-deleted"] as const).map(stageLabel).join(" · ")}`);
  note.title = note.textContent;
  view.append(note);
}
function openView(next: Exclude<ViewName, "settings">): void {
  const liveKey = document.querySelector<HTMLInputElement>("#warden-key-input");
  if (liveKey !== null) settingsKeyDraft = liveKey.value;
  if (next === "approval") approvalDialogDismissed = true;
  currentView = next;
  notice = null;
  settingsOpen = false;
  render();
}

function renderPosture(view: HTMLElement): void {
  view.append(el("h1", "", "Posture"));
  view.append(el("p", "sub", "What is in good shape, and the next thing you can do in the app."));
  if (securityPosture === null) {
    view.append(el("div", "empty", "Posture is not available until vaultd answers."));
    return;
  }
  const grade = el("p", "posture-grade", `Grade ${securityPosture.grade} · ${String(securityPosture.score)}/100`);
  grade.classList.add(securityPosture.score >= 80 ? "is-ok" : securityPosture.score >= 60 ? "is-warn" : "is-danger");
  view.append(grade);
  view.append(el("p", "sub", securityPosture.summary));

  if (securityPosture.checks.length > 0) {
    const wrap = el("div", "data-table-wrap");
    const table = el("table", "data-table");
    const head = el("tr", "");
    head.append(el("th", "", "Control"), el("th", "", "Status"));
    const thead = el("thead", "");
    thead.append(head);
    const tbody = el("tbody", "");
    for (const check of securityPosture.checks) {
      const tr = el("tr", "");
      tr.append(cell(check.name));
      const status = el("td", "");
      status.append(el("span", check.passed ? "status-badge is-ok" : "status-badge is-warn", check.passed ? "Passed" : "Look"));
      tr.append(status);
      tbody.append(tr);
    }
    table.append(thead, tbody);
    wrap.append(table);
    view.append(wrap);
  }

  const prompts: { text: string; label: string; run: () => void }[] =
    securityPosture.remediations.length > 0
      ? securityPosture.remediations.map((rem) => ({
          text: rem.alias !== undefined && rem.alias !== "" ? `${rem.title} (${rem.alias})` : rem.title,
          label: rem.action === "enable-warden" ? "Open Warden" : rem.action === "rotate-stale" ? "Open Vault" : "Open Policies",
          run: () => {
            if (rem.action === "enable-warden") openSettings("warden");
            else if (rem.action === "rotate-stale") openView("vault");
            else openView("policies");
          },
        }))
      : [
          { text: "Review the ceilings agents are allowed to use.", label: "Open Policies", run: () => { openView("policies"); } },
          { text: "Turn the warden on, or change the model.", label: "Open Warden", run: () => { openSettings("warden"); } },
          { text: "Rotate a credential that has been sitting unused.", label: "Open Vault", run: () => { openView("vault"); } },
        ];
  view.append(el("div", "data-table-caption", "Do next"));
  for (const prompt of prompts) {
    const line = el("p", "posture-prompt");
    line.append(document.createTextNode(prompt.text));
    const link = el("button", "text-action", prompt.label) as HTMLButtonElement;
    link.type = "button";
    link.addEventListener("click", prompt.run);
    line.append(link);
    view.append(line);
  }
}


function render(): void {
  const lockHeaderBtn = document.querySelector<HTMLButtonElement>("#lock-session-btn");
  if (lockHeaderBtn !== null) {
    lockHeaderBtn.hidden = !(canLockSessionNow(localAuthStatus) && !vaultLocked);
  }
  const view = mustElement("#view");
  // Capture the audit filter caret before the old input is discarded, so
  // a poll re-render can restore focus and selection exactly.
  const oldFilter = document.querySelector<HTMLInputElement>("#audit-filter");
  if (oldFilter !== null && document.activeElement === oldFilter) {
    auditFilterWasFocused = true;
    auditFilterSelectionStart = oldFilter.selectionStart;
    auditFilterSelectionEnd = oldFilter.selectionEnd;
  }
  if (settingsOpen) {
    const liveKey = document.querySelector<HTMLInputElement>("#warden-key-input");
    if (liveKey !== null) settingsKeyDraft = liveKey.value;
  }
  if (currentView === "settings") {
    settingsOpen = true;
    currentView = "policies";
  }
  if (vaultLocked) settingsOpen = false;
  const page: Exclude<ViewName, "settings"> =
    currentView === "vault" || currentView === "audit" || currentView === "policies" || currentView === "posture" ? currentView : "approval";
  const title = document.querySelector("#view-title");
  if (title !== null) title.textContent = vaultLocked ? "Locked" : VIEW_TITLE[page];
  view.replaceChildren();
  if (vaultLocked) {
    view.replaceChildren();
    const lockScreen = el("div", "lock-screen");
    lockScreen.style.display = "flex";
    lockScreen.style.flexDirection = "column";
    lockScreen.style.alignItems = "center";
    lockScreen.style.justifyContent = "center";
    lockScreen.style.padding = "60px 20px";
    lockScreen.style.textAlign = "center";

    const lockIcon = el("div", "lock-icon");
    lockIcon.append(lockSvg());

    const helloOn = isBiometricsActive(localAuthStatus);
    const lockTitle = el("h2", "", "Vault Locked");
    const lockSub = el(
      "p",
      "sub",
      helloOn
        ? "Confirm with Windows Hello. MetaVault never sees that PIN."
        : "Session locked due to inactivity. Enter your PIN to resume.",
    );
    lockSub.style.marginBottom = "24px";

    const errorP = el("p", "vault-modal-error");
    errorP.hidden = true;
    lockScreen.append(lockIcon, lockTitle, lockSub, errorP);

    let pinInput: HTMLInputElement | null = null;
    if (helloOn) {
      const helloBtn = el("button", "action btn-approve", "Unlock with Windows Hello") as HTMLButtonElement;
      helloBtn.type = "button";
      helloBtn.style.padding = "8px 24px";
      helloBtn.addEventListener("click", () => {
        void (async () => {
          helloBtn.disabled = true;
          const res = await window.metavault.verifyWindowsHello("unlock");
          if (res.ok) {
            vaultLocked = false;
            lastUserActivityTs = Date.now();
            render();
            return;
          }
          errorP.textContent = "Windows Hello was not confirmed.";
          errorP.hidden = false;
          helloBtn.disabled = false;
        })();
      });
      lockScreen.append(helloBtn);
    }
    if (localAuthStatus.configured) {
      const field = document.createElement("input");
      pinInput = field;
      field.className = "vault-input";
      field.type = "password";
      field.placeholder = helloOn ? "App PIN fallback" : "Enter PIN to unlock";
      field.style.maxWidth = "240px";
      field.style.textAlign = "center";
      field.style.margin = helloOn ? "16px 0" : "0 0 16px";

      const unlockBtn = el("button", "action", "Unlock with app PIN") as HTMLButtonElement;
      unlockBtn.type = "button";
      unlockBtn.style.padding = "8px 24px";
      if (!helloOn) unlockBtn.classList.add("btn-approve");

      const doUnlock = async () => {
        const pin = field.value.trim();
        if (!pin) return;
        unlockBtn.disabled = true;
        try {
          const res = (await window.metavault.verifyLocalPin(pin)) as { ok?: boolean } | null;
          if (res?.ok) {
            vaultLocked = false;
            lastUserActivityTs = Date.now();
            render();
          } else {
            errorP.textContent = "Incorrect PIN.";
            errorP.hidden = false;
            unlockBtn.disabled = false;
            field.value = "";
            field.focus();
          }
        } catch {
          errorP.textContent = "Verification error.";
          errorP.hidden = false;
          unlockBtn.disabled = false;
        }
      };

      unlockBtn.addEventListener("click", () => { void doUnlock(); });
      field.addEventListener("keydown", (event) => {
        if (event.key === "Enter") void doUnlock();
      });
      lockScreen.append(field, unlockBtn);
    }
    view.append(lockScreen);
    view.querySelectorAll("h1").forEach((node) => {
      node.setAttribute("aria-hidden", "true");
    });
    paintSettingsModal();
    paintApprovalDialog();
    syncChrome();
    const pinField = pinInput;
    if (!helloOn && pinField !== null) {
      setTimeout(() => { pinField.focus(); }, 50);
    }
    return;
  }

  showBanner(notice);
  if (page === "approval") {
    renderApproval(view);
  } else if (page === "vault") {
    renderVault(view);
  } else if (page === "audit") {
    renderAudit(view);
  } else if (page === "posture") {
    renderPosture(view);

  } else {
    renderPolicies(view);
  }
  view.querySelectorAll("h1").forEach((node) => {
    node.setAttribute("aria-hidden", "true");
  });
  paintSettingsModal();
  paintApprovalDialog();
  syncChrome();
}

async function refresh(): Promise<void> {
  try {
    const [pendingRaw, aliasesRaw, auditRaw, policiesRaw, wardenRaw, wardenKeyRaw, postureRaw, localAuthRaw, secRaw] = await Promise.all([
      window.metavault.pending(),
      window.metavault.aliases(),
      window.metavault.audit(),
      window.metavault.policies(),
      window.metavault.getWardenSettings().catch(() => null),
      window.metavault.wardenKeyStatus().catch(() => null),
      window.metavault.getSecurityPosture().catch(() => null),
      window.metavault.getLocalAuthStatus().catch(() => null),
      window.metavault.getAgentSecuritySettings().catch(() => null),
    ]);
    
    if (secRaw !== null && typeof secRaw === "object") {
      const s = secRaw as Record<string, unknown>;
      agentSecuritySettings = {
        strictMode: Boolean(s["strictMode"]),
        verifyCallerProcess: Boolean(s["verifyCallerProcess"]),
      };
    }
    const nextApprovals = projectPendingResponse(pendingRaw);
    const incoming = sortApprovals(nextApprovals.filter((item) => !knownGrantIds.has(item.grantId)));
    knownGrantIds = new Set(nextApprovals.map((a) => a.grantId));
    if (incoming.length > 0) {
      approvalDialogDismissed = false;
      const soonest = incoming[0];
      if (soonest !== undefined) {
        selectedGrantId = soonest.grantId;
      }
      window.metavault.bringToFront();
    }
    approvals = nextApprovals;
    aliases = projectAliasesResponse(aliasesRaw);
    credentialMeta = projectCredentialsResponse(aliasesRaw);
    auditEvents = projectAuditResponse(auditRaw);
    policiesData = projectPoliciesResponse(policiesRaw);
    securityPosture = projectSecurityPosture(postureRaw);
    const projAuth = projectLocalAuthStatus(localAuthRaw);
    if (projAuth !== null) {
      if (!initialAuthChecked) {
        initialAuthChecked = true;
        if (shouldLockOnLaunch(projAuth)) {
          vaultLocked = true;
        }
      }
      localAuthStatus = projAuth;
    }
    if (isAutoLockDue(localAuthStatus, lastUserActivityTs, Date.now()) && !vaultLocked) {
      vaultLocked = true;
    }
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
  document.body.classList.toggle("is-simple-mode", uiMode === "simple");  window.metavault.onDeeplinkAdd((params) => {
    // Sequenced by runDeeplinkAddFlow: the prefilled Add modal opens only
    // after the Vault render (and any refresh already in flight) has fully
    // completed, replacing any modal that is open. A failure surfaces in
    // the banner instead of silently leaving no modal.
    void runDeeplinkAddFlow(params, {
      switchToVault: () => {
        settingsOpen = false;
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
  const versionNode = document.querySelector("#app-version");
  if (versionNode !== null) versionNode.textContent = `v${APP_VERSION_DISPLAY}`;
  const scroller = document.querySelector("#view");
  scroller?.addEventListener("scroll", () => {
    if (scroller instanceof HTMLElement) {
      document.querySelector(".app-header")?.classList.toggle("is-scrolled", scroller.scrollTop > 8);
    }
  });
  document.querySelector("#open-settings")?.addEventListener("click", () => {
    openSettings();
  });
  document.querySelector("#settings-close")?.addEventListener("click", () => {
    closeSettings();
  });
  document.querySelector("#settings-modal")?.addEventListener("click", (event) => {
    if (event.target === event.currentTarget) closeSettings();
  });
  document.querySelectorAll<HTMLButtonElement>(".settings-tab").forEach((button) => {
    button.addEventListener("click", () => {
      const next = button.dataset["settingsTab"];
      if (next === "general" || next === "warden" || next === "daemon" || next === "security") {
        settingsTab = next;
        applySettingsTab();
      }
    });
  });
  window.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && credentialModal === null) {
      if (document.querySelector("#approval-dialog") !== null) {
        dismissApprovalDialog();
        return;
      }
      if (settingsOpen) closeSettings();
    }
  });
  document.querySelectorAll<HTMLButtonElement>(".nav-btn").forEach((button) => {
    button.addEventListener("click", () => {
      const next = button.dataset["view"];
      if (next === "settings") {
        openSettings();
        return;
      }
      if (next === "approval" || next === "vault" || next === "audit" || next === "policies" || next === "posture") {
        openView(next);
      }
    });
  });
  const lockHeaderBtn = document.querySelector<HTMLButtonElement>("#lock-session-btn");
  if (lockHeaderBtn !== null) {
    lockHeaderBtn.addEventListener("click", () => {
      vaultLocked = true;
      render();
    });
  }
  void refreshTracked();
  if (typeof window.metavault.onBuiltinAiProgress === "function") {
    window.metavault.onBuiltinAiProgress((progress) => {
      builtinAiProgress = progress;
      if (progress.state === "completed" || progress.state === "idle") {
        void window.metavault.getBuiltinAiStatus().then((s) => {
          builtinAiStatus = s;
          render();
        });
      } else {
        render();
      }
    });
  }
  if (typeof window.metavault.onUpdaterStatus === "function") {
    window.metavault.onUpdaterStatus((status) => {
      updaterStatus = status;
      render();
    });
  }
  window.setInterval(() => {
    void refreshTracked();
  }, POLL_MS);
  window.setInterval(tickExpiryLabels, 1_000);
}

start();
function createMetaLogo(): HTMLElement {
  const container = el("span", "bft-logo-wrapper");
  container.innerHTML = '<svg viewBox="0 0 24 24" width="22" height="22" aria-label="Meta"><path fill="#0668E1" d="M16.99 6.06c-1.89 0-3.52.9-4.99 2.56C10.53 6.96 8.9 6.06 7.01 6.06 3.64 6.06 1 8.87 1 12.44c0 3.54 2.59 6.27 5.92 6.27 1.94 0 3.64-.95 5.08-2.67 1.44 1.72 3.14 2.67 5.08 2.67 3.33 0 5.92-2.73 5.92-6.27 0-3.57-2.64-6.38-6.01-6.38zm0 10.28c-1.42 0-2.67-.84-3.8-2.57 1.09-1.68 2.29-2.52 3.8-2.52 1.94 0 3.48 1.48 3.48 3.54 0 2.07-1.54 3.55-3.48 3.55zm-9.98 0c-1.94 0-3.48-1.48-3.48-3.55 0-2.06 1.54-3.54 3.48-3.54 1.51 0 2.71.84 3.8 2.52-1.13 1.73-2.38 2.57-3.8 2.57z"/></svg>';
  return container;
}



