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
  shouldRequireAuthForApproval,
  shouldRequireAuthForSettings,
  isAutoLockDue,
  canLockSessionNow,
  parseDotEnvWithInference,
  type DotEnvImportItem,
} from "./model.js";
import type {
  AuditEventLike,
  CredentialMeta,
  DeeplinkAddParams,
  PendingApproval,
  PoliciesData,
  SecurityPostureReportLike,
  LocalAuthStatusLike,
  UpdaterStatusLike,
  WardenKeyStatusLike,
  WardenSettingsLike,
} from "./types.js";

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
let updaterStatus: UpdaterStatusLike = { status: "idle" };

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
    const executeApproval = () => {
      void runAction(() => window.openvault.approve(hero.grantId), "Approved — the grant executed inside vaultd and expired.");
    };
    if (shouldRequireAuthForApproval(localAuthStatus, hero.allowedScope, hero.risk)) {
      promptVerifyPin("Authenticate to approve capability", executeApproval);
    } else {
      executeApproval();
    }
  });
  const denyBtn = el("button", "action btn-deny", "Deny") as HTMLButtonElement;
  denyBtn.type = "button";
  denyBtn.disabled = busy;
  denyBtn.addEventListener("click", () => {
    void runAction(() => window.openvault.deny(hero.grantId), "Denied — the agent was told no, with the allowed ceiling.");
  });
  const blockBtn = el("button", "action btn-deny", "Block agent") as HTMLButtonElement;
  blockBtn.type = "button";
  blockBtn.disabled = busy;
  blockBtn.title = `Block ${hero.agentId} and cancel all its pending requests`;
  blockBtn.addEventListener("click", () => {
    void runAction(
      () => window.openvault.revoke(hero.agentId),
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
  if (localAuthStatus.biometricEnabled) {
    const bioBtn = el("button", "vault-btn vault-btn-ghost", "Use Windows Hello / Touch ID") as HTMLButtonElement;
    bioBtn.style.marginRight = "auto";
    bioBtn.addEventListener("click", () => {
      void (async () => {
        try {
          const res = (await window.openvault.verifyBiometric()) as { ok?: boolean } | null;
          if (res?.ok) {
            close();
            onVerified();
          } else {
            errorBox.textContent = "Biometric authentication failed. Please enter PIN.";
            errorBox.hidden = false;
          }
        } catch {
          errorBox.textContent = "Biometric authentication error.";
          errorBox.hidden = false;
        }
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
      const res = (await window.openvault.verifyLocalPin(pin)) as { ok?: boolean } | null;
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

  const sub = el("p", "vault-modal-sub", "Configure a 4-8 digit numeric or alphanumeric PIN for protecting your local vault sessions.");
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
      const res = (await window.openvault.setLocalPin(newPin, curInput?.value.trim())) as { ok?: boolean } | null;
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
    const table = el("table", "audit-table");
    table.style.width = "100%";
    table.style.fontSize = "12px";

    const thead = el("thead", "");
    const headerRow = el("tr", "");
    const thCheck = el("th", "", "Use");
    const thKey = el("th", "", "Variable");
    const thAlias = el("th", "", "Inferred Alias");
    const thScope = el("th", "", "Ceiling Scope");
    const thSecret = el("th", "", "Secret");
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
      aliasInp.style.padding = "2px 6px";
      aliasInp.style.fontSize = "11px";
      aliasInp.value = item.alias;
      aliasInp.addEventListener("input", () => {
        item.alias = aliasInp.value.trim();
      });
      tdAlias.append(aliasInp);

      const tdScope = el("td", "");
      const scopeInp = document.createElement("input");
      scopeInp.className = "vault-input";
      scopeInp.style.padding = "2px 6px";
      scopeInp.style.fontSize = "11px";
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
          await window.openvault.addCredential(
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
  headerRow.append(el("h1", "vault-title", "Agent credentials"));

  const actionGroup = el("div", "vault-header-actions");
  actionGroup.style.display = "flex";
  actionGroup.style.gap = "8px";
  actionGroup.style.alignItems = "center";

  const importBtn = el("button", "action btn-import-dotenv", "Import .env") as HTMLButtonElement;
  importBtn.type = "button";
  importBtn.style.padding = "5px 12px";
  importBtn.style.fontSize = "12px";
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

  const controls = el("div", "audit-controls");

  // Search input row
  const searchRow = el("div", "audit-search-row");
  const searchInput = document.createElement("input");
  searchInput.id = "audit-filter";
  searchInput.className = "audit-search-input";
  searchInput.type = "text";
  searchInput.placeholder = "Search requests by agent, alias, scope, outcome, or details (e.g. agent:cursor, outcome:denied)...";
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

  const list = el("div", "rows");
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

    for (const group of paginated.items) {
      const verdict = wardenVerdict(group);
      const expanded = expandedAuditIds.has(group.requestId);
      const node = el("article", "row audit-row");
      const summary = el("div", "audit-summary");
      const allowedText = group.allowedScope ?? "—";
      const scopeText =
        group.requestedScope !== "" && group.requestedScope !== allowedText
          ? `${group.requestedScope} → ${allowedText}`
          : allowedText || group.requestedScope;

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
        if (group.agentId !== "human") {
          const blockAgentBtn = el("button", "action btn-deny", `Block ${group.agentId}`) as HTMLButtonElement;
          blockAgentBtn.type = "button";
          blockAgentBtn.disabled = busy;
          blockAgentBtn.style.marginTop = "10px";
          blockAgentBtn.addEventListener("click", () => {
            void runAction(
              () => window.openvault.revoke(group.agentId),
              `Blocked ${group.agentId} — pending grants cancelled, all future requests denied.`,
            );
          });
          timeline.append(blockAgentBtn);
        }
        node.append(timeline);
      }
      list.append(node);
    }

    // Pagination controls bar
    const paginationBar = el("div", "pagination-bar");
    const info = el(
      "div",
      "pagination-info",
      `Showing ${String(paginated.startIndex)}–${String(paginated.endIndex)} of ${String(paginated.totalItems)} requests`,
    );

    const controlsGroup = el("div", "pagination-controls");

    const prevBtn = el("button", "pagination-btn", "‹ Previous") as HTMLButtonElement;
    prevBtn.type = "button";
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

    const nextBtn = el("button", "pagination-btn", "Next ›") as HTMLButtonElement;
    nextBtn.type = "button";
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

  // 0. Interface Mode (Verbose vs Simple)
  const modeSection = settingsSection("Interface mode", "Choose between a simplified, minimal UI and the full security-first interface.");
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
    const doSave = () => {
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
    };
    if (shouldRequireAuthForSettings(localAuthStatus)) {
      promptVerifyPin("Authenticate to modify settings", doSave);
    } else {
      doSave();
    }
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
    const doSaveKey = () => {
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
    };
    if (shouldRequireAuthForSettings(localAuthStatus)) {
      promptVerifyPin("Authenticate to save key", doSaveKey);
    } else {
      doSaveKey();
    }
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
    const doDeleteKey = () => {
      void runSettingsAction(async () => {
        const raw = await window.openvault.deleteWardenKey();
        const projected = projectWardenKeyStatus(raw);
        wardenKeyStatusState = projected ?? { configured: false, last4: null };
        settingsKeyDraft = "";
        settingsMessage = { text: "Meta API key deleted.", ok: true };
      });
    };
    if (shouldRequireAuthForSettings(localAuthStatus)) {
      promptVerifyPin("Authenticate to delete key", doDeleteKey);
    } else {
      doDeleteKey();
    }
  });
  keyBtns.append(saveKeyBtn, testBtn, deleteKeyBtn);
  keySection.append(keyBtns);
  keySection.append(el("p", "settings-copy", "Test connection runs one metadata-only warden self-check through vaultd using the saved provider and model (save settings changes first to test them). It creates no grants and writes no audit entries."));
  view.append(keySection);

  if (settingsMessage !== null) {
    const msg = el("p", settingsMessage.ok ? "settings-message is-ok" : "settings-message is-error", settingsMessage.text);
    view.append(msg);
  }

  // 4b. Local authentication & security gates (#19)
  const authSection = settingsSection(
    "Local authentication & security gates",
    "Additional layers of local protection (PIN, biometrics, auto-lock) to secure your workstation against unauthorized physical access. (All protection layers are off by default).",
  );

  const authStatusP = el(
    "p",
    "settings-status",
    `Status: ${localAuthStatus.enabled ? "Active" : "Disabled"} · ${
      localAuthStatus.configured ? "PIN configured" : "No PIN set"
    }${localAuthStatus.biometricEnabled ? " · Biometrics ready" : ""}`,
  );
  authSection.append(authStatusP);

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
    if (authToggle.checked && shouldPromptPinSetupOnEnable(localAuthStatus)) {
      openPinModal(() => {
        void runSettingsAction(async () => {
          const raw = await window.openvault.updateLocalAuthSettings({ enabled: true });
          const projected = projectLocalAuthStatus(raw);
          if (projected !== null) localAuthStatus = projected;
          render();
        });
      });
      authToggle.checked = false;
      return;
    }
    void runSettingsAction(async () => {
      const raw = await window.openvault.updateLocalAuthSettings({ enabled: authToggle.checked });
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
        const raw = await window.openvault.updateLocalAuthSettings({ requireOnLaunch: launchToggle.checked });
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
        const raw = await window.openvault.updateLocalAuthSettings({ requireOnApproval: apprToggle.checked });
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
        const raw = await window.openvault.updateLocalAuthSettings({ requireOnSettings: settingsToggle.checked });
        const projected = projectLocalAuthStatus(raw);
        if (projected !== null) localAuthStatus = projected;
      });
    });
    settingsRow.append(settingsLabel, settingsToggle);
    authSection.append(settingsRow);

    // 4. Windows Hello / Touch ID biometrics
    const bioRow = el("div", "settings-row");
    const bioLabel = el(
      "span",
      "settings-row-label",
      "Enable Windows Hello / Touch ID biometrics (Off by default)",
    );
    const bioToggle = document.createElement("input");
    bioToggle.type = "checkbox";
    bioToggle.checked = localAuthStatus.biometricEnabled;
    bioToggle.addEventListener("change", () => {
      void runSettingsAction(async () => {
        const raw = await window.openvault.updateLocalAuthSettings({ biometricEnabled: bioToggle.checked });
        const projected = projectLocalAuthStatus(raw);
        if (projected !== null) localAuthStatus = projected;
      });
    });
    bioRow.append(bioLabel, bioToggle);
    authSection.append(bioRow);

    // 5. Inactivity Auto-Lock
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
        const raw = await window.openvault.updateLocalAuthSettings({ autoLockMinutes: mins });
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

  authSection.append(authBtns);
  view.append(authSection);

  // 5. Daemon (read-only)
  const daemonSection = settingsSection("Daemon", "");
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

  if (activeAgentTab === "claude") {
    configPath = ".mcp.json in workspace or ~/.claude.json";
    codeSnippet = JSON.stringify(
      {
        mcpServers: {
          metavault: {
            command: "node",
            args: ["<path-to-repo>/dist/packages/mcp/src/server.js"],
            env: {
              OPENVAULT_DAEMON_URL: "http://127.0.0.1:7077",
              OPENVAULT_AGENT_ID: "claude-code",
              OPENVAULT_IDE: "Claude Code",
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
              OPENVAULT_DAEMON_URL: "http://127.0.0.1:7077",
              OPENVAULT_AGENT_ID: "cursor",
              OPENVAULT_IDE: "Cursor",
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
              OPENVAULT_DAEMON_URL: "http://127.0.0.1:7077",
              OPENVAULT_AGENT_ID: "vscode",
              OPENVAULT_IDE: "VS Code",
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
      "OPENVAULT_DAEMON_URL = \"http://127.0.0.1:7077\"",
      "OPENVAULT_AGENT_ID = \"codex\"",
      "OPENVAULT_IDE = \"Codex\"",
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
              OPENVAULT_DAEMON_URL: "http://127.0.0.1:7077",
              OPENVAULT_AGENT_ID: "opencode",
              OPENVAULT_IDE: "OpenCode",
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
      "2. Present deeplink (openvault://add?...) to the user",
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

  // 7. Auto-updater & releases (#16)
  const updateSection = settingsSection("Auto-updater & releases", "Keep MetaVault OSS secure with signed background updates directly from GitHub Releases.");
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
    if (typeof window.openvault.checkForUpdates === "function") {
      void window.openvault.checkForUpdates();
    }
  });
  updateBtns.append(checkUpdateBtn);

  if (updaterStatus.status === "downloaded") {
    const installBtn = el("button", "action btn-always", "Restart & install update") as HTMLButtonElement;
    installBtn.type = "button";
    installBtn.addEventListener("click", () => {
      if (typeof window.openvault.quitAndInstallUpdate === "function") {
        void window.openvault.quitAndInstallUpdate();
      }
    });
    updateBtns.append(installBtn);
  }

  updateSection.append(updateBtns);
  view.append(updateSection);
}

function renderPolicies(view: HTMLElement): void {
  view.append(el("h1", "", "Policies"));
  view.append(el("p", "sub", "Deterministic ceilings are enforced inside vaultd policy; the marshal can only narrow them. Revoking an agent blocks its pending and future grants immediately."));

  if (securityPosture !== null) {
    const postureCard = el("article", "row policy-row posture-card");
    const postureHeader = el("div", "policy-card-header");
    postureHeader.append(el("span", "chain", "Security Posture"));
    const gradeBadge = el("span", "chip", `Grade ${securityPosture.grade} · Score ${String(securityPosture.score)}/100`);
    gradeBadge.style.fontWeight = "600";
    if (securityPosture.score >= 80) {
      gradeBadge.style.borderColor = "var(--teal)";
      gradeBadge.style.color = "var(--teal)";
    } else if (securityPosture.score >= 60) {
      gradeBadge.style.borderColor = "var(--warn)";
      gradeBadge.style.color = "var(--warn)";
    } else {
      gradeBadge.style.borderColor = "var(--danger)";
      gradeBadge.style.color = "var(--danger)";
    }
    postureHeader.append(gradeBadge);
    postureCard.append(postureHeader);

    const summaryPara = el("p", "sub", securityPosture.summary);
    summaryPara.style.margin = "8px 0 12px";
    postureCard.append(summaryPara);

    const checksChips = el("div", "policy-chips-group");
    checksChips.append(el("span", "policy-group-label", "Controls:"));
    for (const chk of securityPosture.checks) {
      const mark = chk.passed ? "✓ " : "✕ ";
      const chip = el("span", "chip", `${mark}${chk.name}`);
      if (chk.passed) {
        chip.style.opacity = "0.85";
      } else {
        chip.style.borderColor = "var(--warn)";
      }
      checksChips.append(chip);
    }
    postureCard.append(checksChips);

    if (securityPosture.remediations.length > 0) {
      const remContainer = el("div", "policy-caps");
      remContainer.style.marginTop = "12px";
      remContainer.style.display = "flex";
      remContainer.style.flexDirection = "column";
      remContainer.style.gap = "8px";

      for (const rem of securityPosture.remediations) {
        const remRow = el("div", "row");
        remRow.style.padding = "8px 12px";
        remRow.style.display = "flex";
        remRow.style.justifyContent = "space-between";
        remRow.style.alignItems = "center";

        const textCol = el("div", "");
        const remTitle = el("div", "chain", rem.title);
        remTitle.style.fontSize = "13px";
        const remDesc = el("div", "when", rem.alias ? `Applies to alias: ${rem.alias}` : `Target: ${rem.target ?? "System policy"}`);
        textCol.append(remTitle, remDesc);

        const fixBtn = el("button", "action", "Resolve") as HTMLButtonElement;
        fixBtn.type = "button";
        fixBtn.style.padding = "4px 12px";
        fixBtn.addEventListener("click", () => {
          if (rem.action === "enable-warden") {
            currentView = "settings";
            document.querySelectorAll(".nav-btn").forEach((b) => {
              b.classList.toggle("is-active", (b as HTMLElement).dataset["view"] === "settings");
            });
            render();
          } else if (rem.action === "rotate-stale") {
            currentView = "vault";
            document.querySelectorAll(".nav-btn").forEach((b) => {
              b.classList.toggle("is-active", (b as HTMLElement).dataset["view"] === "vault");
            });
            render();
          } else {
            showBanner(`Inspect policy rules below to fix: ${rem.title}`);
          }
        });

        remRow.append(textCol, fixBtn);
        remContainer.append(remRow);
      }
      postureCard.append(remContainer);
    }

    view.append(postureCard);
  }

  const rows = buildPolicyRows(auditEvents, policiesData);
  const ceilingEntries = Object.entries(policiesData.ceilings).sort(([a], [b]) =>
    a.localeCompare(b),
  );
  if (rows.length === 0 && ceilingEntries.length === 0) {
    view.append(el("div", "empty", "No agent activity yet. Agents appear here after their first request."));
    return;
  }
  if (ceilingEntries.length > 0) {
    const caps = el("div", "rows policy-caps");
    const capsNode = el("article", "row");
    capsNode.append(el("div", "chain", "Enforced ceilings (per alias)"));
    const capChips = el("div", "policy-chips-group");
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
    const main = el("div", "policy-card-main");

    // Header: agentId + meta horizontally distributed
    const head = el("div", "policy-card-header");
    head.append(el("span", "chain", row.agentId));
    head.append(el("span", "policy-card-meta", `${String(row.requestCount)} requests · last seen ${formatLastUsed(row.lastSeenTs, Date.now())}`));
    main.append(head);

    // Horizontal chips group
    const chipsGroup = el("div", "policy-chips-group");
    chipsGroup.append(el("span", "policy-group-label", "Observed:"));
    if (row.scopes.length === 0) {
      chipsGroup.append(el("span", "chip", "none"));
    } else {
      for (const scope of row.scopes) {
        chipsGroup.append(el("span", "chip", scope));
      }
    }

    if (row.ceilings.length > 0) {
      chipsGroup.append(el("span", "policy-group-label", "Ceilings:"));
      for (const entry of row.ceilings) {
        chipsGroup.append(el("span", "chip", `${entry.alias}: ${entry.ceiling}`));
      }
    }

    if (row.standingApprovals.length > 0) {
      chipsGroup.append(el("span", "policy-group-label", "Standing:"));
      for (const approval of row.standingApprovals) {
        chipsGroup.append(el("span", "chip", `${approval.alias}: ${approval.scope}`));
      }
    }
    main.append(chipsGroup);
    node.append(main);

    const revokeBtn = el("button", "action btn-revoke", "Revoke / Block") as HTMLButtonElement;
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
  if (currentView === "settings") {
    const liveKey = document.querySelector<HTMLInputElement>("#warden-key-input");
    if (liveKey !== null) settingsKeyDraft = liveKey.value;
  }
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

    const lockIcon = el("div", "lock-icon", "🔒");
    lockIcon.style.fontSize = "48px";
    lockIcon.style.marginBottom = "16px";

    const lockTitle = el("h2", "", "Vault Locked");
    const lockSub = el("p", "sub", "Session locked due to inactivity. Enter your PIN to resume.");
    lockSub.style.marginBottom = "24px";

    const pinInput = document.createElement("input");
    pinInput.className = "vault-input";
    pinInput.type = "password";
    pinInput.placeholder = "Enter PIN to unlock";
    pinInput.style.maxWidth = "240px";
    pinInput.style.textAlign = "center";
    pinInput.style.marginBottom = "16px";

    const errorP = el("p", "vault-modal-error");
    errorP.hidden = true;

    const unlockBtn = el("button", "action btn-approve", "Unlock Vault") as HTMLButtonElement;
    unlockBtn.style.padding = "8px 24px";

    const doUnlock = async () => {
      const pin = pinInput.value.trim();
      if (!pin) return;
      unlockBtn.disabled = true;
      try {
        const res = (await window.openvault.verifyLocalPin(pin)) as { ok?: boolean } | null;
        if (res?.ok) {
          vaultLocked = false;
          lastUserActivityTs = Date.now();
          render();
        } else {
          errorP.textContent = "Incorrect PIN.";
          errorP.hidden = false;
          unlockBtn.disabled = false;
          pinInput.value = "";
          pinInput.focus();
        }
      } catch {
        errorP.textContent = "Verification error.";
        errorP.hidden = false;
        unlockBtn.disabled = false;
      }
    };

    unlockBtn.addEventListener("click", () => { void doUnlock(); });
    pinInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void doUnlock();
    });

    lockScreen.append(lockIcon, lockTitle, lockSub, errorP, pinInput, unlockBtn);
    if (localAuthStatus.biometricEnabled) {
      const bioBtn = el("button", "vault-btn vault-btn-ghost", "Use Windows Hello / Touch ID") as HTMLButtonElement;
      bioBtn.style.marginTop = "12px";
      bioBtn.addEventListener("click", () => {
        void (async () => {
          try {
            const res = (await window.openvault.verifyBiometric()) as { ok?: boolean } | null;
            if (res?.ok) {
              vaultLocked = false;
              lastUserActivityTs = Date.now();
              render();
            } else {
              errorP.textContent = "Biometric check failed. Enter PIN to unlock.";
              errorP.hidden = false;
            }
          } catch {
            errorP.textContent = "Biometric check failed. Enter PIN to unlock.";
            errorP.hidden = false;
          }
        })();
      });
      lockScreen.append(bioBtn);
    }
    view.append(lockScreen);
    setTimeout(() => { pinInput.focus(); }, 50);
    return;
  }

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
    const [pendingRaw, aliasesRaw, auditRaw, policiesRaw, wardenRaw, wardenKeyRaw, postureRaw, localAuthRaw] = await Promise.all([
      window.openvault.pending(),
      window.openvault.aliases(),
      window.openvault.audit(),
      window.openvault.policies(),
      window.openvault.getWardenSettings().catch(() => null),
      window.openvault.wardenKeyStatus().catch(() => null),
      window.openvault.getSecurityPosture().catch(() => null),
      window.openvault.getLocalAuthStatus().catch(() => null),
    ]);
    const nextApprovals = projectPendingResponse(pendingRaw);
    const hasNewApproval = nextApprovals.some((a) => !knownGrantIds.has(a.grantId));
    knownGrantIds = new Set(nextApprovals.map((a) => a.grantId));
    if (hasNewApproval && nextApprovals.length > 0) {
      currentView = "approval";
      document.querySelectorAll<HTMLElement>(".nav-btn").forEach((b) => {
        b.classList.toggle("is-active", b.dataset["view"] === "approval");
      });
      window.openvault.bringToFront();
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
  document.body.classList.toggle("is-simple-mode", uiMode === "simple");  window.openvault.onDeeplinkAdd((params) => {
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
  const lockHeaderBtn = document.querySelector<HTMLButtonElement>("#lock-session-btn");
  if (lockHeaderBtn !== null) {
    lockHeaderBtn.addEventListener("click", () => {
      vaultLocked = true;
      render();
    });
  }
  void refreshTracked();
  if (typeof window.openvault.onUpdaterStatus === "function") {
    window.openvault.onUpdaterStatus((status) => {
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
