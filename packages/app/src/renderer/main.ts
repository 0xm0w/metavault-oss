import { buildAgentInstructions, type AgentInstructionsContext } from "./onboarding.js";
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
  isCardFormComplete,
  parseCardExpiry,
  cardLabel,
  marshalStatusLine,
  normalizeWebsite,
  projectAliasesResponse,
  projectAgentsResponse,
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
  DEFAULT_META_API_MODEL_ID,
  DEFAULT_WARDEN_SETTINGS,
  EFFORT_OPTIONS,
  LOCAL_API_OPTIONS,
  SUGGESTED_LOCAL_BASE_URL,
  SUGGESTED_LOCAL_MODEL,
  VAULT_PATH_DISPLAY,
  WARDEN_PROVIDERS,
  buildWardenPatch,
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
  projectDevicesResponse,
  projectPairingSession,
  projectRemoteSettings,
  projectSshTunnelResult,
  projectSshTunnelStatus,
  shouldRequireAuthForApproval,
  shouldRequireAuthForRemoteApproval,
  shouldRequireAuthForSettings,
  isAutoLockDue,
  canLockSessionNow,
  parseDotEnvWithInference,
  type DotEnvImportItem,
  MIN_PASSPHRASE_LENGTH,
  keyGateErrorMessage,
  passphraseSetupError,
  projectKeyGate,
  type KeyGate,
  isSettingsTab,
  mcpStatusText,
  projectMcpStatus,
  type McpStatus,
  type SettingsTab,} from "./model.js";
import type {
  AgentSecuritySettingsLike,
  DeviceLike,
  PresenceProofRequestLike,
  PairingSessionLike,
  RemoteSettingsLike,
  SshTunnelSetupProposalLike,
  SshTunnelStatusLike,
  RegisteredAgent,
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
let agentsData: RegisteredAgent[] = [];
interface PendingRegistration { readonly id: string; readonly agentId: string; readonly name: string; readonly ide: string; readonly code: string }
let pendingRegistrations: PendingRegistration[] = [];
let registrationError = "";
let queuedDeeplink: DeeplinkAddParams | null = null;
let openQueuedDeeplink: (() => void) | null = null;
const registrationDrafts = new Map<string, string>();
const newAgentTokens = new Map<string, string>();
let mcpRuntime: { command: string; args: string[]; env: Record<string, string>; dbPath: string } | null = null;
let mcpStatus: McpStatus | null = null;
// Wizard inline Meta API key form (step 2). The key itself is only ever
// sent to the daemon; the draft is cleared on save.
let wizardKeyDraft = "";
let wizardKeyMessage: { text: string; ok: boolean } | null = null;
let wizardKeyBusy = false;

function agentInstructionsContext(): AgentInstructionsContext | null {
  if (mcpRuntime === null) return null;
  return { daemonUrl: DAEMON_URL_DISPLAY, command: mcpRuntime.command, args: mcpRuntime.args, env: mcpRuntime.env, dbPath: mcpRuntime.dbPath };
}
let remoteSettings: RemoteSettingsLike | null = null;
let devicesData: DeviceLike[] = [];
let pairingSession: PairingSessionLike | null = null;
let pairingCode: string | null = null;
let pairingNotice: { text: string; ok: boolean } | null = null;
let sshTunnel: SshTunnelStatusLike | null = null;
let sshSetupStep: "address" | "verify" | "install" | null = null;
let sshSetupProposal: SshTunnelSetupProposalLike | null = null;
let sshSetupError: string | null = null;
let sshRemoveArmedUntil = 0;
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
let keyGate: KeyGate = null;
let vaultKeyFingerprint: string | null = null;
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
let wardenKeyStatusState: WardenKeyStatusLike = { configured: false };
let wardenLoaded = false;
let wardenDirty = false;
let settingsKeyDraft = "";
let settingsBusy = false;
let settingsMessage: { readonly text: string; readonly ok: boolean } | null = null;
let localAuthNotice: { readonly text: string; readonly ok: boolean } | null = null;
let updaterStatus: UpdaterStatusLike = { status: "idle" };

let settingsPending: "test" | null = null;
let daemonDetailsOpen = false;
let agentAdvancedOpen = false;
let lockedSettingsOpen = false;
const sessionBlockedAgents = new Set<string>();

let settingsOpen = false;
let settingsTab: SettingsTab = "general";
let settingsFocusOnOpen = false;

const SETTINGS_TAB_LABEL: Record<SettingsTab, string> = {
  general: "General",
  warden: "Warden",
  daemon: "Daemon",
  security: "Security",
  connections: "Connections",
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
      line.textContent = "Marshal \u00B7 Meta Family of AIs \u00B7 Dual-Warden BFT";
    } else {
      line.textContent =
        wardenDraft.localModel.trim() !== "" && wardenDraft.localBaseUrl.trim() !== ""
          ? `Marshal \u00B7 ${wardenDraft.localModel} \u00B7 Your local endpoint`
          : "Marshal \u00B7 Local endpoint not set \u00B7 Requests come to you";
    }
    return;
  }
  const fromPending = approvals.find((a) => a.modelId !== undefined)?.modelId;
  const fromAudit = auditEvents.find((e) => e.modelId !== undefined)?.modelId;
  mustElement("#marshal-line").textContent = marshalStatusLine(fromPending ?? fromAudit);
}

// One revoke path for the Policies and Audit views. A registered agent has a
// stored token, so the token itself is disabled (persisted, rejects every
// later call, clears pending requests and standing approvals). The session
// block on top of that also stops self-reported calls under the same id. An
// id with no registered token can only be blocked for this vaultd session.
// The UI claims success only after the agent list confirms it.
function revokeAgentFlow(agentId: string): void {
  if (busy) return;
  const registered = agentsData.find((agent) => agent.id === agentId);
  const hasToken = registered !== undefined && !registered.revoked;
  const prompt = hasToken
    ? `Revoke ${agentId}? Its token stops working, and its pending requests and standing approvals are cancelled.`
    : `Block ${agentId}? It has no registered token to revoke, so this blocks the name only until vaultd restarts.`;
  if (!window.confirm(prompt)) return;
  const act = (): void => {
    void runAction(async () => {
      if (hasToken) await window.metavault.revokeAgent(agentId);
      await window.metavault.revoke(agentId);
      if (registered !== undefined) {
        const listed = projectAgentsResponse(await window.metavault.agents());
        if (listed.find((agent) => agent.id === agentId)?.revoked !== true) {
          throw new Error(`Could not confirm that ${agentId} is revoked. Its token may still work.`);
        }
        agentsData = listed;
      } else {
        sessionBlockedAgents.add(agentId);
      }
    }, registered !== undefined
      ? `Revoked ${agentId}. Its token is disabled; pending requests and standing approvals are cancelled.`
      : `Blocked ${agentId} until vaultd restarts. It had no token to revoke.`);
  };
  if (shouldRequireAuthForSettings(localAuthStatus)) void confirmLocalPresence("Authenticate to revoke agent", act);
  else act();
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
  if (hero.origin === "remote") {
    const remoteBox = el("div", "alert is-warn");
    remoteBox.style.marginBottom = "0.75rem";
    const deviceLabel = hero.deviceId !== undefined ? `device ${hero.deviceId}` : "an unknown device";
    const transportLabel = hero.transport !== undefined && hero.transport !== "" ? hero.transport : "remote";
    remoteBox.textContent = `Remote request: this came from ${deviceLabel} over the ${transportLabel} transport, not from a local agent. The same vault policy applies, and approval executes inside vaultd as usual.`;
    card.append(remoteBox);
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
    const executeApproval = (presenceProof?: string) => {
      void runAction(() => window.metavault.approve(hero.grantId, presenceProof), "Approved — the grant executed inside vaultd and expired.");
    };
    if (shouldRequireAuthForRemoteApproval(remoteSettings, hero)) {
      obtainPresenceProof({ scope: "approve", grantId: hero.grantId }, (token) => { executeApproval(token); });
    } else if (shouldRequireAuthForApproval(localAuthStatus, hero.allowedScope, hero.risk)) {
      void confirmLocalPresence("Authenticate to approve capability", () => { executeApproval(); });
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
      const executeAlways = (presenceProof?: string) => {
        void runAction(
          () => window.metavault.approveAlways(hero.grantId, presenceProof),
          `Standing approval saved for ${hero.agentId} · ${hero.allowedScope}. Read-only low-risk only; writes still ask every time.`,
        );
      };
      if (shouldRequireAuthForRemoteApproval(remoteSettings, hero)) {
        obtainPresenceProof({ scope: "approve", grantId: hero.grantId }, (token) => { executeAlways(token); });
      } else {
        executeAlways();
      }
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
  const hero = vaultLocked || keyGate !== null || approvalDialogDismissed || currentView === "approval" ? null : selectedApproval();
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

  // Credential type. A payment card is validated (Luhn, expiry, CVV) and
  // encrypted by the daemon; this window only ever gets brand + last 4
  // back, and every use of the card needs a human approval.
  const kindWrap = el("label", "vault-field");
  kindWrap.append(el("span", "vault-field-label", "Type"));
  const kindSelect = document.createElement("select");
  kindSelect.className = "vault-input";
  for (const [value, text] of [
    ["secret", "API key / token"],
    ["card", "Payment card"],
  ] as const) {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = text;
    kindSelect.append(opt);
  }
  kindWrap.append(kindSelect);
  dialog.append(kindWrap);
  if (prefill !== undefined) {
    kindWrap.hidden = true;
  }

  const nameInput = makeField("Name", "text", "Stripe", "off");
  const scopeInput = makeField("Scope", "text", "charges.read", "off");
  const secretInput = makeField("Value", "password", "Credential value", "new-password");
  const cardNumberInput = makeField("Card number", "password", "4242 4242 4242 4242", "new-password");
  const cardNameInput = makeField("Name on card", "text", "Ada Lovelace", "off");
  const cardExpiryInput = makeField("Expiry (MM/YY)", "text", "12/29", "off");
  const cardCvvInput = makeField("CVV", "password", "123", "new-password");
  cardNumberInput.inputMode = "numeric";
  cardCvvInput.inputMode = "numeric";
  const websiteInput = makeField("Website", "text", "cloudflare.com", "off");
  const secretFields = [scopeInput, secretInput];
  const cardFields = [cardNumberInput, cardNameInput, cardExpiryInput, cardCvvInput];
  const isCard = (): boolean => kindSelect.value === "card";
  const syncKind = (): void => {
    for (const input of secretFields) {
      (input.parentElement as HTMLElement).hidden = isCard();
    }
    for (const input of cardFields) {
      (input.parentElement as HTMLElement).hidden = !isCard();
      if (!isCard()) {
        input.value = "";
      }
    }
    title.textContent = isCard() ? "Add payment card" : "Add credential";
  };
  syncKind();
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

  const formComplete = (): boolean =>
    isCard()
      ? isCardFormComplete(nameInput.value, cardNumberInput.value, cardNameInput.value, cardExpiryInput.value, cardCvvInput.value)
      : isCredentialFormComplete(nameInput.value, scopeInput.value, secretInput.value);
  const syncSave = (): void => {
    saveBtn.disabled = !formComplete();
  };
  for (const input of [nameInput, scopeInput, secretInput, ...cardFields]) {
    input.addEventListener("input", syncSave);
  }
  kindSelect.addEventListener("change", () => {
    syncKind();
    syncSave();
  });

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
        const expiry = parseCardExpiry(cardExpiryInput.value);
        if (isCard() && expiry !== null) {
          await window.metavault.addCard(
            nameInput.value.trim(),
            {
              number: cardNumberInput.value,
              name: cardNameInput.value.trim(),
              expMonth: expiry.expMonth,
              expYear: expiry.expYear,
              cvv: cardCvvInput.value.trim(),
            },
            websiteInput.value.trim(),
          );
          for (const input of cardFields) {
            input.value = "";
          }
        } else {
          await window.metavault.addCredential(
            nameInput.value.trim(),
            scopeInput.value.trim(),
            secretInput.value,
            websiteInput.value.trim(),
            prefill?.enrollmentId,
          );
        }
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
          : message.includes("CardInvalid")
            ? "That card did not validate (check the number, expiry and CVV)."
            : message.includes("VaultLocked")
              ? "The vault is locked. Run `metavault unlock` and try again."
              : message;
        errorBox.hidden = false;
        saveBtn.disabled = !formComplete();
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

// Remote approvals and weakening the remote-presence setting require a
// single-use proof issued by the main process after a REAL PIN check.
// Windows Hello is deliberately NOT accepted for remote approvals: its
// daemon-side result is caller-attested, so it cannot prove presence to
// the vault. No configured PIN means no proof: fail closed, visibly.
function obtainPresenceProof(req: PresenceProofRequestLike, onToken: (token: string) => void): void {
  if (!localAuthStatus.configured) {
    notice = "Set an app PIN in Settings before approving remote requests. Windows Hello alone cannot authorize them.";
    render();
    return;
  }
  if (credentialModal !== null) return;
  const overlay = el("div", "vault-modal-overlay");
  const dialog = el("div", "vault-modal");
  dialog.style.maxWidth = "400px";
  const header = el("div", "vault-modal-header");
  header.append(el("h2", "vault-modal-title", "Approve a remote request"));
  const closeBtn = el("button", "vault-modal-close", "\u00D7") as HTMLButtonElement;
  header.append(closeBtn);
  dialog.append(header);
  dialog.append(el("p", "vault-modal-sub", "This request came from a paired device. Enter your vault PIN to approve it."));
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
  const close = () => {
    credentialModal = null;
    overlay.remove();
  };
  cancelBtn.addEventListener("click", close);
  closeBtn.addEventListener("click", close);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) close();
  });
  const submit = () => {
    const pin = input.value.trim();
    if (pin === "") return;
    confirmBtn.disabled = true;
    void (async () => {
      try {
        const { token } = await window.metavault.requestPresenceProof({ ...req, pin });
        close();
        onToken(token);
      } catch {
        errorBox.textContent = "PIN not verified.";
        errorBox.hidden = false;
        confirmBtn.disabled = false;
        input.value = "";
        input.focus();
      }
    })();
  };
  confirmBtn.addEventListener("click", submit);
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") submit();
  });
  actions.append(cancelBtn, confirmBtn);
  dialog.append(actions);
  overlay.append(dialog);
  credentialModal = overlay;
  document.body.append(overlay);
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
    if (card.card !== undefined) {
      const badge = el("span", "vault-muted", ` \u00B7 ${cardLabel(card.card)} \u00B7 approval every use`);
      aliasMain.append(badge);
    }
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
          blockAgentBtn.addEventListener("click", () => { revokeAgentFlow(group.agentId); });
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

// --- Remote connection (app-managed SSH tunnel) ---------------------------

let sshSetupExpectedFingerprint = "";

function sshTunnelStateLabel(t: SshTunnelStatusLike): string {
  switch (t.state) {
    case "not-configured": return "Not set up";
    case "off": return "Off";
    case "connecting": return "Connecting";
    case "connected": return "Connected";
    case "reconnecting": return t.attempts !== undefined ? `Reconnecting (attempt ${String(t.attempts)})` : "Reconnecting";
    case "error": return "Error";
  }
}

function sshTunnelBadge(t: SshTunnelStatusLike): HTMLElement {
  const badge = el("span", "status-badge", sshTunnelStateLabel(t));
  if (t.state === "connected") badge.classList.add("is-ok");
  if (t.state === "connecting" || t.state === "reconnecting") badge.classList.add("is-warn");
  if (t.state === "error") badge.classList.add("is-danger");
  return badge;
}

function sshErrorText(reason: string | undefined): string {
  switch (reason) {
    case "auth-failed": return "The server refused the key. Check that the line above is in the server's authorized_keys, then verify again.";
    case "forward-refused": return "The server accepted the key but refused the port forwards. The relay ports may be in use, or the key's restrictions do not allow them.";
    case "gateway-down": return "The local gateway is not running. Turn on remote access above, then try again.";
    case "host-key-changed": return "The server's host key no longer matches. Nothing was saved.";
    default: return "The server did not confirm the connection in time. Check that it is reachable.";
  }
}

function applySshStatusResult(raw: unknown): void {
  const result = projectSshTunnelResult(raw);
  if (result !== null && result.kind === "status" && result.status !== undefined) {
    sshTunnel = result.status;
  }
}

function resetSshSetup(): void {
  sshSetupStep = null;
  sshSetupProposal = null;
  sshSetupError = null;
  sshSetupExpectedFingerprint = "";
}

function renderSshSetupWizard(section: HTMLElement): void {
  const stepTitle = sshSetupStep === "address"
    ? "Step 1 of 3: Server address"
    : sshSetupStep === "verify"
      ? "Step 2 of 3: Verify the host key"
      : "Step 3 of 3: Install the key";
  section.append(el("p", "settings-copy", stepTitle));

  if (sshSetupStep === "address") {
    section.append(el("p", "settings-copy", "Enter the SSH server this vault should dial out to. You control this server; the app never picks or rents one for you."));
    const addrRow = el("div", "settings-row");
    addrRow.append(el("span", "settings-row-label", "Server"));
    const addrInput = el("input", "vault-input") as HTMLInputElement;
    addrInput.placeholder = "user@relay.example.com[:22]";
    addrInput.maxLength = 320;
    addrInput.style.maxWidth = "52%";
    addrInput.setAttribute("aria-label", "SSH server address");
    addrRow.append(addrInput);
    section.append(addrRow);
    const portsRow = el("div", "settings-row");
    portsRow.append(el("span", "settings-row-label", "Relay ports (pairing, devices)"));
    const portsBox = el("span", "settings-row-value");
    const pairInput = el("input", "vault-input") as HTMLInputElement;
    pairInput.value = "7078";
    pairInput.maxLength = 5;
    pairInput.style.width = "72px";
    pairInput.setAttribute("aria-label", "Relay pairing port");
    const devInput = el("input", "vault-input") as HTMLInputElement;
    devInput.value = "7080";
    devInput.maxLength = 5;
    devInput.style.width = "72px";
    devInput.style.marginLeft = "6px";
    devInput.setAttribute("aria-label", "Relay device port");
    portsBox.append(pairInput, devInput);
    portsRow.append(portsBox);
    section.append(portsRow);
    if (sshSetupError !== null) section.append(el("p", "alert is-warn", sshSetupError));
    const btns = el("div", "settings-btns");
    const cancelBtn = el("button", "action", "Cancel") as HTMLButtonElement;
    cancelBtn.type = "button";
    cancelBtn.disabled = settingsBusy;
    cancelBtn.addEventListener("click", () => {
      void window.metavault.sshTunnelCancelSetup().catch(() => undefined);
      resetSshSetup();
      render();
    });
    const continueBtn = el("button", "action btn-approve", "Continue") as HTMLButtonElement;
    continueBtn.type = "button";
    continueBtn.disabled = settingsBusy;
    continueBtn.addEventListener("click", () => {
      const address = addrInput.value;
      const pairPort = Number(pairInput.value);
      const devPort = Number(devInput.value);
      void runSettingsAction(async () => {
        const raw = await window.metavault.sshTunnelBeginSetup({
          address,
          ...(Number.isInteger(pairPort) ? { remotePairingPort: pairPort } : {}),
          ...(Number.isInteger(devPort) ? { remoteDevicePort: devPort } : {}),
        });
        const result = projectSshTunnelResult(raw);
        if (result !== null && result.kind === "proposal" && result.proposal !== undefined) {
          sshSetupProposal = result.proposal;
          sshSetupError = null;
          sshSetupStep = "verify";
        } else {
          sshSetupError = result !== null && result.kind === "error" && result.error !== undefined
            ? result.error
            : "Setup could not start.";
        }
      });
    });
    btns.append(cancelBtn, continueBtn);
    section.append(btns);
    return;
  }

  if (sshSetupStep === "verify" && sshSetupProposal !== null) {
    const proposal = sshSetupProposal;
    section.append(el("p", "settings-copy", `The server at ${proposal.user}@${proposal.host}:${String(proposal.port)} presented this ${proposal.keyType} host key:`));
    const fpBox = el("p", "mono");
    fpBox.style.overflowWrap = "anywhere";
    fpBox.style.userSelect = "text";
    fpBox.textContent = proposal.fingerprint;
    section.append(fpBox);
    section.append(el("p", "settings-copy", "Check this against the fingerprint your server provider shows (or run ssh-keygen -lf on the server's host key). Paste the provider's fingerprint here to confirm. A mismatch cancels setup and saves nothing."));
    const fpRow = el("div", "settings-row");
    fpRow.append(el("span", "settings-row-label", "Provider fingerprint"));
    const fpInput = el("input", "vault-input") as HTMLInputElement;
    fpInput.placeholder = "SHA256:...";
    fpInput.maxLength = 128;
    fpInput.style.maxWidth = "52%";
    fpInput.setAttribute("aria-label", "Expected host key fingerprint");
    fpRow.append(fpInput);
    section.append(fpRow);
    if (sshSetupError !== null) section.append(el("p", "alert is-warn", sshSetupError));
    const btns = el("div", "settings-btns");
    const backBtn = el("button", "action", "Back") as HTMLButtonElement;
    backBtn.type = "button";
    backBtn.disabled = settingsBusy;
    backBtn.addEventListener("click", () => { sshSetupError = null; sshSetupStep = "address"; render(); });
    const confirmBtn = el("button", "action btn-approve", "Confirm fingerprint") as HTMLButtonElement;
    confirmBtn.type = "button";
    confirmBtn.disabled = settingsBusy;
    confirmBtn.addEventListener("click", () => {
      if (fpInput.value.trim() === "") {
        sshSetupError = "Paste the fingerprint from your server provider to continue.";
        render();
        return;
      }
      sshSetupExpectedFingerprint = fpInput.value.trim();
      sshSetupError = null;
      sshSetupStep = "install";
      render();
    });
    btns.append(backBtn, confirmBtn);
    section.append(btns);
    return;
  }

  if (sshSetupStep === "install" && sshSetupProposal !== null) {
    const proposal = sshSetupProposal;
    section.append(el("p", "settings-copy", `Two pieces go on ${proposal.host}. Both are verified before setup finishes; setup refuses to finish if either is missing or the account is not locked down.`));
    section.append(el("p", "settings-copy", `1. Add this line to ~/.ssh/authorized_keys for ${proposal.user}. It restricts the key to exactly the two loopback forwards this tunnel needs - no shell, no file access, no pty.`));
    const lineBox = el("p", "mono");
    lineBox.style.overflowWrap = "anywhere";
    lineBox.style.userSelect = "text";
    lineBox.style.fontSize = "11px";
    lineBox.textContent = proposal.installLine;
    section.append(lineBox);
    section.append(el("p", "settings-copy", "2. Add this block to the server's /etc/ssh/sshd_config (or a file in sshd_config.d), then reload sshd. Per-key options cannot genuinely block local port forwarding; this server policy can. Finish verifies it live."));
    const policyBox = el("p", "mono");
    policyBox.style.overflowWrap = "anywhere";
    policyBox.style.userSelect = "text";
    policyBox.style.fontSize = "11px";
    policyBox.style.whiteSpace = "pre-wrap";
    policyBox.textContent = proposal.policyBlock;
    section.append(policyBox);
    section.append(el("p", "settings-copy", "Cancel discards the local key and saves nothing. To undo later: remove both on the server and use Remove connection here."));
    if (sshSetupError !== null) section.append(el("p", "alert is-warn", sshSetupError));
    const btns = el("div", "settings-btns");
    const backBtn = el("button", "action", "Back") as HTMLButtonElement;
    backBtn.type = "button";
    backBtn.disabled = settingsBusy;
    backBtn.addEventListener("click", () => { sshSetupError = null; sshSetupStep = "verify"; render(); });
    const finishBtn = el("button", "action btn-approve", "Key installed - verify and finish") as HTMLButtonElement;
    finishBtn.type = "button";
    finishBtn.disabled = settingsBusy;
    finishBtn.addEventListener("click", () => {
      void runSettingsAction(async () => {
        const raw = await window.metavault.sshTunnelCompleteSetup(sshSetupExpectedFingerprint);
        const result = projectSshTunnelResult(raw);
        if (result === null) {
          sshSetupError = "Unexpected response from the app.";
          return;
        }
        if (result.kind === "error") {
          // Fingerprint mismatch or stale setup: back to the verify step.
          sshSetupError = result.error ?? "Setup failed.";
          sshSetupStep = "verify";
          return;
        }
        if (result.kind === "verification" && result.verified) {
          resetSshSetup();
          settingsMessage = { text: "Remote connection is set up. Press Connect to start the tunnel.", ok: true };
          await refresh();
          return;
        }
        if (result.kind === "verification") {
          sshSetupError = sshErrorText(result.reason);
          await refresh();
          return;
        }
        sshSetupError = "Setup failed.";
      });
    });
    btns.append(backBtn, finishBtn);
    section.append(btns);
  }
}

function renderSshTunnelSection(view: HTMLElement): void {
  const section = settingsSection(
    "Remote connection",
    "Reach this vault from anywhere through an SSH server you control: this PC dials out and forwards the two loopback gateway ports to the server's own loopback. Nothing new listens on your network.",
    "connections",
  );

  if (sshTunnel === null) {
    section.append(el("p", "settings-copy", "Remote connection is unavailable in this build."));
    view.append(section);
    return;
  }
  const t = sshTunnel;

  const statusRow = el("div", "settings-row");
  statusRow.append(el("span", "settings-row-label", "Status"));
  statusRow.append(sshTunnelBadge(t));
  section.append(statusRow);

  if (t.state === "not-configured") {
    if (sshSetupStep === null) {
      section.append(el("p", "settings-copy", "One-time setup: paste the server address, confirm its host key fingerprint, install the shown key on the server."));
      const setupBtn = el("button", "action btn-approve", "Set up remote connection") as HTMLButtonElement;
      setupBtn.type = "button";
      setupBtn.disabled = settingsBusy;
      setupBtn.addEventListener("click", () => {
        resetSshSetup();
        sshSetupStep = "address";
        render();
      });
      section.append(setupBtn);
    } else {
      renderSshSetupWizard(section);
    }
    view.append(section);
    return;
  }

  // Configured states share the server/fingerprint rows.
  const serverRow = el("div", "settings-row");
  serverRow.append(el("span", "settings-row-label", "Server"));
  const serverValue = `${t.user ?? ""}@${t.host ?? ""}${t.port !== undefined && t.port !== 22 ? `:${String(t.port)}` : ""}`;
  const serverText = el("span", "mono settings-row-value", serverValue);
  serverText.title = serverValue;
  serverRow.append(serverText);
  section.append(serverRow);

  if (t.fingerprint !== undefined) {
    const fpRow = el("div", "settings-row");
    fpRow.append(el("span", "settings-row-label", "Host key"));
    const fpText = el("span", "mono settings-row-value", `${t.fingerprint.slice(0, 23)}...`);
    fpText.title = t.fingerprint;
    fpRow.append(fpText);
    const fpCopy = el("button", "action", "Copy") as HTMLButtonElement;
    fpCopy.title = `Copy full host key fingerprint: ${t.fingerprint}`;
    fpCopy.setAttribute("aria-label", "Copy full host key fingerprint");
    fpCopy.addEventListener("click", () => {
      void navigator.clipboard.writeText(t.fingerprint ?? "").then(() => {
        fpCopy.textContent = "Copied";
        setTimeout(() => { fpCopy.textContent = "Copy"; }, 1500);
      });
    });
    fpRow.append(fpCopy);
    section.append(fpRow);
  }

  if (t.state === "connected" && t.connectedSince !== undefined) {
    const sinceRow = el("div", "settings-row");
    sinceRow.append(el("span", "settings-row-label", "Connected since"));
    sinceRow.append(el("span", "settings-row-value", t.connectedSince.replace("T", " ").slice(0, 19)));
    section.append(sinceRow);
  }

  if (t.state === "error" && t.detail !== undefined) {
    section.append(el("p", "alert is-warn", t.detail));
  }

  if (t.state === "off" || t.state === "error" || t.state === "connected") {
    const autoRow = el("div", "settings-row");
    autoRow.append(el("span", "settings-row-label", "Automatic reconnect"));
    const autoBtn = el("button", "action", t.autoReconnect === false ? "Off" : "On") as HTMLButtonElement;
    autoBtn.type = "button";
    autoBtn.disabled = settingsBusy;
    autoBtn.title = "Reconnect automatically if the tunnel drops, with bounded retries.";
    autoBtn.addEventListener("click", () => {
      void runSettingsAction(async () => {
        applySshStatusResult(await window.metavault.sshTunnelSetAutoReconnect(t.autoReconnect === false));
      });
    });
    autoRow.append(autoBtn);
    section.append(autoRow);
  }

  const btns = el("div", "settings-btns");
  if (t.state === "off" || t.state === "error") {
    const connectBtn = el("button", "action btn-approve", t.state === "error" ? "Try again" : "Connect") as HTMLButtonElement;
    connectBtn.type = "button";
    connectBtn.disabled = settingsBusy;
    connectBtn.addEventListener("click", () => {
      void runSettingsAction(async () => {
        applySshStatusResult(await window.metavault.sshTunnelConnect());
      });
    });
    btns.append(connectBtn);
    const removeBtn = el("button", "action btn-deny", sshRemoveArmedUntil > Date.now() ? "Click again to remove" : "Remove connection") as HTMLButtonElement;
    removeBtn.type = "button";
    removeBtn.disabled = settingsBusy;
    removeBtn.title = "Deletes the pinned host key, this PC's keypair and the saved server. Also delete the key line on the server.";
    removeBtn.addEventListener("click", () => {
      if (sshRemoveArmedUntil <= Date.now()) {
        sshRemoveArmedUntil = Date.now() + 5000;
        render();
        return;
      }
      sshRemoveArmedUntil = 0;
      void runSettingsAction(async () => {
        applySshStatusResult(await window.metavault.sshTunnelRemove());
        resetSshSetup();
      });
    });
    btns.append(removeBtn);
  }
  if (t.state === "connecting" || t.state === "reconnecting" || t.state === "connected") {
    const disconnectBtn = el("button", "action btn-deny", t.state === "connected" ? "Disconnect" : "Cancel") as HTMLButtonElement;
    disconnectBtn.type = "button";
    disconnectBtn.disabled = settingsBusy;
    disconnectBtn.addEventListener("click", () => {
      void runSettingsAction(async () => {
        applySshStatusResult(await window.metavault.sshTunnelDisconnect());
      });
    });
    btns.append(disconnectBtn);
  }
  if (btns.childElementCount > 0) section.append(btns);

  if (t.state === "off" && remoteSettings !== null && !remoteSettings.enabled) {
    section.append(el("p", "settings-copy", "Turn on remote access above before connecting; the tunnel forwards its gateway."));
  }

  section.append(el("p", "settings-copy",
    "Connected means the tunnel is up. It grants no capabilities by itself: requests still come only from paired devices, policy decides what is allowed, and your PIN is asked when a remote request needs your approval. This PC must stay awake with MetaVault running for the tunnel to stay up. This section shows only the host address, its fingerprint and connection state; keys stay as files on disk."));

  view.append(section);
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

  // 1. Provider
  const providerSection = settingsSection("Warden provider", "", "warden");
  const providerCopy: Record<WardenSettingsLike["provider"], string> = {
    "meta-api": "The default: Muse Spark 1.3 on the Meta Model API. Needs your Meta API key. Nothing to download.",
    local: "Bring your own: point MetaVault at an Ollama or OpenAI-compatible server you already run, and name the model. A Meta open model such as Muse Glimmer is recommended. MetaVault does not download or run the model for you.",
    bft: "Two wardens: Muse Spark on the Meta API, cross-checked by your local endpoint if you set one. If they disagree, the request comes to you.",
    none: "No model judges requests. Deterministic policy alone decides, and anything needing approval comes to you.",
  };
  const providerLabel = el("label", "vault-field");
  providerLabel.append(el("span", "vault-field-label", "Provider"));
  const providerSelect = document.createElement("select");
  providerSelect.className = "vault-input";
  providerSelect.id = "warden-provider-select";
  for (const provider of WARDEN_PROVIDERS) {
    const opt = document.createElement("option");
    opt.value = provider.id;
    opt.textContent = provider.label;
    providerSelect.append(opt);
  }
  providerSelect.value = wardenDraft.provider;
  providerSelect.addEventListener("change", () => {
    const chosen = WARDEN_PROVIDERS.find((provider) => provider.id === providerSelect.value);
    if (chosen === undefined) return;
    wardenDraft = { ...wardenDraft, provider: chosen.id };
    wardenDirty = true;
    settingsMessage = null;
    render();
  });
  providerLabel.append(providerSelect);
  providerSection.append(providerLabel);
  providerSection.append(el("p", "settings-copy", providerCopy[wardenDraft.provider]));
  view.append(providerSection);

  const textField = (
    id: string,
    labelText: string,
    value: string,
    placeholder: string,
    onInput: (value: string) => void,
  ): HTMLLabelElement => {
    const fieldLabel = el("label", "vault-field") as HTMLLabelElement;
    fieldLabel.append(el("span", "vault-field-label", labelText));
    const input = document.createElement("input");
    input.className = "vault-input";
    input.id = id;
    input.type = "text";
    input.value = value;
    input.placeholder = placeholder;
    input.autocomplete = "off";
    input.spellcheck = false;
    input.addEventListener("input", () => {
      onInput(input.value);
      wardenDirty = true;
      const save = document.querySelector<HTMLButtonElement>("#warden-save-button");
      if (save !== null) save.disabled = settingsBusy || !isWardenFormComplete(wardenDraft);
    });
    fieldLabel.append(input);
    return fieldLabel;
  };

  const appendMetaApiFields = (section: HTMLElement): void => {
    const selectLabel = el("label", "vault-field");
    selectLabel.append(el("span", "vault-field-label", "Meta API model"));
    const select = document.createElement("select");
    select.className = "vault-input";
    select.id = "warden-meta-model-select";
    for (const option of META_API_MODEL_OPTIONS) {
      const opt = document.createElement("option");
      opt.value = option.id;
      opt.textContent = option.label;
      select.append(opt);
    }
    const current = wardenDraft.model.trim() !== "" ? wardenDraft.model : DEFAULT_META_API_MODEL_ID;
    if (!isKnownMetaApiModel(current)) {
      const custom = document.createElement("option");
      custom.value = current;
      custom.textContent = `${current} \u2014 Custom`;
      select.append(custom);
    }
    select.value = current;
    select.addEventListener("change", () => {
      wardenDraft = { ...wardenDraft, model: select.value };
      wardenDirty = true;
      render();
    });
    selectLabel.append(select);
    section.append(selectLabel);
    section.append(
      textField("warden-model-input", "Meta API model id (free text)", wardenDraft.model, DEFAULT_META_API_MODEL_ID, (v) => {
        wardenDraft = { ...wardenDraft, model: v };
      }),
    );
    section.append(
      textField("warden-base-url-input", "Meta API base URL", wardenDraft.metaApiBaseUrl, DEFAULT_WARDEN_SETTINGS.metaApiBaseUrl, (v) => {
        wardenDraft = { ...wardenDraft, metaApiBaseUrl: v };
      }),
    );
  };

  const appendLocalEndpointFields = (section: HTMLElement, optional: boolean): void => {
    section.append(
      el(
        "p",
        "settings-copy",
        optional
          ? "Optional second warden: your own local endpoint. Leave the base URL empty to use the Meta API alone."
          : "Your own local endpoint. MetaVault sends only request metadata (never secrets) to the URL you set. If it is not reachable, requests come to you for approval.",
      ),
    );
    const apiLabel = el("label", "vault-field");
    apiLabel.append(el("span", "vault-field-label", "API style"));
    const apiSelect = document.createElement("select");
    apiSelect.className = "vault-input";
    apiSelect.id = "warden-local-api-select";
    for (const option of LOCAL_API_OPTIONS) {
      const opt = document.createElement("option");
      opt.value = option.id;
      opt.textContent = option.label;
      apiSelect.append(opt);
    }
    apiSelect.value = wardenDraft.localApi;
    apiSelect.addEventListener("change", () => {
      wardenDraft = { ...wardenDraft, localApi: apiSelect.value === "openai" ? "openai" : "ollama" };
      wardenDirty = true;
      render();
    });
    apiLabel.append(apiSelect);
    section.append(apiLabel);
    section.append(
      textField(
        "warden-local-base-url-input",
        "Base URL",
        wardenDraft.localBaseUrl,
        SUGGESTED_LOCAL_BASE_URL[wardenDraft.localApi],
        (v) => {
          wardenDraft = { ...wardenDraft, localBaseUrl: v };
        },
      ),
    );
    section.append(
      textField("warden-local-model-input", "Model name", wardenDraft.localModel, SUGGESTED_LOCAL_MODEL, (v) => {
        wardenDraft = { ...wardenDraft, localModel: v };
      }),
    );
    section.append(
      el(
        "p",
        "settings-copy",
        `We recommend a Meta open model such as Muse Glimmer (for example ${SUGGESTED_LOCAL_MODEL} in Ollama). Any model your server can run works.`,
      ),
    );
  };

  // 2. Model
  const modelSection = settingsSection("Model", "", "warden");
  if (wardenDraft.provider === "none") {
    modelSection.append(el("p", "settings-copy", "No model \u2014 policy only. Choose the Meta API or your local endpoint to enable a warden model."));
  } else if (wardenDraft.provider === "meta-api") {
    appendMetaApiFields(modelSection);
  } else if (wardenDraft.provider === "local") {
    appendLocalEndpointFields(modelSection, false);
  } else {
    const card = el("div", "bft-card");
    const head = el("div", "bft-head");
    const info = el("div", "");
    info.append(el("div", "bft-title", "Meta Dual-Warden BFT Consensus"));
    info.append(el("div", "bft-desc", "Muse Spark on the Meta API judges each request. If you set a local endpoint, it judges too, and any disagreement sends the request to you."));
    head.append(info);
    card.append(head);
    const pillars = el("div", "bft-pillars");
    const metaPillar = el("div", "bft-pillar-item");
    metaPillar.append(createMetaLogo());
    const metaDetails = el("div", "bft-pillar-details");
    metaDetails.append(el("div", "bft-pillar-title", `Meta API: ${wardenDraft.model.trim() !== "" ? wardenDraft.model : DEFAULT_META_API_MODEL_ID}`));
    metaDetails.append(el("div", "bft-pillar-sub", "Cloud warden"));
    metaPillar.append(metaDetails);
    const localPillar = el("div", "bft-pillar-item");
    localPillar.append(createMetaLogo());
    const localDetails = el("div", "bft-pillar-details");
    const localSet = wardenDraft.localBaseUrl.trim() !== "" && wardenDraft.localModel.trim() !== "";
    localDetails.append(el("div", "bft-pillar-title", localSet ? `Your endpoint: ${wardenDraft.localModel}` : "Your endpoint: not set"));
    localDetails.append(el("div", "bft-pillar-sub", localSet ? wardenDraft.localBaseUrl : "Optional"));
    localPillar.append(localDetails);
    pillars.append(metaPillar, localPillar);
    card.append(pillars);
    modelSection.append(card);
    appendMetaApiFields(modelSection);
    appendLocalEndpointFields(modelSection, true);
  }
  view.append(modelSection);

  // 3. Effort
  const effortSection = settingsSection("Effort", "", "warden");
  const effortLabel = el("label", "vault-field");
  effortLabel.append(el("span", "vault-field-label", "Effort"));
  const effortSelect = document.createElement("select");
  effortSelect.className = "vault-input";
  effortSelect.id = "warden-effort-select";
  for (const option of EFFORT_OPTIONS) {
    const opt = document.createElement("option");
    opt.value = option.id;
    opt.textContent = option.label;
    effortSelect.append(opt);
  }
  effortSelect.value = wardenDraft.effort;
  effortSelect.addEventListener("change", () => {
    const chosen = EFFORT_OPTIONS.find((option) => option.id === effortSelect.value);
    if (chosen === undefined) return;
    wardenDraft = { ...wardenDraft, effort: chosen.id };
    wardenDirty = true;
    settingsMessage = null;
    render();
  });
  effortLabel.append(effortSelect);
  effortSection.append(effortLabel);
  const effortCurrent = EFFORT_OPTIONS.find((option) => option.id === wardenDraft.effort);
  if (effortCurrent !== undefined) effortSection.append(el("p", "settings-copy", effortCurrent.description));
  const saveBtn = el("button", "action btn-approve", "Save settings") as HTMLButtonElement;
  saveBtn.type = "button";
  saveBtn.id = "warden-save-button";
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
  // Test connection runs against the saved key only, so it needs one.
  testBtn.disabled = settingsBusy || !wardenKeyStatusState.configured;
  if (settingsPending === "test") {
    testBtn.textContent = "";
    const spin = el("span", "spinner");
    spin.setAttribute("aria-hidden", "true");
    testBtn.append(spin, document.createTextNode("Testing\u2026"));
    testBtn.setAttribute("aria-busy", "true");
  }
  testBtn.addEventListener("click", () => {
    if (settingsBusy) return;
    settingsPending = "test";
    settingsMessage = null;
    void runSettingsAction(async () => {
     try {
      const raw = await window.metavault.testWarden();
      const projected = projectWardenTestResult(raw);
      if (projected === null) {
        settingsMessage = { text: "Warden test failed \u2014 vaultd returned an unexpected response.", ok: false };
        return;
      }
      const result = wardenTestMessage(projected);
      // A typed-but-unsaved key is not what the test used.
      const draftNote =
        settingsKeyDraft.trim() !== ""
          ? " The key typed in the field is not saved yet; this tested the saved key. Click Save key to replace it."
          : "";
      settingsMessage = { text: `${result.message}${draftNote}`, ok: result.ok };
     } finally {
      settingsPending = null;
     }
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
        wardenKeyStatusState = projected ?? { configured: false };
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
  if (settingsPending === "test") {
    const live = el("span", "visually-hidden", "Testing connection\u2026");
    live.setAttribute("role", "status");
    keyBtns.append(live);
  }
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

  // 5. Connections (remote access)
  const remoteSection = settingsSection(
    "Remote access",
    "Pair another device so its agents can request capabilities from this vault over mutual TLS. Remote access is off unless you turn it on here. Pairing and device traffic stay on this machine's loopback unless you also connect an SSH transport below.",
    "connections",
  );
  const remoteOn = remoteSettings?.enabled ?? false;
  const toggleRow = el("div", "settings-row");
  toggleRow.append(el("span", "settings-row-label", "Enable remote access"));
  const toggleBtn = el("button", "action", remoteOn ? "Turn off" : "Turn on") as HTMLButtonElement;
  toggleBtn.type = "button";
  toggleBtn.disabled = settingsBusy;
  toggleBtn.addEventListener("click", () => {
    void runSettingsAction(async () => {
      await window.metavault.updateRemoteSettings({ enabled: !remoteOn });
      pairingNotice = { text: remoteOn ? "Remote access is off. Paired devices can no longer connect." : "Remote access is on (loopback only).", ok: true };
      await refresh();
    });
  });
  toggleRow.append(toggleBtn);
  remoteSection.append(toggleRow);
  if (remoteSettings !== null) {
    const bindRow = el("div", "settings-row");
    bindRow.append(el("span", "settings-row-label", "Gateway bind"));
    bindRow.append(el("span", "mono", `${remoteSettings.host ?? "127.0.0.1"}:${String(remoteSettings.port ?? 7078)} pairing + 7080 devices`));
    remoteSection.append(bindRow);
  }
  const reauthRow = el("div", "settings-row");
  reauthRow.append(el("span", "settings-row-label", "Require app PIN for remote approvals"));
  const reauthOn = remoteSettings?.requireAuthForRemoteApproval ?? true;
  const reauthBtn = el("button", "action", reauthOn ? "On" : "Off") as HTMLButtonElement;
  reauthBtn.type = "button";
  reauthBtn.disabled = settingsBusy;
  reauthBtn.title = "When on, approving a request that arrived from a paired device asks for your app PIN first. Windows Hello cannot authorize remote approvals.";
  reauthBtn.addEventListener("click", () => {
    if (reauthOn) {
      // Weakening protection: requires fresh local presence, enforced in
      // the main process. The UI states the weakened protection plainly.
      pairingNotice = { text: "Turning this off lets paired devices get approvals without your app PIN.", ok: false };
      obtainPresenceProof({ scope: "settings-remote" }, (token) => {
        void runSettingsAction(async () => {
          await window.metavault.updateRemoteSettings({ requireAuthForRemoteApproval: false }, token);
          await refresh();
        });
      });
      return;
    }
    void runSettingsAction(async () => {
      await window.metavault.updateRemoteSettings({ requireAuthForRemoteApproval: true });
      await refresh();
    });
  });
  reauthRow.append(reauthBtn);
  remoteSection.append(reauthRow);
  view.append(remoteSection);

  renderSshTunnelSection(view);

  // Pairing flow. The code is shown once here and typed into the device
  // CLI; the SAS must then match the device screen before anything is
  // issued. There is no auto-confirm path.
  const pairSection = settingsSection(
    "Pair a new device",
    "Start pairing, enter the one-time code on the device (metavault pair), then compare the verification code shown on BOTH screens. Confirm only if they match exactly.",
    "connections",
  );
  if (!remoteOn) {
    pairSection.append(el("p", "settings-copy", "Turn on remote access above to pair a device."));
  } else if (pairingSession === null) {
    const startBtn = el("button", "action btn-approve", "Start pairing") as HTMLButtonElement;
    startBtn.type = "button";
    startBtn.disabled = settingsBusy;
    startBtn.addEventListener("click", () => {
      void runSettingsAction(async () => {
        const raw = (await window.metavault.startPairing()) as { pairingId?: string; code?: string } | null;
        pairingCode = raw !== null && typeof raw.code === "string" ? raw.code : null;
        pairingNotice = pairingCode !== null
          ? { text: "Pairing started. Enter the code on the device within 5 minutes.", ok: true }
          : { text: "Pairing failed to start.", ok: false };
        await refresh();
      });
    });
    pairSection.append(startBtn);
  } else if (pairingSession.status === "awaiting" || pairingSession.status === "created") {
    pairSection.append(el("p", "settings-copy", "Waiting for the device to join. On the other machine run: metavault pair --host <this machine>"));
    if (pairingCode !== null) {
      const codeBox = el("p", "mono");
      codeBox.style.fontSize = "1.4rem";
      codeBox.style.letterSpacing = "0.15em";
      codeBox.textContent = pairingCode;
      pairSection.append(codeBox);
    }
    const cancelBtn = el("button", "action btn-deny", "Cancel pairing") as HTMLButtonElement;
    cancelBtn.type = "button";
    cancelBtn.addEventListener("click", () => {
      void runSettingsAction(async () => {
        const id = pairingSession?.pairingId;
        if (id !== undefined) await window.metavault.cancelPairing(id);
        pairingCode = null;
        await refresh();
      });
    });
    pairSection.append(cancelBtn);
  } else if (pairingSession.status === "joined") {
    const joinedName = pairingSession.deviceName ?? "unknown device";
    const joinedPlatform = pairingSession.platform !== undefined ? ` (${pairingSession.platform})` : "";
    pairSection.append(el("p", "settings-copy", `${joinedName}${joinedPlatform} has joined. Compare the verification code below with the one on the device screen.`));
    const sasBox = el("p", "mono");
    sasBox.style.fontSize = "1.6rem";
    sasBox.style.letterSpacing = "0.12em";
    sasBox.style.textAlign = "center";
    sasBox.textContent = pairingSession.sas ?? "";
    pairSection.append(sasBox);
    const matchRow = el("div", "btns btns-wrap");
    const matchBtn = el("button", "action btn-approve", "Codes match - confirm pairing") as HTMLButtonElement;
    matchBtn.type = "button";
    matchBtn.disabled = settingsBusy || pairingSession.sas === undefined;
    matchBtn.addEventListener("click", () => {
      void runSettingsAction(async () => {
        const id = pairingSession?.pairingId;
        if (id === undefined) return;
        await window.metavault.confirmPairing(id);
        pairingCode = null;
        pairingNotice = { text: "Device paired. It can now connect over mutual TLS.", ok: true };
        await refresh();
      });
    });
    const noMatchBtn = el("button", "action btn-deny", "Codes do not match - cancel") as HTMLButtonElement;
    noMatchBtn.type = "button";
    noMatchBtn.disabled = settingsBusy;
    noMatchBtn.addEventListener("click", () => {
      void runSettingsAction(async () => {
        const id = pairingSession?.pairingId;
        if (id !== undefined) await window.metavault.cancelPairing(id);
        pairingCode = null;
        pairingNotice = { text: "Pairing canceled. Nothing was issued to the device.", ok: true };
        await refresh();
      });
    });
    matchRow.append(matchBtn, noMatchBtn);
    pairSection.append(matchRow);
  } else {
    pairSection.append(el("p", "settings-copy", `Pairing session status: ${pairingSession.status}`));
  }
  if (pairingNotice !== null) {
    pairSection.append(el("p", pairingNotice.ok ? "settings-copy" : "alert is-warn", pairingNotice.text));
  }
  view.append(pairSection);

  // Paired devices
  const devicesSection = settingsSection(
    "Paired devices",
    "A revoked device loses its certificate access and its bound agent tokens. Its subsequent requests are rejected, even on connections it already holds open; requests already executing are not cancelled retroactively.",
    "connections",
  );
  if (!remoteOn) {
    devicesSection.append(el("p", "settings-copy", "Remote access is off."));
  } else if (devicesData.length === 0) {
    devicesSection.append(el("p", "settings-copy", "No devices paired yet."));
  } else {
    for (const device of devicesData) {
      const deviceRow = el("div", "settings-row");
      const deviceLabel = device.revoked === true ? `${device.name} (revoked)` : device.name;
      deviceRow.append(el("span", "settings-row-label", deviceLabel));
      if (device.pairedAt !== undefined) {
        deviceRow.append(el("span", "settings-copy", device.pairedAt.slice(0, 10)));
      }
      if (device.revoked !== true) {
        const revokeBtn = el("button", "action btn-deny", "Revoke") as HTMLButtonElement;
        revokeBtn.type = "button";
        revokeBtn.disabled = settingsBusy;
        revokeBtn.addEventListener("click", () => {
          void runSettingsAction(async () => {
            await window.metavault.revokeDevice(device.id);
            pairingNotice = { text: `${device.name} revoked.`, ok: true };
            await refresh();
          });
        });
        deviceRow.append(revokeBtn);
      }
      devicesSection.append(deviceRow);
    }
  }
  view.append(devicesSection);

  // 6. Daemon (read-only)
  const daemonSection = settingsSection("Daemon", "", "daemon");
  const addDaemonRow = (label: string, value: string, wrap: boolean): void => {
    const row = el("div", "settings-row");
    row.append(el("span", "settings-row-label", label));
    const text = el("span", "mono settings-row-value", value);
    text.title = value;
    if (wrap) {
      text.style.whiteSpace = "normal";
      text.style.overflowWrap = "anywhere";
      text.style.userSelect = "text";
      text.tabIndex = 0;
      text.setAttribute("aria-label", `${label}: ${value}`);
    }
    row.append(text);
    daemonSection.append(row);
  };
  addDaemonRow("Version", `MetaVault OSS ${APP_VERSION_DISPLAY}`, false);
  addDaemonRow("MCP server", mcpStatusText(mcpStatus), true);
  const detailsBtn = el("button", "action btn-always", daemonDetailsOpen ? "Hide details" : "Show details") as HTMLButtonElement;
  detailsBtn.type = "button";
  detailsBtn.id = "daemon-details-toggle";
  detailsBtn.setAttribute("aria-expanded", daemonDetailsOpen ? "true" : "false");
  detailsBtn.setAttribute("aria-controls", "daemon-details");
  detailsBtn.addEventListener("click", () => {
    daemonDetailsOpen = !daemonDetailsOpen;
    render();
  });
  const detailsRow = el("div", "settings-row");
  detailsRow.append(el("span", "settings-row-label", "Connection details"), detailsBtn);
  daemonSection.append(detailsRow);
  // Display-only tidiness, not an access boundary. Tokens and keys are never
  // rendered here, expanded or not.
  if (daemonDetailsOpen) {
    const details = el("div", "");
    details.id = "daemon-details";
    daemonSection.append(details);
    const holder = daemonSection;
    const before = holder.children.length;
    addDaemonRow("Daemon URL", DAEMON_URL_DISPLAY, false);
    addDaemonRow("Vault path", mcpRuntime?.dbPath ?? VAULT_PATH_DISPLAY, true);
    addDaemonRow("Key fingerprint", vaultKeyFingerprint ?? "Unlock to verify", false);
    while (holder.children.length > before) {
      const node = holder.children[before];
      if (node === undefined) break;
      details.append(node);
    }
    daemonSection.append(el("p", "settings-copy", "Read-only. Warden settings apply on the next request, so no restart is needed after saving. If vaultd is unreachable, restart it from the terminal where it was launched, then reopen this page."));
  }
  view.append(daemonSection);

  // 5b. Agent Integration & MCP
  const agentSection = settingsSection(
    "Agent Integration & MCP",
    "Give your AI coding agent these instructions. Policy and your approval still decide every request.",
    "daemon",
  );

  const instructionsBtn = el("button", "action btn-approve", "Copy agent instructions") as HTMLButtonElement;
  instructionsBtn.type = "button";
  instructionsBtn.id = "copy-agent-instructions";
  instructionsBtn.addEventListener("click", () => {
    void navigator.clipboard.writeText(buildAgentInstructions(agentInstructionsContext())).then(
      () => { instructionsBtn.textContent = "Copied"; },
      () => { instructionsBtn.textContent = "Could not copy"; },
    ).finally(() => {
      window.setTimeout(() => { instructionsBtn.textContent = "Copy agent instructions"; }, 2000);
    });
  });
  agentSection.append(instructionsBtn);
  agentSection.append(el("p", "settings-copy", "For an agent running on this PC. A cloud agent connects through the Connections tab instead."));
  const advanced = document.createElement("details");
  advanced.className = "settings-advanced";
  advanced.open = agentAdvancedOpen;
  advanced.addEventListener("toggle", () => { agentAdvancedOpen = advanced.open; });
  advanced.append(el("summary", "", "Advanced: client config and agent tokens"));
  agentSection.append(advanced);
  renderAgentIntegrationBox(advanced);
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

// First-run guide. Shown on the Vault page until dismissed. It only reflects
// real state (a verified agent, a saved credential) and never claims a step
// is done that MetaVault cannot see.
// The connect-your-IDE surface: per-host tabs, one-time token generation,
// and the copyable MCP config with this installation's real paths. Shown in
// the first-run wizard and under Settings > Daemon > Agent Integration &
// MCP (Advanced), so both always offer the exact same config.
function renderAgentIntegrationBox(host: HTMLElement): void {
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
  host.append(tabsRow);

  const management = el("div", "agent-skill-box");
  management.append(el("p", "settings-copy", "Tokens are shown only when generated. Rotate to replace an existing IDE token, then update that IDE config. Rotation cancels pending requests and standing approvals. Existing configs keep working after migration until you rotate them."));
  const createControl = (id: string, name: string, rotate: boolean): void => {
    const action = () => { void runSettingsAction(async () => {
      const raw = await window.metavault.registerAgent(id, name, rotate);
      const minted = projectAgentsResponse([raw])[0];
      if (minted === undefined || minted.token === "") throw new Error("No token returned");
      newAgentTokens.set(id, minted.token);
      const listed = await window.metavault.agents();
      agentsData = projectAgentsResponse(listed);

      settingsMessage = { text: "Token generated. Copy the config now; it cannot be shown again after this app closes.", ok: true };
    }); };
    if (shouldRequireAuthForSettings(localAuthStatus)) void confirmLocalPresence("Authenticate to manage agent", action); else action();
  };
  for (const agent of agentsData) {
    const row = el("div", "btns");
    row.append(el("span", "settings-copy", `${agent.name} (${agent.id})${agent.revoked ? " - inactive" : ""}`));
    const generate = el("button", "action", agent.revoked ? "Generate token" : "Rotate token") as HTMLButtonElement;
    generate.type = "button"; generate.disabled = settingsBusy;
    generate.addEventListener("click", () => { if (agent.revoked || window.confirm(`Rotate ${agent.name}? Its old config will stop working, and pending requests and standing approvals will be cancelled.`)) createControl(agent.id, agent.name, !agent.revoked); });
    const revoke = el("button", "action btn-deny", "Revoke token") as HTMLButtonElement;
    revoke.type = "button"; revoke.disabled = settingsBusy || agent.revoked;
    revoke.addEventListener("click", () => {
      if (!window.confirm(`Revoke ${agent.name}? Its token, pending requests and standing approvals will stop working.`)) return;
      const action = () => { void runSettingsAction(async () => { await window.metavault.revokeAgent(agent.id); newAgentTokens.delete(agent.id); agentsData = projectAgentsResponse(await window.metavault.agents()); }); };
      if (shouldRequireAuthForSettings(localAuthStatus)) void confirmLocalPresence("Authenticate to revoke agent", action); else action();
    });
    row.append(generate, revoke); management.append(row);
  }
  const customId = document.createElement("input"); customId.placeholder = "Custom agent id (lowercase letters, digits, - or _)"; customId.className = "vault-input"; customId.maxLength = 64;
  const customName = document.createElement("input"); customName.placeholder = "Custom agent name"; customName.className = "vault-input"; customName.maxLength = 100;
  const addAgent = el("button", "action", "Add custom agent") as HTMLButtonElement; addAgent.type = "button"; addAgent.disabled = settingsBusy;
  addAgent.addEventListener("click", () => { createControl(customId.value.trim(), customName.value.trim(), false); });
  management.append(customId, customName, addAgent);
  for (const [id, token] of newAgentTokens) {
    if (["cursor", "claude-code", "vscode", "codex", "opencode"].includes(id)) continue;
    const once = el("pre", "", `${id}: ${token}`);
    const copy = el("button", "action", `Copy ${id} token`) as HTMLButtonElement; copy.type = "button";
    copy.addEventListener("click", () => { void navigator.clipboard.writeText(token); });
    management.append(once, copy);
  }
  host.append(management);
  const codeBox = el("div", "agent-code-block");
  let codeSnippet = "";
  let configPath = "";

  const findAgentToken = (id: string): string => {
    const found = agentsData.find((a) => a.id === id);
    return (newAgentTokens.get(id) ?? found?.token) || "<generate-or-rotate-token-in-app>";
  };

  if (activeAgentTab === "claude") {
    configPath = ".mcp.json in workspace or ~/.claude.json";
    codeSnippet = JSON.stringify(
      {
        mcpServers: {
          metavault: {
            command: mcpRuntime?.command ?? "<runtime-unavailable-reopen-app>",
            args: mcpRuntime?.args ?? [],
            env: {
              ...mcpRuntime?.env,
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
            command: mcpRuntime?.command ?? "<runtime-unavailable-reopen-app>",
            args: mcpRuntime?.args ?? [],
            env: {
              ...mcpRuntime?.env,
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
            command: mcpRuntime?.command ?? "<runtime-unavailable-reopen-app>",
            args: mcpRuntime?.args ?? [],
            env: {
              ...mcpRuntime?.env,
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
      `command = ${JSON.stringify(mcpRuntime?.command ?? "<runtime-unavailable-reopen-app>")}`,
      `args = ${JSON.stringify(mcpRuntime?.args ?? [])}`,
      "",
      "[mcp_servers.metavault.env]",
      ...Object.entries(mcpRuntime?.env ?? {}).map(([key, value]) => `${key} = ${JSON.stringify(value)}`),
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
            command: [mcpRuntime?.command ?? "<runtime-unavailable-reopen-app>", ...(mcpRuntime?.args ?? [])],
            enabled: true,
            environment: {
              ...mcpRuntime?.env,
              METAVAULT_DAEMON_URL: "http://127.0.0.1:7077",
              METAVAULT_AGENT_ID: "opencode",
              METAVAULT_AGENT_TOKEN: findAgentToken("opencode"),
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
  copyBtn.disabled = activeAgentTab !== "skill" && mcpRuntime === null;
  copyBtn.addEventListener("click", () => {
    localStorage.setItem("metavault_wizard_config_copied", "1");
    void navigator.clipboard.writeText(codeSnippet);
    copyBtn.textContent = "Copied!";
    window.setTimeout(() => {
      copyBtn.textContent = "Copy Config";
    }, 2000);
  });

  const pre = el("pre", "");
  pre.textContent = codeSnippet;
  pre.tabIndex = 0;
  pre.setAttribute("aria-label", "MCP configuration, scroll horizontally to view long lines");
  codeBox.append(copyBtn, pre);
  host.append(el("p", "settings-copy", `Configuration location: ${configPath}`));
  host.append(codeBox);
  const skillInfo = el("div", "agent-skill-box");
  skillInfo.append(el("div", "agent-skill-title", "Zero Secret Leakage Invariant"));
  skillInfo.append(
    el(
      "div",
      "agent-skill-step",
      "Secrets never pass through MCP, agents, terminal stdout, or audit trails. AI agents request scoped capabilities; vaultd holds the encrypted secrets and executes calls; the MetaVault OSS UI prompts the human for approval."
    )
  );
  host.append(skillInfo);
}

function renderWizardWardenStep(item: HTMLElement): void {
  const form = el("div", "wizard-key-form");
  const status = el("p", "settings-copy", wardenKeyStatusState.configured ? "A Meta API key is saved. Test it before connecting your IDE." : "No key saved yet.");
  form.append(status);
  const input = document.createElement("input");
  input.className = "vault-input";
  input.id = "wizard-warden-key";
  input.type = "password";
  input.placeholder = "Paste Meta API key";
  input.autocomplete = "new-password";
  input.value = wizardKeyDraft;
  input.disabled = wizardKeyBusy;
  const btns = el("div", "btns");
  const save = el("button", "action btn-approve", "Save key") as HTMLButtonElement;
  save.type = "button";
  save.id = "wizard-warden-save";
  save.disabled = wizardKeyBusy || wizardKeyDraft.trim() === "";
  input.addEventListener("input", () => {
    wizardKeyDraft = input.value;
    save.disabled = wizardKeyBusy || input.value.trim() === "";
  });
  save.addEventListener("click", () => {
    const doSave = (): void => {
      wizardKeyBusy = true;
      wizardKeyMessage = null;
      render();
      void (async () => {
        try {
          const raw = await window.metavault.setWardenKey(wizardKeyDraft);
          const projected = projectWardenKeyStatus(raw);
          if (projected !== null) wardenKeyStatusState = projected;
          wizardKeyDraft = "";
          wizardKeyMessage = { text: "Meta API key saved. It is stored encrypted and never shown again.", ok: true };
        } catch (err) {
          wizardKeyMessage = { text: err instanceof Error ? err.message : "Could not save the key", ok: false };
        } finally {
          wizardKeyBusy = false;
          render();
        }
      })();
    };
    if (shouldRequireAuthForSettings(localAuthStatus)) void confirmLocalPresence("Authenticate to save key", doSave); else doSave();
  });
  const test = el("button", "action", wizardKeyBusy ? "Testing\u2026" : "Test connection") as HTMLButtonElement;
  test.type = "button";
  test.id = "wizard-warden-test";
  test.disabled = wizardKeyBusy || !wardenKeyStatusState.configured;
  test.addEventListener("click", () => {
    wizardKeyBusy = true;
    wizardKeyMessage = null;
    render();
    void (async () => {
      try {
        const raw = await window.metavault.testWarden();
        const projected = projectWardenTestResult(raw);
        if (projected === null) {
          wizardKeyMessage = { text: "Warden test failed - vaultd returned an unexpected response.", ok: false };
        } else {
          const result = wardenTestMessage(projected);
          wizardKeyMessage = { text: result.message, ok: result.ok };
        }
      } catch (err) {
        wizardKeyMessage = { text: err instanceof Error ? err.message : "Warden test failed", ok: false };
      } finally {
        wizardKeyBusy = false;
        render();
      }
    })();
  });
  btns.append(save, test);
  form.append(input, btns);
  if (wizardKeyMessage !== null) {
    form.append(el("p", wizardKeyMessage.ok ? "settings-message is-ok" : "settings-message is-error", wizardKeyMessage.text));
  }
  form.append(el("p", "settings-copy", "The key is typed here in the app, never in a chat, is stored encrypted, and is never shown again. The test calls Meta's API once with no vault data; everything else stays local. Without a key, policy still decides every request. You can also do this later in Settings > Warden."));
  item.append(form);
}

function renderOnboardingWizard(view: HTMLElement): void {
  if (localStorage.getItem("metavault_wizard_done") === "1") {
    const show = el("button", "wizard-reopen", "Show the setup guide") as HTMLButtonElement;
    show.type = "button";
    show.addEventListener("click", () => { localStorage.removeItem("metavault_wizard_done"); render(); });
    view.prepend(show);
    return;
  }
  const card = el("section", "wizard-card");
  card.append(el("h3", "", "Get started"));
  const hasAgent = agentsData.some((agent) => !agent.revoked);
  const hasCredential = aliases.length > 0;
  const copied = localStorage.getItem("metavault_wizard_copied") === "1";
  const configCopied = localStorage.getItem("metavault_wizard_config_copied") === "1";
  const mcpReady = mcpStatus?.state === "ready";
  const steps: { title: string; body: string; done: boolean; action?: HTMLElement }[] = [
    {
      title: "MetaVault is running",
      body: mcpReady
        ? "The vault service is running locally, and the launch check confirmed the bundled MCP server answers with all 8 tools. Nothing leaves this computer."
        : mcpStatusText(mcpStatus),
      done: mcpReady,
    },
    { title: "Add your Meta API key", body: "The warden vets each agent request from metadata only. Save the key here and test it before connecting an IDE.", done: wardenKeyStatusState.configured },
    {
      title: "Connect your IDE",
      body: "Pick your IDE below, generate its token, copy the config into your IDE's MCP config file, then fully restart the IDE. This is what makes the metavault tools appear; pasting the instructions into a chat alone does not connect anything.",
      done: configCopied || hasAgent,
    },
    { title: "Copy the agent instructions", body: "Paste them into your IDE agent. They already carry this installation's local connection details and no secrets.", done: copied },
    { title: "Let your IDE register", body: "The agent shows a 6-digit code. Approve the matching request here. That makes it a Verified agent. It gives it no access to anything.", done: hasAgent },
    { title: "Add a token to test", body: "Tell your IDE: \"I will add a token to test.\" MetaVault opens in front with the secure input. Type the token here, never in the chat.", done: hasCredential },
    { title: "Check it works", body: "Ask your IDE to use that token for one read-only check, for example reading traffic for one of your sites. You approve that access separately.", done: localStorage.getItem("metavault_wizard_tested") === "1" },
  ];
  const nextIndex = steps.findIndex((step) => !step.done);
  const list = el("ol", "wizard-steps");
  steps.forEach((step, index) => {
    // A failed launch check is not "next", it needs attention first.
    const attention = index === 0 && mcpStatus?.state === "failed";
    const item = el("li", step.done ? "is-done" : attention ? "is-attention" : index === nextIndex ? "is-next" : "");
    const prefix = step.done ? "Done: " : attention ? "Attention: " : "";
    item.append(el("strong", "", `${prefix}${step.title}`), el("span", attention ? "wizard-attention-body" : "", step.body));
    if (index === 1) {
      renderWizardWardenStep(item);
    }
    if (index === 2) {
      renderAgentIntegrationBox(item);
    }
    if (index === 3) {
      const copy = el("button", "action btn-approve", copied ? "Copy again" : "Copy agent instructions") as HTMLButtonElement;
      copy.type = "button";
      copy.addEventListener("click", () => {
        void navigator.clipboard.writeText(buildAgentInstructions(agentInstructionsContext())).then(
          () => { localStorage.setItem("metavault_wizard_copied", "1"); copy.textContent = "Copied"; },
          () => { copy.textContent = "Could not copy"; },
        );
      });
      item.append(copy);
    }
    if (index === 6 && !step.done && hasCredential) {
      const mark = el("button", "action", "It worked") as HTMLButtonElement;
      mark.type = "button";
      mark.addEventListener("click", () => { localStorage.setItem("metavault_wizard_tested", "1"); render(); });
      item.append(mark);
    }
    list.append(item);
  });
  if (nextIndex === -1) card.append(el("p", "", "All set. Your IDE is connected."));
  const dismiss = el("button", "action", nextIndex === -1 ? "Close the guide" : "Skip for now") as HTMLButtonElement;
  dismiss.type = "button";
  dismiss.addEventListener("click", () => { localStorage.setItem("metavault_wizard_done", "1"); render(); });
  card.append(list, dismiss);
  view.prepend(card);
}

function renderRegistrationCards(view: HTMLElement): void {
  if (pendingRegistrations.length === 0 && registrationError === "") return;
  const wrap = el("div", "registration-cards");
  if (registrationError !== "") wrap.append(el("p", "field-error", registrationError));
  for (const reg of pendingRegistrations) {
    const card = el("section", "registration-card");
    card.append(el("h3", "", "An agent wants to be a Verified agent"));
    card.append(el("p", "", `${reg.name} (agent id ${reg.agentId}) asked to register. Approve only if the code it showed you in its chat is the one you type below.`));
    const input = document.createElement("input");
    input.type = "text";
    input.inputMode = "numeric";
    input.maxLength = 6;
    input.placeholder = "6-digit code";
    input.setAttribute("aria-label", `Code for ${reg.agentId}`);
    input.className = "registration-code";
    input.value = registrationDrafts.get(reg.id) ?? "";
    input.addEventListener("input", () => { registrationDrafts.set(reg.id, input.value); });
    const approve = el("button", "action btn-approve", "Approve") as HTMLButtonElement;
    const deny = el("button", "action", "Deny") as HTMLButtonElement;
    approve.type = "button"; deny.type = "button";
    const decide = (action: "approve" | "deny"): void => {
      approve.disabled = true; deny.disabled = true;
      registrationError = "";
      void window.metavault.decideAgentRegistration(reg.id, action, input.value.trim())
        .catch(() => { registrationError = action === "approve" ? "Not approved. Check the code matches the one the agent showed you." : "Could not deny the request."; })
        .then(() => refreshTracked());
    };
    approve.addEventListener("click", () => { decide("approve"); });
    deny.addEventListener("click", () => { decide("deny"); });
    const actions = el("div", "registration-actions");
    actions.append(input, approve, deny);
    card.append(actions);
    card.append(el("p", "registration-note", "Verified means you approved this agent's own credential. It does not prove which program it is, and it gives the agent no access to any secret. Each request still needs its own approval."));
    wrap.append(card);
  }
  view.prepend(wrap);
}

function renderPolicies(view: HTMLElement): void {
  view.append(el("h1", "", "Policies"));
  view.append(el("p", "sub", "Deterministic ceilings are enforced inside vaultd policy; the marshal can only narrow them. Revoking an agent disables its token and cancels its pending requests; it stays revoked until you rotate it."));

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
    const table = el("table", "data-table agents-table");
    const head = el("tr", "");
    const agentColumns = ["Agent", "Status", "Requests", "Last seen", "Observed", "Ceilings", "Standing", ""];
    for (const label of agentColumns) {
      head.append(el("th", label === "" ? "data-table-action" : "", label));
    }
    const thead = el("thead", "");
    thead.append(head);
    const tbody = el("tbody", "");
    for (const row of rows) {
      const observed = row.scopes.length === 0 ? "none" : row.scopes.join(", ");
      const ceilings = row.ceilings.length === 0 ? "—" : row.ceilings.map((entry) => `${entry.alias}: ${entry.ceiling}`).join(", ");
      const tr = el("tr", "");
      const statusCell = el("td", "");
      const registeredAgent = agentsData.find((agent) => agent.id === row.agentId);
      const isRevoked = registeredAgent?.revoked === true;
      // Revoking cancels standing approvals, so a revoked agent never shows an
      // active-looking grant; any leftover record is labelled as inactive.
      const standing = isRevoked
        ? (row.standingApprovals.length === 0 ? "None (cancelled on revoke)" : "None active (cancelled on revoke)")
        : row.standingApprovals.length === 0 ? "—" : row.standingApprovals.map((approval) => `${approval.alias}: ${approval.scope}`).join(", ");
      const isBlocked = !isRevoked && sessionBlockedAgents.has(row.agentId);
      statusCell.append(
        isRevoked
          ? el("span", "status-badge is-bad", "Revoked")
          : isBlocked
            ? el("span", "status-badge is-bad", "Blocked until restart")
            : el(
                "span",
                registeredAgent !== undefined ? "status-badge is-ok" : "status-badge is-warn",
                registeredAgent !== undefined ? "Verified" : "⚠️ Unverified",
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
      const revokeBtn = el("button", "text-revoke", busy ? "Working\u2026" : isRevoked || isBlocked ? "Revoked" : "Revoke") as HTMLButtonElement;
      revokeBtn.type = "button";
      revokeBtn.disabled = busy || isRevoked || isBlocked;
      if (busy) revokeBtn.setAttribute("aria-busy", "true");
      revokeBtn.addEventListener("click", () => { revokeAgentFlow(row.agentId); });
      action.append(revokeBtn);
      tr.append(action);
      // Labels let the narrow layout show each row as a labelled card.
      agentColumns.forEach((label, index) => {
        const td = tr.children[index];
        if (td !== undefined && label !== "") td.setAttribute("data-label", label);
      });
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
  const lockedNow = vaultLocked || keyGate !== null;
  document.body.classList.toggle("is-locked", lockedNow);
  if (lockedNow) {
    showBanner(null);
    // Sensitive details never stay open across a lock.
    daemonDetailsOpen = false;
  } else {
    lockedSettingsOpen = false;
    if (queuedDeeplink !== null && openQueuedDeeplink !== null) window.setTimeout(openQueuedDeeplink, 0);
  }
  if (keyGate !== null) {
    settingsOpen = false;
    const gateTitle = document.querySelector("#view-title");
    if (gateTitle !== null) gateTitle.textContent = keyGate === "setup" ? "Welcome" : "Locked";
    // Keep the open form (and what the user typed) across poll re-renders.
    const existing = view.querySelector<HTMLElement>("#vault-key-gate");
    if (existing === null || existing.dataset["mode"] !== keyGate) {
      view.replaceChildren(renderKeyGate(keyGate));
    }
    paintSettingsModal();
    paintApprovalDialog();
    syncChrome();
    return;
  }
  const page: Exclude<ViewName, "settings"> =
    currentView === "vault" || currentView === "audit" || currentView === "policies" || currentView === "posture" ? currentView : "approval";
  const title = document.querySelector("#view-title");
  if (title !== null) title.textContent = vaultLocked ? "Locked" : VIEW_TITLE[page];
  view.replaceChildren();
  if (vaultLocked) {
    view.replaceChildren();
    const lockScreen = el("div", "lock-screen");

    const lockIcon = el("div", "lock-icon");
    lockIcon.append(lockSvg());

    const helloOn = isBiometricsActive(localAuthStatus);
    const lockTitle = el("h2", "", "Welcome back.");
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
    let helloPill: HTMLElement | null = null;
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
      helloBtn.classList.add("lock-pill");
      helloBtn.removeAttribute("style");
      helloPill = helloBtn;
    }
    if (localAuthStatus.configured) {
      const field = document.createElement("input");
      pinInput = field;
      field.className = "vault-input";
      field.type = "password";
      field.placeholder = helloOn ? "App PIN fallback" : "Enter PIN to unlock";

      const unlockBtn = el("button", "action lock-submit", "Unlock") as HTMLButtonElement;
      unlockBtn.type = "button";
      unlockBtn.classList.add("btn-approve");

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
    decorateLockScreen(lockScreen, lockTitle, helloPill);
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
  if (page === "vault") renderOnboardingWizard(view);
  renderRegistrationCards(view);
  view.querySelectorAll("h1").forEach((node) => {
    node.setAttribute("aria-hidden", "true");
  });
  paintSettingsModal();
  paintApprovalDialog();
  syncChrome();
}

async function refresh(): Promise<void> {
  try {
    mcpRuntime ??= await window.metavault.runtimePaths().catch(() => null);
    if (mcpStatus === null || mcpStatus.state === "pending") {
      mcpStatus = projectMcpStatus(await window.metavault.mcpStatus().catch(() => null));
    }
    const keyStatusRaw = await window.metavault.keyStatus().catch(() => null);
    vaultKeyFingerprint = keyStatusRaw !== null && typeof keyStatusRaw === "object" && "fingerprint" in keyStatusRaw && typeof keyStatusRaw.fingerprint === "string" && /^[a-f0-9]{24}$/.test(keyStatusRaw.fingerprint) ? keyStatusRaw.fingerprint : null;
    keyGate = projectKeyGate(keyStatusRaw);
    if (keyGate !== null) {
      newAgentTokens.clear();
      setDaemonStatus(true);
      render();
      return;
    }
    const [pendingRaw, aliasesRaw, auditRaw, policiesRaw, agentsRaw, wardenRaw, wardenKeyRaw, postureRaw, localAuthRaw, secRaw, remoteRaw] = await Promise.all([
      window.metavault.pending(),
      window.metavault.aliases(),
      window.metavault.audit(),
      window.metavault.policies(),
      window.metavault.agents().catch(() => null),
      window.metavault.getWardenSettings().catch(() => null),
      window.metavault.wardenKeyStatus().catch(() => null),
      window.metavault.getSecurityPosture().catch(() => null),
      window.metavault.getLocalAuthStatus().catch(() => null),
      window.metavault.getAgentSecuritySettings().catch(() => null),
      window.metavault.getRemoteSettings().catch(() => null),
    ]);
    
    remoteSettings = projectRemoteSettings(remoteRaw);
    if (remoteSettings !== null && remoteSettings.enabled) {
      const [devicesRaw, pairingRaw] = await Promise.all([
        window.metavault.listDevices().catch(() => null),
        window.metavault.getPairingSession().catch(() => null),
      ]);
      devicesData = projectDevicesResponse(devicesRaw);
      const projectedSession = projectPairingSession(pairingRaw);
      pairingSession = projectedSession;
      // A consumed or expired session clears the one-time code from memory.
      if (projectedSession === null || projectedSession.status === "confirmed" || projectedSession.status === "canceled") {
        pairingCode = null;
      }
    } else {
      devicesData = [];
      pairingSession = null;
      pairingCode = null;
    }
    const sshRaw = await window.metavault.sshTunnelStatus().catch(() => null);
    const sshResult = projectSshTunnelResult(sshRaw);
    if (sshResult !== null && sshResult.kind === "status" && sshResult.status !== undefined) {
      sshTunnel = sshResult.status;
    }
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
    agentsData = projectAgentsResponse(agentsRaw);
    const regsRaw: unknown = await window.metavault.agentRegistrations().catch(() => null);
    const regList = typeof regsRaw === "object" && regsRaw !== null && Array.isArray((regsRaw as { registrations?: unknown }).registrations) ? (regsRaw as { registrations: unknown[] }).registrations : [];
    const nextRegs: PendingRegistration[] = [];
    for (const r of regList) {
      if (typeof r !== "object" || r === null) continue;
      const o = r as Record<string, unknown>;
      if (typeof o["id"] === "string" && typeof o["agentId"] === "string" && typeof o["name"] === "string" && typeof o["ide"] === "string" && typeof o["code"] === "string") {
        nextRegs.push({ id: o["id"], agentId: o["agentId"], name: o["name"], ide: o["ide"], code: o["code"] });
      }
    }
    if (nextRegs.some((r) => !pendingRegistrations.some((p) => p.id === r.id))) window.metavault.bringToFront();
    pendingRegistrations = nextRegs;
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

// First run: create the vault passphrase (POST /setup). Later launches:
// unlock with it (POST /unlock). The passphrase goes straight to the local
// daemon through main and is never stored by the app.

function decorateLockScreen(box: HTMLElement, heading: HTMLElement, hello: HTMLElement | null): void {
  box.classList.add("lock-shell");
  box.querySelector(".lock-icon")?.remove();
  const logo = document.createElement("img");
  logo.className = "lock-logo";
  logo.src = "./favicon.svg";
  logo.alt = "MetaVault";
  logo.width = 56;
  logo.height = 56;
  box.prepend(logo);
  heading.textContent = "Welcome back.";
  const bar = el("div", "lock-bar");
  const settingsBtn = el("button", "lock-settings-btn", "Settings") as HTMLButtonElement;
  settingsBtn.type = "button";
  settingsBtn.setAttribute("aria-expanded", String(lockedSettingsOpen));
  const panel = el("div", "lock-settings-panel");
  panel.hidden = !lockedSettingsOpen;
  panel.append(el("h3", "", "Settings"));
  const modeRow = el("div", "lock-mode-row");
  for (const [value, label] of [["verbose", "Full interface"], ["simple", "Simple interface"]] as const) {
    const b = el("button", `lock-mode-btn${uiMode === value ? " is-selected" : ""}`, label) as HTMLButtonElement;
    b.type = "button";
    b.addEventListener("click", () => {
      uiMode = value;
      localStorage.setItem("metavault_ui_mode", value);
      document.body.classList.toggle("is-simple-mode", value === "simple");
      modeRow.querySelectorAll(".lock-mode-btn").forEach((n) => { n.classList.remove("is-selected"); });
      b.classList.add("is-selected");
    });
    modeRow.append(b);
  }
  panel.append(modeRow, el("p", "lock-note", `Version v${APP_VERSION_DISPLAY}. More settings are available after you unlock.`));
  settingsBtn.addEventListener("click", () => {
    lockedSettingsOpen = !lockedSettingsOpen;
    panel.hidden = !lockedSettingsOpen;
    settingsBtn.setAttribute("aria-expanded", String(lockedSettingsOpen));
  });
  bar.append(settingsBtn);
  if (hello !== null) bar.append(hello);
  box.append(panel, bar);
}

function renderKeyGate(mode: "setup" | "unlock"): HTMLElement {
  const box = el("form", "lock-screen vault-key-gate");
  box.id = "vault-key-gate";
  box.dataset["mode"] = mode;
  const icon = el("div", "lock-icon");
  icon.append(lockSvg());
  const heading = el("h2", "", mode === "setup" ? "Create your vault password" : "Welcome back.");
  const sub = el(
    "p",
    "",
    mode === "setup"
      ? `This password encrypts your vault key on this computer. Use at least ${String(MIN_PASSPHRASE_LENGTH)} characters. There is no reset: if you forget it, the vault cannot be opened.`
      : "Enter your vault password.",
  );
  const pass = document.createElement("input");
  pass.type = "password";
  pass.id = "vault-passphrase-input";
  pass.autocomplete = mode === "setup" ? "new-password" : "current-password";
  pass.placeholder = "Password";
  pass.setAttribute("aria-label", "Vault password");
  const confirm = document.createElement("input");
  confirm.type = "password";
  confirm.id = "vault-passphrase-confirm";
  confirm.autocomplete = "new-password";
  confirm.placeholder = "Type it again";
  confirm.setAttribute("aria-label", "Confirm vault password");
  const error = el("p", "field-error");
  error.id = "vault-key-gate-error";
  error.setAttribute("role", "alert");
  const submit = el("button", "action btn-approve lock-submit", mode === "setup" ? "Create vault" : "Unlock") as HTMLButtonElement;
  submit.type = "submit";
  box.append(icon, heading, sub, pass);
  if (mode === "setup") box.append(confirm);
  box.append(error, submit);
  if (mode === "unlock") {
    const vaultRow = el("div", "lock-vault-row");
    vaultRow.append(el("span", "", "Vault"), el("span", "lock-vault-value", "Local"));
    box.insertBefore(vaultRow, pass);
    decorateLockScreen(box, heading, null);
  } else {
    box.classList.add("lock-shell");
    box.querySelector(".lock-icon")?.remove();
    const logo = document.createElement("img");
    logo.className = "lock-logo";
    logo.src = "./favicon.svg";
    logo.alt = "MetaVault";
    logo.width = 56;
    logo.height = 56;
    box.prepend(logo);
  }
  box.addEventListener("submit", (event) => {
    event.preventDefault();
    const problem = mode === "setup" ? passphraseSetupError(pass.value, confirm.value) : pass.value === "" ? "Enter your password." : null;
    if (problem !== null) {
      error.textContent = problem;
      return;
    }
    submit.disabled = true;
    error.textContent = "";
    const call = mode === "setup" ? window.metavault.setupVault(pass.value) : window.metavault.unlockVault(pass.value);
    call
      .then(() => {
        pass.value = "";
        confirm.value = "";
        return refreshTracked();
      })
      .catch((err: unknown) => {
        const message = keyGateErrorMessage(err instanceof Error ? err.message : "");
        error.textContent = message;
        submit.disabled = false;
        if (message.includes("already has a passphrase")) void refreshTracked();
      });
  });
  setTimeout(() => { pass.focus(); }, 50);
  return box;
}

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
    // While the vault or app is locked nothing opens over the lock screen.
    // The request is kept and the add form opens right after unlock.
    if (vaultLocked || keyGate !== null) {
      queuedDeeplink = params;
      return;
    }
    openDeeplinkAdd(params);
  });
  openQueuedDeeplink = () => {
    const queued = queuedDeeplink;
    queuedDeeplink = null;
    if (queued !== null) openDeeplinkAdd(queued);
  };
  function openDeeplinkAdd(params: DeeplinkAddParams): void {
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
  }
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
      if (isSettingsTab(next)) {
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
  // The nav strip scrolls sideways on narrow windows. Keyboard focus must
  // bring the whole focused button into view, not leave it half clipped.
  document.querySelector(".sidebar")?.addEventListener("focusin", (event) => {
    if (event.target instanceof HTMLElement) event.target.scrollIntoView({ block: "nearest", inline: "nearest" });
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
  if (typeof window.metavault.onSshTunnelStatus === "function") {
    window.metavault.onSshTunnelStatus((value) => {
      const projected = projectSshTunnelStatus(value);
      if (projected !== null) {
        sshTunnel = projected;
        if (settingsOpen && !settingsBusy) render();
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



