import { appendFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { app, BrowserWindow, ipcMain, Menu, nativeImage, Notification, screen, Tray } from "electron";
import { DAEMON_CALL_CHANNEL, callDaemon, daemonEventToken, getDaemonBaseUrl, readDaemonJson, setDaemonToken, setPackagedBuild } from "./daemon-client.js";
import { PRESENCE_PROOF_CHANNEL, defaultGuardDeps, guardedDaemonCall, issuePresenceProof } from "./remote-approval-ipc.js";
import { PresenceProofIssuer } from "./remote-approval-guard.js";
import { bundledDaemonPaths, daemonHealthy, ensureBundledDaemon } from "./daemon-launcher.js";
import { checkMcpRuntime, MCP_SELFCHECK_PENDING, type McpSelfCheckResult } from "./mcp-selfcheck.js";
import { autostartGatewayWhenRemoteEnabled } from "./gateway-autostart.js";
import { bundledGatewayPaths, ensureBundledGateway, gatewayListening, GATEWAY_HOST, GATEWAY_PORT, GATEWAY_DEVICE_PORT, type GatewayLaunchResult } from "./gateway-launcher.js";
import { SshTunnelManager, resolveSshBinaries, sshTunnelPaths } from "./ssh-tunnel.js";
import { SSH_TUNNEL_CHANNEL, SSH_TUNNEL_STATUS_CHANNEL, handleSshTunnelRequest } from "./ssh-tunnel-ipc.js";
import type { ChildProcess } from "node:child_process";
import { DEEPLINK_CHANNEL, findVaultDeeplink, parseVaultDeeplinkAction, websiteFromTrustedEnrollment, type DeeplinkAddParams, type EnrollmentWebsiteRecord, type VaultDeeplinkAction } from "./deeplink.js";
import { PRELOAD_FILE_NAME, buildWindowOptions, shouldHideOnClose } from "./window-options.js";
import {
  applyPreferencePatch,
  loadDesktopPreferences,
  persistDesktopPreferences,
  preferencesFilePath,
  type DesktopPreferences,
} from "./desktop-prefs.js";
import { composeTrayIcon, trayTooltip, type TrayState } from "./tray-icons.js";
import { ensureFlyout, flyoutWebContents, hideFlyout, isFlyoutSender, toggleFlyout } from "./tray-flyout.js";
import { ApprovalToastManager, type ToastClickRoute } from "./notifications.js";
import type { FlyoutGrantLike, FlyoutStateLike, LockStateLike, NavigateLike, SoundCue } from "./renderer/types.js";
import { initAutoUpdater } from "./updater.js";
import { runtimePaths } from "./runtime-paths.js";
import { registerWindowsHelloIpc } from "./windows-hello.js";
import { IDE_CONFIG_CHANNEL, ideConfigIpc, type IdeConfigRequest } from "./ide-config-ipc.js";

// Validates the fixed IDE-config channel shape; anything else throws so the
// handler answers with a plain failure instead of injecting unknown keys.
function decodeIdeConfigRequest(input: unknown): IdeConfigRequest {
  if (typeof input !== "object" || input === null) throw new Error("malformed IDE-config request");
  const record = input as Record<string, unknown>;
  if (record["action"] !== "inspect" && record["action"] !== "apply") throw new Error("unknown IDE-config action");
  const host = record["host"];
  const entry = record["entry"];
  const token = record["token"];
  if (host !== undefined && typeof host !== "string") throw new Error("malformed IDE-config host");
  if (token !== undefined && typeof token !== "string") throw new Error("malformed IDE-config token");
  if (record["action"] === "apply") {
    if (typeof host !== "string" || host === "") throw new Error("apply requires a host");
    if (typeof token !== "string" || token === "") throw new Error("apply requires a token");
    if (entry !== undefined && typeof entry !== "object") throw new Error("malformed IDE-config entry");
  }
  return {
    action: record["action"],
    ...(host !== undefined ? { host } : {}),
    ...(entry !== undefined ? { entry } : {}),
    ...(token !== undefined ? { token } : {}),
  };
}

// MetaVault OSS desktop shell: a window over vaultd, in the wallet pattern.
// This main process owns the daemon HTTP client and the daemon token (see
// daemon-client.ts); the token stays in main and never crosses IPC into
// the preload or renderer. It talks to nothing but the local daemon. Closing the window minimises to the
// tray so approval prompts can still surface. In the installed app, if no
// daemon answers on the daemon port, main starts the bundled one
// (resources/vaultd) and stops it again when you quit from the tray. A
// daemon you started yourself (vaultd / metavault) is left alone.

setPackagedBuild(app.isPackaged);

const here = dirname(fileURLToPath(import.meta.url));
const preloadPath = join(here, PRELOAD_FILE_NAME);
const rendererPath = join(here, "renderer", "index.html");

// Register as the metavault:// and openvault:// handler. In dev (running
// via the Electron binary) the execPath/argv form with resolved script path
// is required so Windows launches this app cleanly.
if (process.defaultApp) {
  const script = process.argv[1];
  if (script !== undefined) {
    const resolvedScript = resolve(script);
    app.setAsDefaultProtocolClient("metavault", process.execPath, [resolvedScript]);
    app.setAsDefaultProtocolClient("openvault", process.execPath, [resolvedScript]);
  } else {
    app.setAsDefaultProtocolClient("metavault");
    app.setAsDefaultProtocolClient("openvault");
  }
} else {
  app.setAsDefaultProtocolClient("metavault");
  app.setAsDefaultProtocolClient("openvault");
}

// Windows toast banners show "MetaVault OSS" with the app icon when the
// AUMID is set before whenReady and matches build.appId.
if (process.platform === "win32") {
  app.setAppUserModelId("dev.metavault.app");
}

// Synthesized earcons play from a background (minimized-at-login) window,
// so the AudioContext must never start suspended.
app.commandLine.appendSwitch("autoplay-policy", "no-user-gesture-required");

// Vault data lives in %APPDATA%\MetaVault OSS whatever the package name is,
// so the uninstaller's "delete vault data" step knows where to look.
const dataDir = join(app.getPath("appData"), "MetaVault OSS");
app.setPath("userData", dataDir);
const daemonPaths = bundledDaemonPaths(process.resourcesPath, dataDir);

// Result of the launch-time MCP self-check (mcp-selfcheck.ts). Starts as
// pending; the renderer polls it until the check settles. The IDE still
// launches the MCP server itself - this only proves the bundled runtime is
// ready for that connection.
let mcpSelfCheck: McpSelfCheckResult = MCP_SELFCHECK_PENDING;

async function runMcpSelfCheck(): Promise<void> {
  // Wait for the daemon to answer first: the MCP server is a thin adapter
  // over it, so checking before it is up would prove nothing.
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (await daemonHealthy(getDaemonBaseUrl())) break;
    await new Promise((resolveTimer) => setTimeout(resolveTimer, 500));
  }
  const runtime = runtimePaths({ packaged: app.isPackaged, execPath: process.execPath, resourcesPath: process.resourcesPath, repoRoot: join(here, "..", "..", ".."), dbPath: process.env["METAVAULT_DB_PATH"] ?? join(process.cwd(), "metavault.db") });
  mcpSelfCheck = await checkMcpRuntime({
    command: runtime.command,
    args: runtime.args,
    env: runtime.env,
    daemonUrl: getDaemonBaseUrl(),
  }).catch((err: unknown): McpSelfCheckResult => ({ state: "failed", tools: [], detail: err instanceof Error ? err.message : "self-check error", checkedAt: new Date().toISOString() }));
}
if (app.isPackaged) {
  // daemon-client reads this lazily to find the daemon token file.
  process.env["METAVAULT_DB_PATH"] ??= daemonPaths.dbPath;
}
let bundledDaemon: ChildProcess | null = null;
let bundledGateway: ChildProcess | null = null;
let sshTunnel: SshTunnelManager | null = null;

const adoptGatewayChild = (launched: GatewayLaunchResult): void => {
  if (launched.child !== undefined) {
    bundledGateway = launched.child;
    launched.child.once("exit", () => {
      if (bundledGateway === launched.child) bundledGateway = null;
    });
  }
};

let mainWindow: BrowserWindow | null = null;
let pendingDeeplink: DeeplinkAddParams | null = null;
let rendererReady = false;

function enrollmentRecord(body: unknown): { readonly enrollment: EnrollmentWebsiteRecord | null; readonly expiresAtMs: number | null } {
  if (typeof body !== "object" || body === null) return { enrollment: null, expiresAtMs: null };
  const record = body as Record<string, unknown>;
  const status = typeof record["status"] === "string" ? record["status"] : "";
  const alias = typeof record["alias"] === "string" ? record["alias"] : "";
  const scope = typeof record["scope"] === "string" ? record["scope"] : "";
  const website = typeof record["website"] === "string" ? record["website"] : "";
  return {
    enrollment: { status, alias, scope, website },
    expiresAtMs: typeof record["expiresAtMs"] === "number" ? record["expiresAtMs"] : null,
  };
}

async function enrichDeeplink(params: DeeplinkAddParams): Promise<DeeplinkAddParams> {
  let enrollment: EnrollmentWebsiteRecord | null = null;
  let expiresAtMs: number | null = null;
  if (params.enrollmentId !== "") {
    const projected = enrollmentRecord(await readDaemonJson(`/enrollments/${encodeURIComponent(params.enrollmentId)}`));
    enrollment = projected.enrollment;
    expiresAtMs = projected.expiresAtMs;
  }
  const trusted = websiteFromTrustedEnrollment(params, enrollment, Date.now(), expiresAtMs);
  return {
    alias: params.alias,
    scope: params.scope,
    website: trusted.website,
    enrollmentId: params.enrollmentId,
    ...(trusted.untrusted ? { untrusted: true } : {}),
  };
}

async function sendEnrichedDeeplink(window: BrowserWindow, params: DeeplinkAddParams): Promise<void> {
  const enriched = await enrichDeeplink(params);
  if (mainWindow !== window || window.isDestroyed()) return;
  window.webContents.send(DEEPLINK_CHANNEL, enriched);
}

function routeDeeplink(params: DeeplinkAddParams): void {
  showWindow();
  if (mainWindow !== null && rendererReady) {
    void sendEnrichedDeeplink(mainWindow, params);
  } else {
    pendingDeeplink = params;
  }
}

function handleDeeplinkUrl(raw: unknown): void {
  const action = parseVaultDeeplinkAction(raw);
  if (action !== null) {
    routeDeeplinkAction(action);
  }
}

// Second-instance argv and cold start queue: first valid action wins.
function deeplinkActionFromArgv(argv: readonly unknown[]): VaultDeeplinkAction | null {
  for (const arg of argv) {
    const action = parseVaultDeeplinkAction(arg);
    if (action !== null) {
      return action;
    }
  }
  return null;
}
let tray: Tray | null = null;
let isQuitting = false;

function showWindow(): void {
  if (mainWindow === null) {
    createWindow();
    return;
  }
  if (mainWindow.isMinimized()) {
    mainWindow.restore();
  }
  mainWindow.show();
  // Windows can refuse a plain focus() from a background launch; a brief
  // always-on-top pass brings the window to the front without keeping it there.
  mainWindow.setAlwaysOnTop(true);
  mainWindow.moveTop();
  mainWindow.focus();
  mainWindow.setAlwaysOnTop(false);
}

function bringWindowToFront(): void {
  if (mainWindow === null) {
    createWindow();
    return;
  }
  if (mainWindow.isMinimized()) {
    mainWindow.restore();
  }
  mainWindow.showInactive();
  mainWindow.flashFrame(true);
}

// --- Desktop preferences, lock state, tray, flyout, toasts, live events ---

// Preferences load from %APPDATA%\MetaVault OSS\desktop-preferences.json;
// a missing or corrupt file falls back to platform defaults.
let prefs: DesktopPreferences = loadDesktopPreferences(preferencesFilePath(dataDir));

let uiLocked = false;
let daemonLocked = false;
let daemonPassphraseMode = true;
let localAuthConfigured = false;
let pendingNavigation: NavigateLike | null = null;
let trayPendingCount = 0;
let trayRegistrationCount = 0;
let liveEventsDisabled = false;

function totalPendingCount(): number {
  return trayPendingCount + trayRegistrationCount;
}

// Hydrate daemon lock + local auth at boot and after vault lock changes.
async function hydrateLockState(): Promise<void> {
  const keyStatus = await readDaemonJson("/key/status").catch(() => null);
  if (typeof keyStatus === "object" && keyStatus !== null) {
    const record = keyStatus as Record<string, unknown>;
    if (typeof record["locked"] === "boolean") {
      daemonLocked = record["locked"];
    }
    if (typeof record["mode"] === "string") {
      daemonPassphraseMode = record["mode"] === "passphrase";
    }
  }
  await directLockStateBroadcast();
}

async function directLockStateBroadcast(): Promise<void> {
  const localAuth = await readDaemonJson("/settings/local-auth").catch(() => null);
  if (typeof localAuth === "object" && localAuth !== null) {
    const record = localAuth as Record<string, unknown>;
    const enabled = record["enabled"] === true;
    const configured = record["configured"] === true;
    const biometric = record["biometricEnabled"] === true;
    localAuthConfigured = enabled && (configured || biometric);
  }
  broadcastLockState();
}

function broadcastLockState(): void {
  const payload: LockStateLike = { uiLocked, daemonLocked };
  if (mainWindow !== null && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send("metavault:lock-state", payload);
  }
  const flyoutContents = flyoutWebContents();
  if (flyoutContents !== null) {
    flyoutContents.send("metavault:lock-state", payload);
    void pushFlyoutState().catch(() => undefined);
  }
  refreshTray();
}

// Flush navigation targets that arrived while a lock screen was up.
function flushPendingNavigation(): void {
  if (pendingNavigation === null) return;
  const nav = pendingNavigation;
  pendingNavigation = null;
  if (uiLocked || daemonLocked) {
    pendingNavigation = nav;
    return;
  }
  sendNavigate(nav);
}

function routeDeeplinkAction(action: VaultDeeplinkAction): void {
  hideFlyout();
  if (action.kind === "add") {
    routeDeeplink(action);
    return;
  }
  showWindow();
  if (action.kind === "unlock") {
    broadcastLockState();
    sendNavigate({ kind: "unlock", target: action.target });
    return;
  }
  if (action.kind === "approve") {
    sendNavigateOrStash({ kind: "approval", id: action.grantId });
    return;
  }
  if (action.kind === "register") {
    sendNavigateOrStash({ kind: "registration", id: action.registrationId });
    return;
  }
  if (action.kind === "audit") {
    sendNavigateOrStash({ kind: "audit", id: action.requestId });
    return;
  }
  sendNavigateOrStash({ kind: "settings", section: action.section });
}

function sendNavigateOrStash(nav: NavigateLike): void {
  if (!rendererReady || uiLocked || daemonLocked) {
    // Locked or still loading: stash the target; route after ready & unlocked.
    pendingNavigation = nav;
    return;
  }
  sendNavigate(nav);
}

function sendNavigate(nav: NavigateLike): void {
  if (mainWindow !== null && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send("metavault:navigate", nav);
  }
}

function playSound(cue: SoundCue): void {
  if (prefs.soundMode === "off") return;
  if (prefs.soundMode === "high-risk-only" && cue !== "approval-high-risk") return;
  if (mainWindow !== null && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send("metavault:play-sound", { cue });
  }
}

// Start-at-login toggles mirror into the OS login item instead of relying
// on the installer's Run key, so the user's choice survives upgrades.
function syncSystemLoginItem(): void {
  if (!app.isPackaged) return;
  try {
    app.setLoginItemSettings({ openAtLogin: prefs.startMinimizedAtLogin, args: ["--minimized"] });
  } catch {
    // A failing login-item write must not break the preference toggle.
  }
}

// Single write path for preference changes: validate, merge in memory,
// persist to disk, mirror the OS login item, and repaint tray + flyout.
// Accepts unknown input and returns false when nothing valid applied.
function updatePreferences(patch: unknown): boolean {
  const result = applyPreferencePatch(prefs, patch);
  if (!result.ok) return false;
  prefs = result.prefs;
  persistDesktopPreferences(preferencesFilePath(dataDir), prefs);
  syncSystemLoginItem();
  refreshTray();
  if (flyoutWebContents() !== null) {
    void pushFlyoutState().catch(() => undefined);
  }
  return true;
}

// --- Live events (GET /events SSE) ---

let liveEventsRetrying = false;

async function watchDaemonEvents(): Promise<void> {
  if (liveEventsDisabled) {
    return;
  }
  const token = daemonEventToken();
  if (token === undefined || token === "") {
    // Nothing token-guarded can be read; retry later once a token exists.
    scheduleEventsRetry(4000);
    return;
  }
  let response: Response;
  try {
    response = await fetch(`${getDaemonBaseUrl()}/events`, {
      headers: { "x-metavault-token": token },
      signal: AbortSignal.timeout(70_000),
    });
  } catch {
    scheduleEventsRetry(4000);
    return;
  }
  if (!response.ok || response.body === null) {
    scheduleEventsRetry(6000);
    return;
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf8");
  let buffer = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const frames = buffer.split("\n\n");
      buffer = frames.pop() ?? "";
      for (const frame of frames) {
        handleEventFrame(frame);
      }
    }
  } catch {
    // Daemon restart or network hiccup; retry below.
  }
  scheduleEventsRetry(2000);
}

function scheduleEventsRetry(afterMs: number): void {
  if (liveEventsDisabled || liveEventsRetrying) return;
  liveEventsRetrying = true;
  setTimeout(() => {
    liveEventsRetrying = false;
    if (!liveEventsDisabled) {
      void watchDaemonEvents();
    }
  }, afterMs).unref();
}

function handleEventFrame(frame: string): void {
  let eventName = "";
  let data = "";
  for (const line of frame.split("\n")) {
    if (line.startsWith("event: ")) {
      eventName = line.slice(7).trim();
    } else if (line.startsWith("data: ")) {
      data = line.slice(6).trim();
    }
  }
  if (eventName === "" || data.startsWith(":")) return;
  let payload: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(data);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return;
    payload = parsed as Record<string, unknown>;
  } catch {
    return;
  }
  if (eventName === "pending.changed") {
    const count = typeof payload["pendingCount"] === "number" ? payload["pendingCount"] : trayPendingCount;
    trayPendingCount = count;
    refreshTray();
    const addedGrantId = payload["addedGrantId"];
    if (typeof addedGrantId === "string" && addedGrantId !== "") {
      void toastNewGrant(addedGrantId, payload);
    } else {
      void pushFlyoutState().catch(() => undefined);
    }
    scheduleToastSweep();
    return;
  }
  if (eventName === "registration.changed") {
    if (typeof payload["pendingRegistrationsCount"] === "number") {
      trayRegistrationCount = payload["pendingRegistrationsCount"];
      refreshTray();
    }
    const addedRegistrationId = payload["addedRegistrationId"];
    if (typeof addedRegistrationId === "string" && addedRegistrationId !== "") {
      void toastNewRegistration(addedRegistrationId);
    } else {
      void pushFlyoutState().catch(() => undefined);
    }
    scheduleToastSweep();
    return;
  }
  if (eventName === "vault.lock_changed") {
    const nowLocked = payload["daemonLocked"] === true;
    if (daemonLocked !== nowLocked) {
      daemonLocked = nowLocked;
      if (nowLocked) {
        hideFlyout();
      }
      void hydrateLockState().catch(() => undefined);
      broadcastLockState();
      if (nowLocked) {
        playSound("vault-locked");
      } else {
        flushPendingNavigation();
      }
      void pushFlyoutState().catch(() => undefined);
    }
  }
}

const toasts: ApprovalToastManager = new ApprovalToastManager({
  notificationsSupported: () => Notification.isSupported(),
  create: (options) => {
    const note = new Notification(options);
    return {
      on: note.on.bind(note),
      show: note.show.bind(note),
      close: note.close.bind(note),
    };
  },
  onRoute: (route: ToastClickRoute) => {
    hideFlyout();
    showWindow();
    sendNavigateOrStash(
      route.kind === "approval"
        ? { kind: "approval", id: route.id }
        : { kind: "registration", id: route.id },
    );
  },
  onSettingsRoute: () => {
    hideFlyout();
    showWindow();
    sendNavigateOrStash({ kind: "settings", section: "connections" });
  },
});

function pendingRows(body: unknown): FlyoutGrantLike[] {
  if (typeof body !== "object" || body === null) return [];
  const container = body as { approvals?: unknown; pending?: unknown };
  const list = Array.isArray(container.approvals)
    ? container.approvals
    : Array.isArray(container.pending)
      ? container.pending
      : [];
  const rows: FlyoutGrantLike[] = [];
  for (const row of list) {
    if (typeof row !== "object" || row === null) continue;
    const r = row as Record<string, unknown>;
    if (typeof r["grantId"] !== "string" || typeof r["agentId"] !== "string" || typeof r["alias"] !== "string" || typeof r["requestedScope"] !== "string") continue;
    const allowedScope = typeof r["allowedScope"] === "string" ? r["allowedScope"] : r["requestedScope"];
    const explanation = typeof r["marshalExplanation"] === "string" ? r["marshalExplanation"] : undefined;
    const origin = r["origin"] === "local" || r["origin"] === "remote" ? r["origin"] : undefined;
    let payloadHeadline: string | undefined;
    const ps = r["payloadSummary"];
    if (typeof ps === "object" && ps !== null && !Array.isArray(ps)) {
      const psRec = ps as Record<string, unknown>;
      const method = typeof psRec["declaredMethod"] === "string" && psRec["declaredMethod"] !== "" ? psRec["declaredMethod"] : null;
      const preview = typeof psRec["preview"] === "string" ? psRec["preview"].slice(0, 120) : "";
      if (method !== null || preview !== "") {
        payloadHeadline = [method, preview].filter((part): part is string => part !== null && part !== "").join(" ");
      }
    }
    rows.push({
      grantId: r["grantId"],
      agentId: r["agentId"],
      alias: r["alias"],
      requestedScope: r["requestedScope"],
      allowedScope,
      risk: typeof r["risk"] === "string" ? r["risk"] : "medium",
      verified: r["verified"] === true,
      ...(origin !== undefined ? { origin } : {}),
      ...(explanation !== undefined && explanation !== "" ? { explanation } : {}),
      ...(payloadHeadline !== undefined && payloadHeadline !== "" ? { payloadHeadline } : {}),
    });
  }
  return rows;
}

function flashTaskbarQuietly(): void {
  if (mainWindow !== null && !mainWindow.isDestroyed()) {
    mainWindow.flashFrame(true);
  }
}

async function toastNewGrant(grantId: string, frame: Record<string, unknown>): Promise<void> {
  const body = await readDaemonJson("/pending").catch(() => null);
  const rows = pendingRows(body);
  trayPendingCount = rows.length;
  refreshTray();
  const row = rows.find((r) => r.grantId === grantId);
  const lockedNow = uiLocked || daemonLocked;
  if (prefs.popWindowOnApproval) {
    bringWindowToFront();
  } else {
    flashTaskbarQuietly();
  }
  if (row === undefined) {
    if (!lockedNow) return;
    // Locked and the row is not visible: redacted toast keeps the user aware.
    const highRiskFrame = frame["risk"] === "high" || frame["origin"] === "remote";
    toasts.fires(
      { grantId, agentId: "", alias: "", requestedScope: "", risk: highRiskFrame ? "high" : "signal", remote: frame["origin"] === "remote" },
      prefs,
      lockedNow,
    );
    playSound(highRiskFrame ? "approval-high-risk" : "approval-standard");
    return;
  }
  const effectiveRisk = typeof frame["risk"] === "string" ? frame["risk"] : row.risk;
  const isRemote = frame["origin"] === "remote" || row.origin === "remote";
  const isHighRisk = effectiveRisk === "high" || !row.allowedScope.endsWith(".read") && row.allowedScope !== "read" && !row.allowedScope.endsWith(":read") || isRemote;
  toasts.fires(
    {
      grantId: row.grantId,
      agentId: row.agentId,
      alias: row.alias,
      requestedScope: row.requestedScope,
      risk: effectiveRisk,
      remote: isRemote,
    },
    prefs,
    lockedNow,
  );
  dispatchedGrantIds.add(row.grantId);
  playSound(isHighRisk ? "approval-high-risk" : "approval-standard");
  void pushFlyoutState().catch(() => undefined);
}

async function toastNewRegistration(registrationId: string): Promise<void> {
  const body = await readDaemonJson("/agent-registrations").catch(() => null);
  const list = typeof body === "object" && body !== null && Array.isArray((body as { registrations?: unknown }).registrations)
    ? (body as { registrations: unknown[] }).registrations
    : [];
  trayRegistrationCount = list.length;
  refreshTray();
  if (prefs.popWindowOnApproval) {
    bringWindowToFront();
  } else {
    flashTaskbarQuietly();
  }
  const row = list.find((r) => {
    if (typeof r !== "object" || r === null) return false;
    return (r as Record<string, unknown>)["id"] === registrationId;
  });
  const rawName = row !== undefined ? (row as Record<string, unknown>)["name"] : undefined;
  const name = typeof rawName === "string" ? rawName : "an agent";
  toasts.firesRegistration({ registrationId, name }, prefs, uiLocked || daemonLocked);
  dispatchedRegistrationIds.add(registrationId);
  playSound("agent-registration");
  void pushFlyoutState().catch(() => undefined);
}

// Toasts vanish from Action Center as soon as their source resolves.
const dispatchedGrantIds = new Set<string>();
const dispatchedRegistrationIds = new Set<string>();
let sweepTimer: NodeJS.Timeout | null = null;

function scheduleToastSweep(): void {
  if (sweepTimer !== null) return;
  sweepTimer = setTimeout(() => {
    sweepTimer = null;
    void sweepStaleToasts().catch(() => undefined);
  }, 700);
  sweepTimer.unref();
}

async function sweepStaleToasts(): Promise<void> {
  const [pendingBody, regsBody] = await Promise.all([
    readDaemonJson("/pending").catch(() => null),
    readDaemonJson("/agent-registrations").catch(() => null),
  ]);
  const liveRows = pendingRows(pendingBody);
  trayPendingCount = liveRows.length;
  const liveGrants = new Set(liveRows.map((r) => r.grantId));
  for (const grantId of [...dispatchedGrantIds]) {
    if (!liveGrants.has(grantId)) {
      dispatchedGrantIds.delete(grantId);
      toasts.dismiss(`grant:${grantId}`);
    }
  }
  const liveRegs = typeof regsBody === "object" && regsBody !== null && Array.isArray((regsBody as { registrations?: unknown }).registrations)
    ? (regsBody as { registrations: unknown[] }).registrations.flatMap((r) => {
        if (typeof r === "object" && r !== null && typeof (r as Record<string, unknown>)["id"] === "string") {
          return [(r as Record<string, unknown>)["id"] as string];
        }
        return [];
      })
    : [];
  trayRegistrationCount = liveRegs.length;
  const liveRegsSet = new Set(liveRegs);
  for (const registrationId of [...dispatchedRegistrationIds]) {
    if (!liveRegsSet.has(registrationId)) {
      dispatchedRegistrationIds.delete(registrationId);
      toasts.dismiss(`reg:${registrationId}`);
    }
  }
  refreshTray();
}

// --- Tray ---

let trayBaseIconPath: string | null = null;

function currentTrayState(): TrayState {
  if (daemonLocked) return "daemon-locked";
  if (uiLocked) return "ui-locked";
  if (totalPendingCount() > 0) return "pending";
  return "unlocked-idle";
}

function buildTrayMenu(state: TrayState): Electron.Menu {
  const totalPending = totalPendingCount();
  const menuTemplate: Electron.MenuItemConstructorOptions[] = [
    {
      label:
        state === "daemon-locked" ? "MetaVault: Vault Locked"
      : state === "ui-locked" ? "MetaVault: UI Locked"
      : "MetaVault: Unlocked",
      enabled: false,
    },
    ...(totalPending > 0
      ? [{
          label: `Review Pending Approvals (${String(totalPending)})`,
          click: () => {
            hideFlyout();
            showWindow();
            sendNavigateOrStash(trayPendingCount > 0 ? { kind: "approval" } : { kind: "registration" });
          },
        } satisfies Electron.MenuItemConstructorOptions]
      : []),
    {
      label: "Add Credential…",
      click: () => {
        hideFlyout();
        showWindow();
        sendNavigateOrStash({ kind: "add-credential" });
      },
    },
    { type: "separator" },
    {
      label: "Lock UI",
      enabled: localAuthConfigured && !uiLocked,
      click: () => {
        lockUiAction();
      },
    },
    {
      label: "Lock Vault Daemon",
      enabled: daemonPassphraseMode && !daemonLocked,
      click: () => {
        void lockDaemonAction().catch(() => undefined);
      },
    },
    { type: "separator" },
    {
      label: "Mute Notification Sounds",
      type: "checkbox",
      checked: prefs.soundMode === "off",
      click: (item) => {
        updatePreferences({ soundMode: item.checked ? "off" : "all" });
      },
    },
    {
      label: "Start Minimized at Login",
      type: "checkbox",
      checked: prefs.startMinimizedAtLogin,
      enabled: app.isPackaged,
      click: (item) => {
        updatePreferences({ startMinimizedAtLogin: item.checked });
      },
    },
    { type: "separator" },
    {
      label: "Open MetaVault OSS",
      click: () => {
        hideFlyout();
        showWindow();
      },
    },
    {
      label: "Quit MetaVault OSS",
      click: () => {
        isQuitting = true;
        app.quit();
      },
    },
  ];
  return Menu.buildFromTemplate(menuTemplate);
}

function refreshTray(): void {
  if (tray === null) return;
  const state = currentTrayState();
  const totalPending = totalPendingCount();
  if (trayBaseIconPath === null || !existsSync(trayBaseIconPath)) {
    if (trayBaseIconPath === null) trayBaseIconPath = join(here, "renderer", process.platform === "win32" ? "icon.ico" : "tray.png");
    if (!existsSync(trayBaseIconPath)) {
      tray.setToolTip(trayTooltip(state, totalPending));
      return;
    }
  }
  const base = nativeImage.createFromPath(trayBaseIconPath);
  const composed = composeTrayIcon(base, state);
  tray.setImage(composed);
  tray.setToolTip(trayTooltip(state, totalPending));
  if (process.platform !== "darwin") {
    tray.setContextMenu(buildTrayMenu(state));
  }
  if (process.platform === "win32" && mainWindow !== null && !mainWindow.isDestroyed()) {
    if (state === "unlocked-idle") {
      mainWindow.setOverlayIcon(null, "");
    } else {
      mainWindow.setOverlayIcon(composed, trayTooltip(state, totalPending));
    }
  }
}

let priorTunnelStatus: string | null = null;

function lockUiAction(): void {
  if (!localAuthConfigured) return;
  uiLocked = true;
  hideFlyout();
  playSound("vault-locked");
  broadcastLockState();
}

async function lockDaemonAction(): Promise<void> {
  await callDaemon({ method: "POST", path: "/lock", body: {} });
  daemonLocked = true;
  if (localAuthConfigured) {
    uiLocked = true;
  }
  hideFlyout();
  playSound("vault-locked");
  broadcastLockState();
}

// --- Flyout state ---

async function pushFlyoutState(): Promise<void> {
  const contents = flyoutWebContents();
  if (contents === null) return;
  const lockedNow = uiLocked || daemonLocked;
  const canLockDaemon = daemonPassphraseMode && !daemonLocked;
  if (lockedNow && prefs.redactToastWhenLocked) {
    const redactedState: FlyoutStateLike = {
      uiLocked,
      daemonLocked,
      localAuthConfigured,
      canLockDaemon,
      soundMode: prefs.soundMode,
      pendingCount: trayPendingCount,
      registrationCount: trayRegistrationCount,
      credentialCount: 0,
      grants: [],
      registrations: [],
    };
    contents.send("metavault:flyout-state", redactedState);
    return;
  }
  const [pendingBody, regsBody, aliasesBody] = await Promise.all([
    readDaemonJson("/pending").catch(() => null),
    readDaemonJson("/agent-registrations").catch(() => null),
    readDaemonJson("/aliases").catch(() => null),
  ]);
  const allRows = pendingRows(pendingBody);
  trayPendingCount = allRows.length;
  const rows = allRows.slice(0, 6);
  const regList = typeof regsBody === "object" && regsBody !== null && Array.isArray((regsBody as { registrations?: unknown }).registrations)
    ? (regsBody as { registrations: unknown[] }).registrations
    : [];
  const regs = regList.flatMap((r) => {
    if (typeof r !== "object" || r === null) return [];
    const o = r as Record<string, unknown>;
    if (typeof o["id"] !== "string" || typeof o["agentId"] !== "string" || typeof o["name"] !== "string") return [];
    const ide = typeof o["ide"] === "string" && o["ide"] !== "" ? o["ide"] : undefined;
    return [{ id: o["id"], agentId: o["agentId"], name: o["name"], ...(ide !== undefined ? { ide } : {}) }];
  });
  trayRegistrationCount = regs.length;
  const credList = typeof aliasesBody === "object" && aliasesBody !== null && Array.isArray((aliasesBody as { aliases?: unknown }).aliases)
    ? (aliasesBody as { aliases: unknown[] }).aliases
    : [];
  refreshTray();
  const state: FlyoutStateLike = {
    uiLocked,
    daemonLocked,
    localAuthConfigured,
    canLockDaemon,
    soundMode: prefs.soundMode,
    pendingCount: allRows.length,
    registrationCount: regs.length,
    credentialCount: credList.length,
    grants: lockedNow ? [] : rows,
    registrations: lockedNow ? [] : regs,
  };
  contents.send("metavault:flyout-state", state);
}

function isAppWindowSender(event: { readonly sender: unknown; readonly senderFrame: unknown }): boolean {
  const contents = mainWindow?.webContents;
  if (contents === undefined) return false;
  if (event.sender === contents) return true;
  return event.senderFrame === contents.mainFrame;
}

function ideRuntime(): {
  readonly packaged: boolean;
  readonly execPath: string;
  readonly resourcesPath: string;
  readonly repoRoot: string;
  readonly dbPath: string;
} {
  return {
    packaged: app.isPackaged,
    execPath: process.execPath,
    resourcesPath: process.resourcesPath,
    repoRoot: join(here, "..", "..", ".."),
    dbPath: process.env["METAVAULT_DB_PATH"] ?? join(process.cwd(), "metavault.db"),
  };
}

function createWindow(): void {
  rendererReady = false;
  const isMinimizedStart = process.argv.includes("--minimized") || process.argv.includes("--hidden");
  const window = new BrowserWindow(buildWindowOptions(preloadPath, process.argv));
  window.webContents.on("will-navigate", (event) => {
    event.preventDefault();
  });
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.setMenuBarVisibility(false);
  window.removeMenu();
  mainWindow = window;
  window.once("focus", () => {
    window.flashFrame(false);
  });
  window.on("focus", () => {
    window.flashFrame(false);
  });
  window.once("ready-to-show", () => {
    if (!isMinimizedStart) {
      window.show();
      window.focus();
    }
  });
  if (!isMinimizedStart) {
    setTimeout(() => {
      if (mainWindow === window && !window.isVisible()) {
        window.show();
        window.focus();
      }
    }, 1000);
  }
  window.on("close", (event) => {
    if (shouldHideOnClose(isQuitting, prefs.minimizeToTrayOnClose)) {
      event.preventDefault();
      window.hide();
      if (!prefs.firstCloseNoticeShown) {
        updatePreferences({ firstCloseNoticeShown: true });
        if (prefs.toastNotificationsEnabled) {
          toasts.firesInfo(
            "first-close",
            "MetaVault OSS is still running in the system tray",
            "Agents can still request capabilities. Right-click the tray icon to lock or quit.",
          );
        }
      }
    }
  });
  window.on("closed", () => {
    if (mainWindow === window) {
      mainWindow = null;
    }
  });
  window.webContents.on("did-finish-load", () => {
    rendererReady = true;
    if (pendingDeeplink !== null) {
      const queued = pendingDeeplink;
      pendingDeeplink = null;
      void sendEnrichedDeeplink(window, queued);
    }
    if (pendingNavigation !== null && !uiLocked && !daemonLocked) {
      const queuedNav = pendingNavigation;
      pendingNavigation = null;
      sendNavigate(queuedNav);
    }
    broadcastLockState();
  });
  void window.loadFile(rendererPath);
}

function createTray(): void {
  const iconPath = join(here, "renderer", process.platform === "win32" ? "icon.ico" : "tray.png");
  trayBaseIconPath = existsSync(iconPath) ? iconPath : null;
  const icon = trayBaseIconPath !== null
    ? nativeImage.createFromPath(trayBaseIconPath)
    : nativeImage.createFromDataURL(
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
      );
  try {
    tray = new Tray(icon);
    tray.setToolTip(trayTooltip(currentTrayState(), totalPendingCount()));
    if (process.platform !== "darwin") {
      tray.setContextMenu(buildTrayMenu(currentTrayState()));
    }
    // 1Password/Bitwarden/Tailscale convention: left click toggles the
    // flyout; the native context menu stays on right click.
    tray.on("click", () => {
      ensureFlyout(preloadPath, join(here, "renderer"), () => {
        void pushFlyoutState();
      });
      void pushFlyoutState().catch(() => undefined);
      toggleFlyoutSafe();
    });
    if (process.platform === "darwin") {
      // macOS intercepts left click when the context menu is attached, so
      // it is popped explicitly here instead.
      tray.on("right-click", () => {
        if (tray !== null) {
          tray.popUpContextMenu(buildTrayMenu(currentTrayState()));
        }
      });
    }
  } catch (err) {
    console.warn("Failed to create tray icon:", err);
  }
}

function toggleFlyoutSafe(): void {
  if (tray === null) return;
  const trayBounds = tray.getBounds();
  const display = screen.getDisplayNearestPoint({ x: trayBounds.x, y: trayBounds.y });
  toggleFlyout(trayBounds, display.workArea);
}

const coldStartDeeplink = findVaultDeeplink(process.argv.slice(1));
if (coldStartDeeplink !== null) {
  pendingDeeplink = coldStartDeeplink;
}
// Non-add cold-start routes wait for the renderer, then route.
const coldStartAction = deeplinkActionFromArgv(process.argv.slice(1));
if (coldStartAction !== null && coldStartAction.kind !== "add") {
  pendingNavigation = actionToNavigate(coldStartAction);
}

function actionToNavigate(action: VaultDeeplinkAction): NavigateLike | null {
  if (action.kind === "approve") return { kind: "approval", id: action.grantId };
  if (action.kind === "register") return { kind: "registration", id: action.registrationId };
  if (action.kind === "audit") return { kind: "audit", id: action.requestId };
  if (action.kind === "settings") return { kind: "settings", section: action.section };
  return null; // add + unlock route at boot through their own paths
}

const hasLock = app.requestSingleInstanceLock();
if (!hasLock) {
  app.quit();
} else {
  app.on("second-instance", (_event, argv) => {
    const action = deeplinkActionFromArgv(argv);
    if (action !== null) {
      routeDeeplinkAction(action);
    } else {
      showWindow();
    }
  });
  // macOS delivers protocol URLs via open-url, not argv.
  app.on("open-url", (event, url) => {
    event.preventDefault();
    handleDeeplinkUrl(url);
  });
  void app.whenReady().then(() => {
    app.setAppUserModelId("dev.metavault.app");
    Menu.setApplicationMenu(null);
    if (app.isPackaged) {
      void ensureBundledDaemon({ execPath: process.execPath, paths: daemonPaths, baseUrl: getDaemonBaseUrl() })
        .then((result) => {
          if (typeof result.token === "string" && result.token !== "") {
            setDaemonToken(result.token);
          }
          if (result.child !== undefined) {
            bundledDaemon = result.child;
            result.child.once("exit", () => {
              if (bundledDaemon === result.child) bundledDaemon = null;
            });
          }
          // With the session token pinned, lock state and the live-event
          // stream become readable; the SSE retry loop picks this up too.
          void hydrateLockState().catch(() => undefined);
          void runMcpSelfCheck();
        })
        .catch((err: unknown) => {
          console.warn("Could not start the bundled vault daemon:", err);
        });
      // Remote access (mTLS pairing + devices) needs the bundled gateway up
      // whenever it is enabled, independent of the SSH tunnel. Nothing
      // launched it before; start it once the daemon answers. The gateway
      // refuses to run unconfigured, so this is a no-op until remote is on.
      // Diagnostics land in gateway.log (collected by the installer smoke).
      {
        const gatewayPaths = bundledGatewayPaths(process.resourcesPath, dataDir);
        void autostartGatewayWhenRemoteEnabled({
          callDaemonFn: (input) => callDaemon(input),
          ensureGatewayFn: async () => {
            const launched = await ensureBundledGateway({
              execPath: process.execPath,
              paths: gatewayPaths,
              vaultDir: dataDir,
              daemonBaseUrl: getDaemonBaseUrl(),
            });
            adoptGatewayChild(launched);
            return launched.status;
          },
          waitFn: async (ms) => new Promise((resolveTimer) => setTimeout(resolveTimer, ms)),
          logFn: (line) => {
            try {
              appendFileSync(gatewayPaths.logPath, `[main ${new Date().toISOString()}] ${line}\n`);
            } catch {
              // Logging must never break startup.
            }
          },
        }).catch(() => undefined);
      }
    }
    const presenceIssuer = new PresenceProofIssuer();
    const guardDeps = defaultGuardDeps(presenceIssuer);
    ipcMain.handle(DAEMON_CALL_CHANNEL, async (event, request: unknown) => {
      const fromApp = isAppWindowSender(event);
      const fromFlyout = !fromApp && isFlyoutSender(event);
      if (!fromApp && !fromFlyout) {
        throw new Error("MetaVault request rejected");
      }
      if (fromFlyout) {
        if (uiLocked || daemonLocked) {
          throw new Error("MetaVault UI is locked");
        }
        const reqObj = typeof request === "object" && request !== null ? (request as Record<string, unknown>) : {};
        const reqPath = typeof reqObj["path"] === "string" ? reqObj["path"] : "";
        const reqMethod = typeof reqObj["method"] === "string" ? reqObj["method"] : "";
        const allowedFlyoutCall =
          reqMethod === "POST" &&
          (reqPath === "/approve" || reqPath === "/deny" || /^\/agent-registrations\/[^/]+\/(approve|deny)$/.test(reqPath));
        if (!allowedFlyoutCall) {
          throw new Error("MetaVault flyout request rejected");
        }
      }
      const res = await guardedDaemonCall(request, guardDeps);
      if (typeof request === "object" && request !== null) {
        const reqRec = request as Record<string, unknown>;
        const path = typeof reqRec["path"] === "string" ? reqRec["path"] : "";
        const method = typeof reqRec["method"] === "string" ? reqRec["method"] : "";
        if (
          path === "/lock" ||
          path === "/unlock" ||
          path === "/setup" ||
          path === "/settings/local-auth" ||
          path === "/settings/local-auth/pin"
        ) {
          void hydrateLockState().catch(() => undefined);
        }
        if (fromFlyout && method === "POST") {
          if (path === "/approve" || path.endsWith("/approve")) {
            playSound("decision-approved");
            scheduleToastSweep();
            void pushFlyoutState().catch(() => undefined);
          } else if (path === "/deny" || path.endsWith("/deny")) {
            playSound("decision-denied");
            scheduleToastSweep();
            void pushFlyoutState().catch(() => undefined);
          }
        }
      }
      return res;
    });
    ipcMain.handle(PRESENCE_PROOF_CHANNEL, async (_event, input: unknown) => issuePresenceProof(input, guardDeps));
    ipcMain.handle("metavault:desktop-prefs:get", (event) => {
      if (!isAppWindowSender(event) && !isFlyoutSender(event)) {
        return null;
      }
      return prefs;
    });
    ipcMain.handle("metavault:desktop-prefs:update", (event, patch: unknown) => {
      if (!isAppWindowSender(event) && !isFlyoutSender(event)) {
        return { ok: false };
      }
      const applied = updatePreferences(patch);
      return applied ? { ok: true, prefs } : { ok: false };
    });
    // Lock UI = lock the window + flyout behind PIN/Hello. Renderer drives
    // the unlock screen; main tracks the flag.
    ipcMain.handle("metavault:lock-ui", (event) => {
      if (!isAppWindowSender(event) && !isFlyoutSender(event)) {
        throw new Error("MetaVault request rejected");
      }
      lockUiAction();
    });
    ipcMain.on("metavault:ui-lock-state", (event, locked: unknown) => {
      if (!isAppWindowSender(event)) {
        return;
      }
      const next = locked === true;
      if (uiLocked !== next) {
        uiLocked = next;
        if (uiLocked) {
          hideFlyout();
        } else {
          flushPendingNavigation();
        }
        broadcastLockState();
      }
    });
    // Renderer asks for the current lock state on boot.
    ipcMain.handle("metavault:lock-state-get", (event) => {
      if (!isAppWindowSender(event) && !isFlyoutSender(event)) {
        return null;
      }
      return { uiLocked, daemonLocked } satisfies LockStateLike;
    });
    // Flyout opens: push the current snapshot.
    ipcMain.on("metavault:flyout-ready", (event) => {
      if (!isFlyoutSender(event)) {
        return;
      }
      void pushFlyoutState().catch(() => undefined);
    });
    ipcMain.on("metavault:flyout-action", (event, raw: unknown) => {
      if (!isFlyoutSender(event) || typeof raw !== "object" || raw === null) {
        return;
      }
      const rec = raw as Record<string, unknown>;
      const type = rec["type"];
      if (type === "close") {
        hideFlyout();
        return;
      }
      if (type === "toggle-mute") {
        updatePreferences({ soundMode: prefs.soundMode === "off" ? "all" : "off" });
        return;
      }
      if (type === "lock-ui") {
        lockUiAction();
        return;
      }
      if (type === "lock-daemon") {
        void lockDaemonAction().catch(() => undefined);
        return;
      }
      if (type === "open-app") {
        hideFlyout();
        showWindow();
        const navRaw = rec["nav"];
        if (typeof navRaw === "object" && navRaw !== null) {
          const navRec = navRaw as Record<string, unknown>;
          const kind = navRec["kind"];
          if (
            kind === "approval" ||
            kind === "registration" ||
            kind === "unlock" ||
            kind === "audit" ||
            kind === "settings" ||
            kind === "add-credential"
          ) {
            sendNavigateOrStash({
              kind,
              ...(typeof navRec["id"] === "string" ? { id: navRec["id"] } : {}),
              ...(typeof navRec["section"] === "string" ? { section: navRec["section"] } : {}),
              ...(typeof navRec["target"] === "string" ? { target: navRec["target"] } : {}),
            });
          }
        }
      }
    });
    ipcMain.handle("metavault:runtime-paths", () => runtimePaths({ packaged: app.isPackaged, execPath: process.execPath, resourcesPath: process.resourcesPath, repoRoot: join(here, "..", "..", ".."), dbPath: process.env["METAVAULT_DB_PATH"] ?? join(process.cwd(), "metavault.db") }));
    ipcMain.handle("metavault:mcp-status", () => mcpSelfCheck);
    ipcMain.handle(IDE_CONFIG_CHANNEL, async (event, request: unknown) => {
      if (!isAppWindowSender(event)) {
        return { ok: false, reason: "rejected" };
      }
      try {
        const decoded = decodeIdeConfigRequest(request);
        const runtime = ideRuntime();
        return decoded.action === "inspect"
          ? await ideConfigIpc({ action: "inspect" }, { runtime })
          : await ideConfigIpc(decoded, { runtime });
      } catch (err) {
        return { ok: false, reason: err instanceof Error ? err.message : "malformed IDE-config request" };
      }
    });
    registerWindowsHelloIpc();
    // Hydrate lock state, mirror the login item once, and open the JSON
    // event stream that drives toasts, tray badge and chimes while hidden.
    syncSystemLoginItem();
    void hydrateLockState().catch(() => undefined);
    void sweepStaleToasts().catch(() => undefined);
    void watchDaemonEvents().catch(() => undefined);
    // App-managed SSH tunnel for Remote Connections. Off unless the user
    // completed setup and left it connected; a restart then reconnects.
    // The status channel pushes every state change to the renderer.
    const sshBinaries = resolveSshBinaries(process.platform, process.env, existsSync, !app.isPackaged);
    if (sshBinaries !== null) {
      const gatewayPaths = bundledGatewayPaths(process.resourcesPath, dataDir);
      sshTunnel = new SshTunnelManager({
        paths: sshTunnelPaths(dataDir),
        binaries: sshBinaries,
        gatewayReady: async () => {
          // The tunnel forwards the gateway's two loopback listeners, so
          // "connected" requires them to be up. In the packaged app the
          // bundled gateway is started on demand; it refuses to run
          // unconfigured, so a vault with remote access disabled simply
          // never answers here.
          if (app.isPackaged) {
            try {
              adoptGatewayChild(await ensureBundledGateway({
                execPath: process.execPath,
                paths: gatewayPaths,
                vaultDir: dataDir,
                daemonBaseUrl: getDaemonBaseUrl(),
              }));
            } catch {
              // Fall through to the listener check below.
            }
          }
          return (await gatewayListening(GATEWAY_HOST, GATEWAY_PORT)) && (await gatewayListening(GATEWAY_HOST, GATEWAY_DEVICE_PORT));
        },
        onStatus: (status) => {
          mainWindow?.webContents.send(SSH_TUNNEL_STATUS_CHANNEL, status);
          // Toast only when an established connection falls over
          // (connected -> reconnecting/error). Reconnects stay silent.
          const statusState = status.state;
          if (priorTunnelStatus === "connected" && (statusState === "reconnecting" || statusState === "error")) {
            toasts.firesTunnelDrop(
              "The SSH connection to your remote relay dropped. Check Settings > Connections.",
              prefs,
            );
          }
          priorTunnelStatus = statusState;
        },
      });
    }
    const tunnelManager = sshTunnel;
    ipcMain.handle(SSH_TUNNEL_CHANNEL, async (_event, request: unknown) => {
      if (tunnelManager === null) {
        return { kind: "error", error: "An OpenSSH client was not found on this PC. Install the Windows OpenSSH Client feature, then try again." };
      }
      return await handleSshTunnelRequest(tunnelManager, request);
    });
    if (tunnelManager !== null && tunnelManager.wantsConnection()) {
      void tunnelManager.connect();
    }
    ipcMain.on("metavault:bring-to-front", (event) => {
      if (!isAppWindowSender(event)) {
        return;
      }
      if (prefs.popWindowOnApproval) {
        bringWindowToFront();
      } else {
        flashTaskbarQuietly();
      }
    });
    createWindow();
    createTray();
    void initAutoUpdater(() => mainWindow);
    app.on("activate", () => {
      showWindow();
    });
  });
}

app.on("before-quit", () => {
  isQuitting = true;
  liveEventsDisabled = true;
});

app.on("will-quit", () => {
  if (sshTunnel !== null) {
    void sshTunnel.shutdown();
    sshTunnel = null;
  }
  if (bundledGateway !== null) {
    bundledGateway.kill();
    bundledGateway = null;
  }
  if (bundledDaemon !== null) {
    bundledDaemon.kill();
    bundledDaemon = null;
  }
});

// Tray-resident: the app deliberately does not quit when its window closes.
app.on("window-all-closed", () => {
  // No-op by design — see the close handler in createWindow.
});
