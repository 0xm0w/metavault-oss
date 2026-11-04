import { contextBridge, ipcRenderer } from "electron";
import type {
  CapabilityRequestLike,
  SshTunnelBeginSetupInput,
  SshTunnelStatusLike,
  PresenceProofRequestLike,
  RemoteSettingsPatchLike,
  CardInputLike,
  DeeplinkAddParams,
  AgentSecuritySettingsPatchLike,
  LocalAuthPatchLike,
  UpdaterStatusLike,
  VaultApi,
  WardenSettingsPatch,
} from "./renderer/types.js";

// Thin IPC bridge: the sandboxed preload has no filesystem, network, or
// token access. It only forwards the fixed VaultApi operations to the main
// process over the single "metavault:daemon-call" channel; main owns the
// daemon HTTP client and the daemon token, which never crosses into the
// renderer. No generic IPC channel is exposed.
const DAEMON_CALL_CHANNEL = "metavault:daemon-call";
const DEEPLINK_CHANNEL = "metavault:deeplink-add";

function invoke(method: "GET" | "POST" | "PATCH" | "PUT" | "DELETE", path: string, body?: unknown): Promise<unknown> {
  return ipcRenderer.invoke(
    DAEMON_CALL_CHANNEL,
    body !== undefined ? { method, path, body } : { method, path },
  ) as Promise<unknown>;
}

const api: VaultApi = {
  runtimePaths: () => ipcRenderer.invoke("metavault:runtime-paths"),
  request: (body: CapabilityRequestLike) => invoke("POST", "/request", body),
  approve: (grantId: string, presenceProof?: string) =>
    invoke("POST", "/approve", { grantId, ...(presenceProof !== undefined ? { __presenceProof: presenceProof } : {}) }),
  deny: (grantId: string) => invoke("POST", "/deny", { grantId }),
  approveAlways: (grantId: string, presenceProof?: string) =>
    invoke("POST", "/approve-always", { grantId, ...(presenceProof !== undefined ? { __presenceProof: presenceProof } : {}) }),
  revoke: (target: string) => invoke("POST", "/revoke", { target }),
  aliases: () => invoke("GET", "/aliases"),
  audit: () => invoke("GET", "/audit"),
  pending: () => invoke("GET", "/pending"),
  policies: () => invoke("GET", "/policies"),
  agents: () => invoke("GET", "/agents"),
  registerAgent: (id: string, name: string, rotate: boolean) => invoke("POST", rotate ? "/agents/rotate" : "/agents", { id, name }),
  revokeAgent: (id: string) => invoke("POST", "/agents/revoke", { target: id }),
  getSecurityPosture: () => invoke("GET", "/security/posture"),
  addCredential: (alias: string, scope: string, secret: string, website?: string, enrollmentId?: string) =>
    invoke("POST", "/credentials", {
      alias,
      scope,
      secret,
      ...(website !== undefined ? { website } : {}),
      ...(enrollmentId !== undefined && enrollmentId !== "" ? { enrollmentId } : {}),
    }),
  // Card fields go straight to the daemon, which validates and encrypts
  // them; the response carries only brand + last 4.
  addCard: (alias: string, card: CardInputLike, website?: string) =>
    invoke("POST", "/cards", {
      alias,
      number: card.number,
      name: card.name,
      expMonth: card.expMonth,
      expYear: card.expYear,
      cvv: card.cvv,
      ...(website !== undefined && website !== "" ? { website } : {}),
    }),
  keyStatus: () => invoke("GET", "/key/status"),
  unlockVault: (passphrase: string) => invoke("POST", "/unlock", { passphrase }),
  setupVault: (passphrase: string) => invoke("POST", "/setup", { passphrase }),
  lockVault: () => invoke("POST", "/lock"),
  onDeeplinkAdd: (handler: (params: DeeplinkAddParams) => void) => {
    // Fixed channel, validated shape only: no new privilege, just a
    // prefill notification from main. Extra keys are dropped here too.
    const listener = (_event: unknown, value: unknown): void => {
      if (typeof value !== "object" || value === null) { return; }
      const record = value as Record<string, unknown>;
      const alias = record["alias"]; const scope = record["scope"];
      const website = record["website"]; const enrollmentId = record["enrollmentId"];
      if (typeof alias !== "string" || alias === "" || alias.length > 128) { return; }
      if (typeof scope !== "string" || scope === "" || scope.length > 256) { return; }
      if (typeof website !== "string" || website.length > 253) { return; }
      if (typeof enrollmentId !== "string" || enrollmentId.length > 128) { return; }
      handler({ alias, scope, website, enrollmentId });
    };
    ipcRenderer.on(DEEPLINK_CHANNEL, listener);
    return () => { ipcRenderer.removeListener(DEEPLINK_CHANNEL, listener); };
  },
  updateCredential: (alias: string, patch: { scope?: string; website?: string; secret?: string }) =>
    invoke("PATCH", `/credentials/${encodeURIComponent(alias)}`, patch),
  deleteCredential: (alias: string) =>
    invoke("DELETE", `/credentials/${encodeURIComponent(alias)}`),
  getWardenSettings: () => invoke("GET", "/settings/warden"),
  updateWardenSettings: (patch: WardenSettingsPatch) => invoke("PATCH", "/settings/warden", patch),
  setWardenKey: (key: string) => invoke("PUT", "/settings/warden/key", { key }),
  deleteWardenKey: () => invoke("DELETE", "/settings/warden/key"),
  wardenKeyStatus: () => invoke("GET", "/settings/warden/key"),
  testWarden: () => invoke("POST", "/settings/warden/test"),
  getLocalAuthStatus: () => invoke("GET", "/settings/local-auth"),
  updateLocalAuthSettings: (patch: LocalAuthPatchLike) => invoke("PATCH", "/settings/local-auth", patch),
  getAgentSecuritySettings: () => invoke("GET", "/settings/security"),
  updateAgentSecuritySettings: (patch: AgentSecuritySettingsPatchLike) => invoke("PATCH", "/settings/security", patch),
  // Remote Connections: pairing and device management. The daemon token
  // stays in main; the renderer only ever sees session/device state, never
  // the pairing code once consumed, and never any secret material.
  getRemoteSettings: () => invoke("GET", "/settings/remote"),
  updateRemoteSettings: (patch: RemoteSettingsPatchLike, presenceProof?: string) =>
    invoke("PATCH", "/settings/remote", { ...patch, ...(presenceProof !== undefined ? { __presenceProof: presenceProof } : {}) }),
  requestPresenceProof: (req: PresenceProofRequestLike) =>
    ipcRenderer.invoke("metavault:presence-proof", req) as Promise<{ token: string }>,
  listDevices: () => invoke("GET", "/devices"),
  startPairing: () => invoke("POST", "/devices/pair", {}),
  getPairingSession: () => invoke("GET", "/devices/pairing"),
  confirmPairing: (pairingId: string) => invoke("POST", "/devices/pairing/confirm", { pairingId }),
  cancelPairing: (pairingId: string) => invoke("POST", "/devices/pairing/cancel", { pairingId }),
  renameDevice: (id: string, name: string) => invoke("POST", "/devices/rename", { id, name }),
  revokeDevice: (target: string) => invoke("POST", "/devices/revoke", { target }),
  setDeviceAliasPolicy: (deviceId: string, alias: string, allowWrite: boolean) =>
    invoke("POST", "/devices/policy", { deviceId, alias, allowWrite }),
  listDeviceAliasPolicies: (deviceId: string) =>
    invoke("GET", `/devices/policies/${encodeURIComponent(deviceId)}`),
  setLocalPin: (pin: string, currentPin?: string) =>
    invoke("POST", "/settings/local-auth/pin", { pin, ...(currentPin !== undefined && currentPin !== "" ? { currentPin } : {}) }),
  verifyLocalPin: (pin: string) => invoke("POST", "/settings/local-auth/verify", { pin }),
  verifyBiometric: () => invoke("POST", "/settings/local-auth/verify-biometric"),
  windowsHelloAvailability: () => ipcRenderer.invoke("metavault:windows-hello-availability"),
  verifyWindowsHello: (purpose: "setup" | "unlock") => ipcRenderer.invoke("metavault:windows-hello-verify", purpose),
  sshTunnelStatus: () => ipcRenderer.invoke("metavault:ssh-tunnel", { action: "status" }),
  sshTunnelBeginSetup: (input: SshTunnelBeginSetupInput) =>
    ipcRenderer.invoke("metavault:ssh-tunnel", {
      action: "begin-setup",
      address: input.address,
      ...(input.remotePairingPort !== undefined ? { remotePairingPort: input.remotePairingPort } : {}),
      ...(input.remoteDevicePort !== undefined ? { remoteDevicePort: input.remoteDevicePort } : {}),
    }),
  sshTunnelCompleteSetup: (fingerprint: string) =>
    ipcRenderer.invoke("metavault:ssh-tunnel", { action: "complete-setup", fingerprint }),
  sshTunnelCancelSetup: () => ipcRenderer.invoke("metavault:ssh-tunnel", { action: "cancel-setup" }),
  sshTunnelConnect: () => ipcRenderer.invoke("metavault:ssh-tunnel", { action: "connect" }),
  sshTunnelDisconnect: () => ipcRenderer.invoke("metavault:ssh-tunnel", { action: "disconnect" }),
  sshTunnelRemove: () => ipcRenderer.invoke("metavault:ssh-tunnel", { action: "remove" }),
  sshTunnelSetAutoReconnect: (enabled: boolean) =>
    ipcRenderer.invoke("metavault:ssh-tunnel", { action: "set-auto-reconnect", enabled }),
  onSshTunnelStatus: (handler: (status: SshTunnelStatusLike) => void) => {
    // Fixed channel; the payload is projected through model.ts validation
    // by the renderer before use. Extra keys are dropped there.
    const listener = (_event: unknown, value: unknown) => {
      handler(value as SshTunnelStatusLike);
    };
    ipcRenderer.on("metavault:ssh-tunnel-status", listener);
    return () => { ipcRenderer.removeListener("metavault:ssh-tunnel-status", listener); };
  },
  bringToFront: () => {
    ipcRenderer.send("metavault:bring-to-front");
  },
  checkForUpdates: () => ipcRenderer.invoke("metavault:check-for-updates"),
  quitAndInstallUpdate: () => ipcRenderer.invoke("metavault:quit-and-install"),
  onUpdaterStatus: (handler: (status: UpdaterStatusLike) => void) => {
    const listener = (_event: unknown, data: unknown): void => {
      handler(data as UpdaterStatusLike);
    };
    ipcRenderer.on("metavault:updater-status", listener);
    return () => {
      ipcRenderer.removeListener("metavault:updater-status", listener);
    };
  },
};

contextBridge.exposeInMainWorld("metavault", api);
