import { contextBridge, ipcRenderer } from "electron";
import type {
  CapabilityRequestLike,
  DeeplinkAddParams,
  LocalAuthPatchLike,
  UpdaterStatusLike,
  VaultApi,
  WardenSettingsPatch,
} from "./renderer/types.js";

// Thin IPC bridge: the sandboxed preload has no filesystem, network, or
// token access. It only forwards the fixed VaultApi operations to the main
// process over the single "openvault:daemon-call" channel; main owns the
// daemon HTTP client and the daemon token, which never crosses into the
// renderer. No generic IPC channel is exposed.
const DAEMON_CALL_CHANNEL = "openvault:daemon-call";
const DEEPLINK_CHANNEL = "openvault:deeplink-add";

function invoke(method: "GET" | "POST" | "PATCH" | "PUT" | "DELETE", path: string, body?: unknown): Promise<unknown> {
  return ipcRenderer.invoke(
    DAEMON_CALL_CHANNEL,
    body !== undefined ? { method, path, body } : { method, path },
  ) as Promise<unknown>;
}

const api: VaultApi = {
  request: (body: CapabilityRequestLike) => invoke("POST", "/request", body),
  approve: (grantId: string) => invoke("POST", "/approve", { grantId }),
  deny: (grantId: string) => invoke("POST", "/deny", { grantId }),
  approveAlways: (grantId: string) => invoke("POST", "/approve-always", { grantId }),
  revoke: (target: string) => invoke("POST", "/revoke", { target }),
  aliases: () => invoke("GET", "/aliases"),
  audit: () => invoke("GET", "/audit"),
  pending: () => invoke("GET", "/pending"),
  policies: () => invoke("GET", "/policies"),
  getSecurityPosture: () => invoke("GET", "/security/posture"),
  addCredential: (alias: string, scope: string, secret: string, website?: string, enrollmentId?: string) =>
    invoke("POST", "/credentials", {
      alias,
      scope,
      secret,
      ...(website !== undefined ? { website } : {}),
      ...(enrollmentId !== undefined && enrollmentId !== "" ? { enrollmentId } : {}),
    }),
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
  setLocalPin: (pin: string, currentPin?: string) =>
    invoke("POST", "/settings/local-auth/pin", { pin, ...(currentPin !== undefined && currentPin !== "" ? { currentPin } : {}) }),
  verifyLocalPin: (pin: string) => invoke("POST", "/settings/local-auth/verify", { pin }),
  verifyBiometric: () => invoke("POST", "/settings/local-auth/verify-biometric"),
  bringToFront: () => {
    ipcRenderer.send("openvault:bring-to-front");
  },
  checkForUpdates: () => ipcRenderer.invoke("openvault:check-for-updates"),
  quitAndInstallUpdate: () => ipcRenderer.invoke("openvault:quit-and-install"),
  onUpdaterStatus: (handler: (status: UpdaterStatusLike) => void) => {
    const listener = (_event: unknown, data: unknown): void => {
      handler(data as UpdaterStatusLike);
    };
    ipcRenderer.on("openvault:updater-status", listener);
    return () => {
      ipcRenderer.removeListener("openvault:updater-status", listener);
    };
  },
};

contextBridge.exposeInMainWorld("openvault", api);
