import { contextBridge, ipcRenderer } from "electron";
import type { CapabilityRequestLike, VaultApi } from "./renderer/types.js";

// Thin IPC bridge: the sandboxed preload has no filesystem, network, or
// token access. It only forwards the fixed VaultApi operations to the main
// process over the single "openvault:daemon-call" channel; main owns the
// daemon HTTP client and the daemon token, which never crosses into the
// renderer. No generic IPC channel is exposed.
const DAEMON_CALL_CHANNEL = "openvault:daemon-call";

function invoke(method: "GET" | "POST", path: string, body?: unknown): Promise<unknown> {
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
};

contextBridge.exposeInMainWorld("openvault", api);
