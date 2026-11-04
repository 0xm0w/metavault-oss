import { userInfo } from "node:os";
import {
  SshTunnelManager,
  type SshTunnelSetupProposal,
  type SshTunnelStatus,
} from "./ssh-tunnel.js";

// IPC surface for the app-managed SSH tunnel. Mirrors the daemon-call
// whitelist pattern: one fixed channel, a closed set of actions, every
// field type-checked before it reaches the manager. The renderer never
// passes shell fragments; the manager revalidates everything anyway.

export const SSH_TUNNEL_CHANNEL = "metavault:ssh-tunnel";
export const SSH_TUNNEL_STATUS_CHANNEL = "metavault:ssh-tunnel-status";

export type SshTunnelAction =
  | "status"
  | "begin-setup"
  | "complete-setup"
  | "cancel-setup"
  | "connect"
  | "disconnect"
  | "remove"
  | "set-auto-reconnect";

export interface SshTunnelRequest {
  readonly action: SshTunnelAction;
  readonly address?: string;
  readonly remotePairingPort?: number;
  readonly remoteDevicePort?: number;
  readonly fingerprint?: string;
  readonly enabled?: boolean;
}

const ACTIONS: ReadonlySet<string> = new Set([
  "status",
  "begin-setup",
  "complete-setup",
  "cancel-setup",
  "connect",
  "disconnect",
  "remove",
  "set-auto-reconnect",
]);

export function validateSshTunnelRequest(input: unknown): SshTunnelRequest {
  if (typeof input !== "object" || input === null) {
    throw new Error("MetaVault OSS ssh-tunnel call rejected: malformed request");
  }
  const record = input as Record<string, unknown>;
  const action = record["action"];
  if (typeof action !== "string" || !ACTIONS.has(action)) {
    throw new Error("MetaVault OSS ssh-tunnel call rejected: unknown action");
  }
  const out: {
    action: SshTunnelAction;
    address?: string;
    remotePairingPort?: number;
    remoteDevicePort?: number;
    fingerprint?: string;
    enabled?: boolean;
  } = { action: action as SshTunnelAction };
  if (action === "begin-setup") {
    const address = record["address"];
    if (typeof address !== "string" || address.trim() === "" || address.length > 320) {
      throw new Error("MetaVault OSS ssh-tunnel call rejected: invalid address");
    }
    out.address = address;
    for (const key of ["remotePairingPort", "remoteDevicePort"] as const) {
      const value = record[key];
      if (value !== undefined) {
        if (typeof value !== "number" || !Number.isInteger(value) || value < 1024 || value > 65535) {
          throw new Error("MetaVault OSS ssh-tunnel call rejected: invalid relay port");
        }
        out[key] = value;
      }
    }
  }
  if (action === "complete-setup") {
    const fingerprint = record["fingerprint"];
    if (typeof fingerprint !== "string" || fingerprint.length < 7 || fingerprint.length > 128) {
      throw new Error("MetaVault OSS ssh-tunnel call rejected: invalid fingerprint");
    }
    out.fingerprint = fingerprint;
  }
  if (action === "set-auto-reconnect") {
    const enabled = record["enabled"];
    if (typeof enabled !== "boolean") {
      throw new Error("MetaVault OSS ssh-tunnel call rejected: invalid auto-reconnect flag");
    }
    out.enabled = enabled;
  }
  return out;
}

export type SshTunnelIpcResult =
  | { readonly kind: "status"; readonly status: SshTunnelStatus }
  | { readonly kind: "proposal"; readonly proposal: SshTunnelSetupProposal }
  | { readonly kind: "error"; readonly error: string }
  | { readonly kind: "verification"; readonly verified: boolean; readonly reason?: string }
  | { readonly kind: "ok" };

// Executes one validated request against the manager. Only safe, whitelisted
// strings ever reach the renderer (the manager's own error messages carry
// no paths, secrets or raw ssh output).
export async function handleSshTunnelRequest(
  manager: SshTunnelManager,
  input: unknown,
): Promise<SshTunnelIpcResult> {
  const request = validateSshTunnelRequest(input);
  switch (request.action) {
    case "status":
      return { kind: "status", status: manager.getStatus() };
    case "begin-setup": {
      const proposal = await manager.beginSetup({
        address: request.address as string,
        ...(request.remotePairingPort !== undefined ? { remotePairingPort: request.remotePairingPort } : {}),
        ...(request.remoteDevicePort !== undefined ? { remoteDevicePort: request.remoteDevicePort } : {}),
        currentUser: safeCurrentUser(),
      });
      if ("error" in proposal) return { kind: "error", error: proposal.error };
      return { kind: "proposal", proposal };
    }
    case "complete-setup": {
      const result = await manager.completeSetup(request.fingerprint as string);
      if (!result.configured) {
        const error = result.reason === "host-key-changed"
          ? "That fingerprint does not match the key the server presented. Nothing was saved. Check the fingerprint with your server provider and start again."
          : result.reason === "server-unrestricted"
            ? "Safety check failed: this account let the key run a shell or file access, so the key line is not installed as shown. Nothing was saved. Use a dedicated account for this tunnel, install the key line exactly, then try again."
            : result.reason === "server-policy-missing"
              ? "Safety check failed: the server does not block local port forwarding for this account. Nothing was saved. Add the shown Match block to the server's sshd_config, reload sshd, then try again."
              : "Setup is no longer open. Start again.";
        return { kind: "error", error };
      }
      return { kind: "verification", verified: result.verified, ...(result.reason !== undefined ? { reason: result.reason } : {}) };
    }
    case "cancel-setup":
      manager.cancelSetup();
      return { kind: "ok" };
    case "connect":
      return { kind: "status", status: await manager.connect() };
    case "disconnect":
      return { kind: "status", status: await manager.disconnect() };
    case "remove":
      await manager.remove();
      return { kind: "status", status: manager.getStatus() };
    case "set-auto-reconnect":
      manager.setAutoReconnect(request.enabled === true);
      return { kind: "status", status: manager.getStatus() };
  }
}

function safeCurrentUser(): string {
  try {
    const name = userInfo().username;
    return typeof name === "string" && name !== "" ? name : "metavault";
  } catch {
    return "metavault";
  }
}
