import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { contextBridge } from "electron";
import type { CapabilityRequestLike, VaultApi } from "./renderer/types.js";

// The preload bridge is the renderer's only way out: daemon API calls to
// vaultd on 127.0.0.1, nothing else. No filesystem, no shell, no generic
// fetch/IPC channel is exposed. Responses pass through as parsed JSON; the
// daemon never puts secret values in them, and the renderer additionally
// projects every payload through whitelists before rendering.
const daemonBase = (
  process.env["OPENVAULT_DAEMON_URL"] ?? "http://127.0.0.1:7077"
).replace(/\/+$/, "");

// Daemon token for the human-decision routes: OPENVAULT_DAEMON_TOKEN, else
// the openvault.token file the daemon writes next to the vault DB. Resolved
// lazily (and cached once found) so a daemon started after this app still
// authenticates. The token never crosses into the renderer.
let cachedDaemonToken: string | undefined;
function daemonToken(): string | undefined {
  if (cachedDaemonToken !== undefined) {
    return cachedDaemonToken;
  }
  const fromEnv = process.env["OPENVAULT_DAEMON_TOKEN"];
  if (fromEnv !== undefined && fromEnv !== "") {
    cachedDaemonToken = fromEnv;
    return cachedDaemonToken;
  }
  try {
    const dbPath = process.env["OPENVAULT_DB_PATH"] ?? join(process.cwd(), "openvault.db");
    const text = readFileSync(join(dirname(dbPath), "openvault.token"), "utf8").trim();
    if (text !== "") {
      cachedDaemonToken = text;
    }
  } catch {
    // No token available yet; the daemon will 401 the guarded routes only.
  }
  return cachedDaemonToken;
}

async function call(method: "GET" | "POST", path: string, body?: unknown): Promise<unknown> {
  let response: Response;
  try {
    const token = daemonToken();
    response = await fetch(`${daemonBase}${path}`, {
      method,
      headers: {
        "content-type": "application/json",
        ...(token !== undefined ? { "x-openvault-token": token } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
  } catch {
    throw new Error("OpenVault daemon unreachable — is vaultd running?");
  }
  const text = await response.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new Error(`OpenVault daemon returned a non-JSON response (${String(response.status)})`);
  }
  if (!response.ok) {
    // Daemon error bodies carry only a tagged error name and a safe message.
    throw new Error(`OpenVault daemon error (${String(response.status)})`);
  }
  return parsed;
}

const api: VaultApi = {
  request: (body: CapabilityRequestLike) => call("POST", "/request", body),
  approve: (grantId: string) => call("POST", "/approve", { grantId }),
  deny: (grantId: string) => call("POST", "/deny", { grantId }),
  approveAlways: (grantId: string) => call("POST", "/approve-always", { grantId }),
  revoke: (target: string) => call("POST", "/revoke", { target }),
  aliases: () => call("GET", "/aliases"),
  audit: () => call("GET", "/audit"),
  pending: () => call("GET", "/pending"),
  policies: () => call("GET", "/policies"),
};

contextBridge.exposeInMainWorld("openvault", api);
