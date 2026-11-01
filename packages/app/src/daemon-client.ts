import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

// Daemon HTTP client for the Electron MAIN process. The daemon token lives
// only here in main: it is resolved from the environment or the token file
// and sent as a header, and it never crosses IPC into the preload or the
// renderer. This module imports no Electron APIs so the whitelist and
// validation logic are unit-testable headlessly.

export const DAEMON_CALL_CHANNEL = "openvault:daemon-call";

export type DaemonMethod = "GET" | "POST" | "PATCH" | "PUT" | "DELETE";

export interface DaemonCallRequest {
  readonly method: DaemonMethod;
  readonly path: string;
  readonly body?: unknown;
}

// The fixed set of daemon operations the renderer may request through the
// single IPC channel. Anything outside this list is rejected in main.
export const ALLOWED_DAEMON_CALLS: readonly DaemonCallRequest[] = [
  { method: "POST", path: "/request" },
  { method: "POST", path: "/approve" },
  { method: "POST", path: "/deny" },
  { method: "POST", path: "/approve-always" },
  { method: "POST", path: "/revoke" },
  { method: "GET", path: "/aliases" },
  { method: "GET", path: "/audit" },
  { method: "GET", path: "/pending" },
  { method: "GET", path: "/policies" },
  { method: "GET", path: "/security/posture" },
  { method: "POST", path: "/credentials" },
  { method: "GET", path: "/settings/warden" },
  { method: "PATCH", path: "/settings/warden" },
  { method: "GET", path: "/settings/warden/key" },
  { method: "PUT", path: "/settings/warden/key" },
  { method: "DELETE", path: "/settings/warden/key" },
  { method: "POST", path: "/settings/warden/test" },
  { method: "GET", path: "/settings/local-auth" },
  { method: "PATCH", path: "/settings/local-auth" },
  { method: "POST", path: "/settings/local-auth/pin" },
  { method: "POST", path: "/settings/local-auth/verify" },
  { method: "GET", path: "/settings/security" },
  { method: "PATCH", path: "/settings/security" },
];

const ALLOWED_KEYS: ReadonlySet<string> = new Set(
  ALLOWED_DAEMON_CALLS.map((call) => `${call.method} ${call.path}`),
);

const CREDENTIAL_ITEM_PATTERN = /^\/credentials\/[^/]+$/;

export function isAllowedDaemonCall(method: unknown, path: unknown): boolean {
  if (typeof method !== "string" || typeof path !== "string") {
    return false;
  }
  if (ALLOWED_KEYS.has(`${method} ${path}`)) {
    return true;
  }
  return (method === "PATCH" || method === "DELETE") && CREDENTIAL_ITEM_PATTERN.test(path);
}

export function validateDaemonCall(input: unknown): DaemonCallRequest {
  if (typeof input !== "object" || input === null) {
    throw new Error("OpenVault daemon call rejected: malformed request");
  }
  const record = input as Record<string, unknown>;
  const method = record["method"];
  const path = record["path"];
  if (!isAllowedDaemonCall(method, path)) {
    throw new Error(
      `OpenVault daemon call rejected: ${String(method)} ${String(path)} is not allowed`,
    );
  }
  const validated: { method: DaemonMethod; path: string; body?: unknown } = {
    method: method as DaemonMethod,
    path: path as string,
  };
  if ("body" in record) {
    validated.body = record["body"];
  }
  return validated;
}

const daemonBase = (
  process.env["OPENVAULT_DAEMON_URL"] ?? "http://127.0.0.1:7077"
).replace(/\/+$/, "");

// Daemon token for the human-decision routes: OPENVAULT_DAEMON_TOKEN, else
// the openvault.token file the daemon writes next to the vault DB. Resolved
// lazily (and cached once found) so a daemon started after this app still
// authenticates. The token stays in the main process.
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

export async function callDaemon(input: unknown): Promise<unknown> {
  const { method, path, body } = validateDaemonCall(input);
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
    // Surface only a whitelisted safe error tag (e.g. "alias-exists") so
    // callers can show it inline; daemon bodies never carry secrets here.
    const rawError =
      typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>)["error"] : undefined;
    const rawTag =
      typeof rawError === "string"
        ? rawError
        : typeof rawError === "object" && rawError !== null
          ? (rawError as Record<string, unknown>)["_tag"]
          : undefined;
    const safeTag = typeof rawTag === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(rawTag) ? rawTag : null;
    if (safeTag !== null) {
      throw new Error(`OpenVault daemon error (${String(response.status)}): ${safeTag}`);
    }
    // Daemon error bodies carry only a tagged error name and a safe message.
    throw new Error(`OpenVault daemon error (${String(response.status)})`);
  }
  return parsed;
}
