import { metavaultEnv } from "./env.js";

// Daemon HTTP client for the Electron MAIN process. The daemon token lives
// only here in main: it is resolved from the environment and sent as a
// header, and it never crosses IPC into the preload or the renderer. This
// module imports no Electron APIs so the whitelist and validation logic are
// unit-testable headlessly.

export const DAEMON_CALL_CHANNEL = "metavault:daemon-call";

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
  { method: "POST", path: "/approve-session" },
  { method: "POST", path: "/revoke" },
  { method: "GET", path: "/aliases" },
  { method: "GET", path: "/audit" },
  { method: "GET", path: "/pending" },
  { method: "GET", path: "/policies" },
  { method: "GET", path: "/agents" },
  { method: "POST", path: "/agents" },
  { method: "POST", path: "/agents/rotate" },
  { method: "POST", path: "/agents/revoke" },
  { method: "GET", path: "/security/posture" },
  { method: "POST", path: "/credentials" },
  { method: "POST", path: "/cards" },
  { method: "GET", path: "/key/status" },
  { method: "POST", path: "/unlock" },
  { method: "POST", path: "/setup" },
  { method: "POST", path: "/lock" },
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
  // Remote Connections (WP4/WP5): pairing and device management. All of
  // these stay daemon-token gated in the daemon; the token never leaves
  // the main process.
  { method: "GET", path: "/settings/remote" },
  { method: "PATCH", path: "/settings/remote" },
  { method: "GET", path: "/devices" },
  { method: "POST", path: "/devices/pair" },
  { method: "GET", path: "/devices/pairing" },
  { method: "POST", path: "/devices/pairing/confirm" },
  { method: "POST", path: "/devices/pairing/cancel" },
  { method: "POST", path: "/devices/rename" },
  { method: "POST", path: "/devices/revoke" },
  { method: "POST", path: "/devices/policy" },
  { method: "GET", path: "/agent-registrations" },
];

const ALLOWED_KEYS: ReadonlySet<string> = new Set(
  ALLOWED_DAEMON_CALLS.map((call) => `${call.method} ${call.path}`),
);

const CREDENTIAL_ITEM_PATTERN = /^\/credentials\/[^/]+$/;
const AGENT_REGISTRATION_DECISION_PATTERN = /^\/agent-registrations\/reg_[a-f0-9]{24}\/(approve|deny)$/;
const DEVICE_POLICIES_PATTERN = /^\/devices\/policies\/[^/]+$/;

export function isAllowedDaemonCall(method: unknown, path: unknown): boolean {
  if (typeof method !== "string" || typeof path !== "string") {
    return false;
  }
  if (ALLOWED_KEYS.has(`${method} ${path}`)) {
    return true;
  }
  if ((method === "PATCH" || method === "DELETE") && CREDENTIAL_ITEM_PATTERN.test(path)) {
    return true;
  }
  if (method === "POST" && AGENT_REGISTRATION_DECISION_PATTERN.test(path)) {
    return true;
  }
  return method === "GET" && DEVICE_POLICIES_PATTERN.test(path);
}

export function validateDaemonCall(input: unknown): DaemonCallRequest {
  if (typeof input !== "object" || input === null) {
    throw new Error("MetaVault OSS daemon call rejected: malformed request");
  }
  const record = input as Record<string, unknown>;
  const method = record["method"];
  const path = record["path"];
  if (!isAllowedDaemonCall(method, path)) {
    throw new Error(
      `MetaVault daemon call rejected: ${String(method)} ${String(path)} is not allowed`,
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

export const DAEMON_BASE_URL = (
  metavaultEnv("DAEMON_URL") ?? "http://127.0.0.1:7077"
).replace(/\/+$/, "");
const daemonBase = DAEMON_BASE_URL;

// Daemon token for the human-decision routes: METAVAULT_DAEMON_TOKEN in the
// environment, nothing else. The daemon never writes a token file, so there
// is no on-disk copy for a same-UID IDE agent to read. When this app spawns
// the bundled daemon it generates the token and both processes share it
// through the environment. A daemon the app did not spawn (started by hand)
// must be started with METAVAULT_DAEMON_TOKEN set to the same value.
let cachedDaemonToken: string | undefined;
function daemonToken(): string | undefined {
  if (cachedDaemonToken !== undefined) {
    return cachedDaemonToken;
  }
  const fromEnv = metavaultEnv("DAEMON_TOKEN");
  if (fromEnv !== undefined && fromEnv !== "") {
    cachedDaemonToken = fromEnv;
    return cachedDaemonToken;
  }
  // No token available: guarded routes stay 401 until the env var exists.
  return undefined;
}

const daemonFetch = async (method: string, path: string, body: unknown): Promise<Response> => {
  const token = daemonToken();
  return fetch(`${daemonBase}${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      ...(token !== undefined ? { "x-metavault-token": token } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
};

export async function callDaemon(input: unknown): Promise<unknown> {
  const { method, path, body } = validateDaemonCall(input);
  let response: Response;
  try {
    response = await daemonFetch(method, path, body);
    if (response.status === 401) {
      // The daemon token is environment-only, so it does not rotate on a
      // daemon restart the way the old on-disk token did. A relaunched app
      // shares the session token with the daemon it spawns (gateway
      // autostart, renderer IPC after a daemon bounce). Re-read the
      // environment once on 401 and retry: harmless when unchanged.
      cachedDaemonToken = undefined;
      response = await daemonFetch(method, path, body);
    }
  } catch {
    throw new Error("MetaVault OSS daemon unreachable — is vaultd running?");
  }
  const text = await response.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new Error(`MetaVault OSS daemon returned a non-JSON response (${String(response.status)})`);
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
      throw new Error(`MetaVault OSS daemon error (${String(response.status)}): ${safeTag}`);
    }
    // Daemon error bodies carry only a tagged error name and a safe message.
    throw new Error(`MetaVault OSS daemon error (${String(response.status)})`);
  }
  return parsed;
}
