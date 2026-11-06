import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, openSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";

// Starts the vault daemon that ships inside the installed app
// (resources/vaultd/vaultd.cjs) when nothing answers on the daemon port.
// It runs under the app's own Electron binary in Node mode, so the user
// needs no separate Node install. This module imports no Electron APIs so
// the pieces below are unit-testable headlessly.

export const DAEMON_HEALTH_PATH = "/health";
export const DAEMON_DB_FILE = "metavault.db";

export interface BundledDaemonPaths {
  readonly script: string;
  readonly dataDir: string;
  readonly dbPath: string;
  readonly logPath: string;
}

export function bundledDaemonPaths(resourcesPath: string, dataDir: string): BundledDaemonPaths {
  return {
    script: join(resourcesPath, "vaultd", "vaultd.cjs"),
    dataDir,
    dbPath: join(dataDir, DAEMON_DB_FILE),
    logPath: join(dataDir, "vaultd.log"),
  };
}

// Environment for the bundled daemon. A fresh install has no key yet, so
// first-run setup is on: the app then asks the user for a passphrase.
// An explicit METAVAULT_DB_PATH from the user wins. The session token is
// set only on this new object, never on `base` or process.env.
export function bundledDaemonEnv(base: NodeJS.ProcessEnv, dbPath: string, token?: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...base,
    ELECTRON_RUN_AS_NODE: "1",
    METAVAULT_DB_PATH: base["METAVAULT_DB_PATH"] ?? dbPath,
    METAVAULT_FIRST_RUN_SETUP: "1",
  };
  if (token !== undefined && token !== "") {
    env["METAVAULT_DAEMON_TOKEN"] = token;
  }
  return env;
}

// The app owns the daemon token: it generates one per session and hands it
// to the bundled daemon on the child environment only. Nothing is written
// to disk or to process.env, so a same-UID IDE agent cannot read a stable
// copy of the admin secret. An explicitly set METAVAULT_DAEMON_TOKEN (e.g.
// the user running a daemon by hand) is returned as-is and not copied onto
// process.env.
export function ensureSessionDaemonToken(base: NodeJS.ProcessEnv): string {
  const existing = base["METAVAULT_DAEMON_TOKEN"];
  if (existing !== undefined && existing !== "") {
    return existing;
  }
  return randomBytes(32).toString("hex");
}

export async function daemonHealthy(baseUrl: string, timeoutMs = 1500): Promise<boolean> {
  try {
    const res = await fetch(`${baseUrl.replace(/\/+$/, "")}${DAEMON_HEALTH_PATH}`, {
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return false;
    const body = (await res.json()) as unknown;
    return typeof body === "object" && body !== null && (body as Record<string, unknown>)["service"] === "vaultd";
  } catch {
    return false;
  }
}

export interface LaunchResult {
  readonly status: "already-running" | "started" | "not-bundled" | "port-occupied";
  readonly child?: ChildProcess;
  readonly token?: string;
}

// A listener that answers /health as vaultd still has to accept this
// session's token. 401/403 means some other vault owns the port.
async function pendingAcceptsToken(baseUrl: string, token: string, timeoutMs = 1500): Promise<"ok" | "denied" | "unreachable"> {
  try {
    const res = await fetch(`${baseUrl.replace(/\/+$/, "")}/pending`, {
      headers: { "x-metavault-token": token },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status === 401 || res.status === 403) return "denied";
    return "ok";
  } catch {
    return "unreachable";
  }
}

export async function ensureBundledDaemon(options: {
  readonly execPath: string;
  readonly paths: BundledDaemonPaths;
  readonly baseUrl: string;
  readonly env?: NodeJS.ProcessEnv;
}): Promise<LaunchResult> {
  const source = options.env ?? process.env;
  const token = ensureSessionDaemonToken(source);
  if (await daemonHealthy(options.baseUrl)) {
    const pending = await pendingAcceptsToken(options.baseUrl, token);
    if (pending === "ok") return { status: "already-running", token };
    // Health says vaultd, but this token is refused or the protected route
    // did not answer. Do not spawn a second daemon on the same port.
    return { status: "port-occupied", token };
  }
  if (!existsSync(options.paths.script)) return { status: "not-bundled", token };
  mkdirSync(options.paths.dataDir, { recursive: true });
  const log = openSync(options.paths.logPath, "a");
  const child = spawn(options.execPath, [options.paths.script], {
    env: bundledDaemonEnv(source, options.paths.dbPath, token),
    stdio: ["ignore", log, log],
    windowsHide: true,
  });
  return { status: "started", child, token };
}
