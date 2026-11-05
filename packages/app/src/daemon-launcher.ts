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
// An explicit METAVAULT_DB_PATH from the user wins.
export function bundledDaemonEnv(base: NodeJS.ProcessEnv, dbPath: string): NodeJS.ProcessEnv {
  return {
    ...base,
    ELECTRON_RUN_AS_NODE: "1",
    METAVAULT_DB_PATH: base["METAVAULT_DB_PATH"] ?? dbPath,
    METAVAULT_FIRST_RUN_SETUP: "1",
  };
}

// The app owns the daemon token: it generates one per session, hands it to
// the bundled daemon through the environment and keeps it in its own
// process for the human-decision routes. Nothing is written to disk, so a
// same-UID IDE agent cannot read a stable copy of the admin secret. An
// explicitly set METAVAULT_DAEMON_TOKEN (e.g. the user running a daemon by
// hand) is respected, not overwritten.
export function ensureSessionDaemonToken(base: NodeJS.ProcessEnv): string {
  const existing = base["METAVAULT_DAEMON_TOKEN"];
  if (existing !== undefined && existing !== "") {
    return existing;
  }
  const token = randomBytes(32).toString("hex");
  base["METAVAULT_DAEMON_TOKEN"] = token;
  return token;
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
  readonly status: "already-running" | "started" | "not-bundled";
  readonly child?: ChildProcess;
}

export async function ensureBundledDaemon(options: {
  readonly execPath: string;
  readonly paths: BundledDaemonPaths;
  readonly baseUrl: string;
  readonly env?: NodeJS.ProcessEnv;
}): Promise<LaunchResult> {
  if (await daemonHealthy(options.baseUrl)) return { status: "already-running" };
  if (!existsSync(options.paths.script)) return { status: "not-bundled" };
  mkdirSync(options.paths.dataDir, { recursive: true });
  // Mint the session token on the env the child will inherit; when the
  // caller passed this process's env, the main process keeps the same
  // value for its own client (daemon-client resolves it lazily from env).
  const env = options.env ?? process.env;
  ensureSessionDaemonToken(env);
  const log = openSync(options.paths.logPath, "a");
  const child = spawn(options.execPath, [options.paths.script], {
    env: bundledDaemonEnv(env, options.paths.dbPath),
    stdio: ["ignore", log, log],
    windowsHide: true,
  });
  return { status: "started", child };
}
