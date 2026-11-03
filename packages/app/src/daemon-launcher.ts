import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, openSync } from "node:fs";
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
  const log = openSync(options.paths.logPath, "a");
  const child = spawn(options.execPath, [options.paths.script], {
    env: bundledDaemonEnv(options.env ?? process.env, options.paths.dbPath),
    stdio: ["ignore", log, log],
    windowsHide: true,
  });
  return { status: "started", child };
}
