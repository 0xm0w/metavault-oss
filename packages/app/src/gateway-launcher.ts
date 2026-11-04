import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, openSync } from "node:fs";
import { connect } from "node:net";
import { join } from "node:path";

// Starts the remote-access gateway that ships inside the installed app
// (resources/vaultd/gateway.cjs) when the user has enabled remote access.
// Remote is OFF by default: the app only calls ensureBundledGateway after
// an explicit enable, and the gateway itself refuses any non-loopback bind
// until the user picks a real transport. This module imports no Electron
// APIs so the pieces below are unit-testable headlessly.

export const GATEWAY_PORT = 7078;
export const GATEWAY_HOST = "127.0.0.1";

export interface BundledGatewayPaths {
  readonly script: string;
  readonly dataDir: string;
  readonly logPath: string;
}

export function bundledGatewayPaths(resourcesPath: string, dataDir: string): BundledGatewayPaths {
  return {
    script: join(resourcesPath, "vaultd", "gateway.cjs"),
    dataDir,
    logPath: join(dataDir, "gateway.log"),
  };
}

// Environment for the bundled gateway. The bind is pinned to loopback
// here regardless of inherited env; widening the transport is a separate
// user decision and must never ride in on a base environment variable.
export function bundledGatewayEnv(
  base: NodeJS.ProcessEnv,
  options: { readonly vaultDir: string; readonly daemonBaseUrl: string; readonly port?: number },
): NodeJS.ProcessEnv {
  return {
    ...base,
    ELECTRON_RUN_AS_NODE: "1",
    METAVAULT_VAULT_DIR: options.vaultDir,
    METAVAULT_DAEMON_URL: options.daemonBaseUrl,
    METAVAULT_GATEWAY_HOST: GATEWAY_HOST,
    METAVAULT_GATEWAY_PORT: String(options.port ?? GATEWAY_PORT),
    METAVAULT_TRANSPORT: "loopback",
  };
}

// The gateway is mTLS: there is no unauthenticated /health to probe. A TCP
// connect that reaches the listener (even one that later fails the TLS
// handshake for lack of a client certificate) proves the port is served.
export async function gatewayListening(host: string, port: number, timeoutMs = 1500): Promise<boolean> {
  return await new Promise<boolean>((resolve) => {
    const socket = connect({ host, port, timeout: timeoutMs });
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.once("error", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

export interface GatewayLaunchResult {
  readonly status: "already-running" | "started" | "not-bundled";
  readonly child?: ChildProcess;
}

export async function ensureBundledGateway(options: {
  readonly execPath: string;
  readonly paths: BundledGatewayPaths;
  readonly vaultDir: string;
  readonly daemonBaseUrl: string;
  readonly host?: string;
  readonly port?: number;
  readonly env?: NodeJS.ProcessEnv;
}): Promise<GatewayLaunchResult> {
  const host = options.host ?? GATEWAY_HOST;
  const port = options.port ?? GATEWAY_PORT;
  if (await gatewayListening(host, port)) return { status: "already-running" };
  if (!existsSync(options.paths.script)) return { status: "not-bundled" };
  mkdirSync(options.paths.dataDir, { recursive: true });
  const log = openSync(options.paths.logPath, "a");
  const child = spawn(options.execPath, [options.paths.script], {
    env: bundledGatewayEnv(options.env ?? process.env, {
      vaultDir: options.vaultDir,
      daemonBaseUrl: options.daemonBaseUrl,
      port,
    }),
    stdio: ["ignore", log, log],
    windowsHide: true,
  });
  return { status: "started", child };
}
