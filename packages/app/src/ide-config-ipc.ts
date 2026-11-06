// IPC wiring for the agent-led IDE connection flow.
//
// Two actions:
// - inspect: the renderer's wizard asks, per host config, whether the
//   metavault block exists and which state its token is in. This is the
//   honest "the agent really wrote the file" check.
// - apply: one button seals the real agent token into the config the agent
//   wrote (or adds the full block when the agent never got to it). A backup
//   is written only when an existing file changes.
//
// The token travels renderer -> main over fixed IPC and lands in the user's
// MCP config file only. It is the one allowed exception to "no secrets in
// config"; everything else stays merge-protected.

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { applyIdeConnect, inspectIdeConfig, type IdeApplyResult, type IdeHost, type IdeInspectResult } from "./ide-config.js";
import { runtimePaths } from "./runtime-paths.js";
import { hardenPathPermissions } from "./ssh-tunnel.js";

export const IDE_CONFIG_CHANNEL = "metavault:ide-config";

export interface IdeConfigLocation {
  readonly host: IdeHost;
  readonly containerKey: "mcp" | "mcpServers" | "servers";
  readonly path: string;
}

export function ideConfigLocations(home: string = homedir()): readonly IdeConfigLocation[] {
  return [
    { host: "opencode", containerKey: "mcp", path: join(home, ".config", "opencode", "opencode.json") },
    { host: "claude-code", containerKey: "mcpServers", path: join(home, ".claude.json") },
    { host: "cursor", containerKey: "mcpServers", path: join(home, ".cursor", "mcp.json") },
    { host: "vscode", containerKey: "servers", path: join(home, ".vscode", "mcp.json") },
    { host: "antigravity", containerKey: "mcpServers", path: join(home, ".gemini", "antigravity", "mcp_config.json") },
  ];
}

export interface IdeConfigIo {
  readonly read: (path: string) => string | null;
  readonly write: (path: string, data: string) => void;
  readonly mkdir: (dir: string) => void;
}

export function defaultIdeConfigIo(): IdeConfigIo {
  return {
    read: (path) => (existsSync(path) ? readFileSync(path, "utf8") : null),
    write: (path, data) => {
      writeFileSync(path, data, "utf8");
      if (path.endsWith(".metavault-backup") && existsSync(path)) {
        chmodSync(path, 0o600);
        hardenPathPermissions(path, false);
      }
    },
    mkdir: (dir) => mkdirSync(dir, { recursive: true }),
  };
}

export interface IdeConfigInspectRequest {
  readonly action: "inspect";
}

export interface IdeConfigApplyRequest {
  readonly action: "apply";
  readonly host?: string;
  readonly entry?: unknown;
  readonly token?: string;
}

export type IdeConfigRequest = IdeConfigInspectRequest | IdeConfigApplyRequest;

export interface IdeConfigInspectRow {
  readonly host: string;
  readonly path: string;
  readonly result: IdeInspectResult;
}

export interface IdeConfigApplyResult {
  readonly ok: boolean;
  readonly mode?: IdeApplyResult["mode"];
  readonly path?: string;
  readonly backupPath?: string;
  readonly reason?: string;
}

export interface IdeRuntime {
  readonly packaged: boolean;
  readonly execPath: string;
  readonly resourcesPath: string;
  readonly repoRoot: string;
  readonly dbPath: string;
}

export interface IdeConfigDeps {
  readonly home?: string;
  readonly io?: IdeConfigIo;
  readonly runtime?: IdeRuntime;
}

function defaultIdeRuntime(): IdeRuntime {
  return {
    packaged: false,
    execPath: process.execPath,
    resourcesPath: "",
    repoRoot: join(dirname(fileURLToPath(import.meta.url)), "..", "..", ".."),
    dbPath: "",
  };
}

const IDE_DAEMON_URL = "http://127.0.0.1:7077";

const IDE_HOST_META: Record<string, { readonly agentId: string; readonly ideName: string; readonly opencode: boolean; readonly vscode?: boolean }> = {
  opencode: { agentId: "opencode", ideName: "OpenCode", opencode: true },
  "claude-code": { agentId: "claude-code", ideName: "Claude Code", opencode: false },
  cursor: { agentId: "cursor", ideName: "Cursor", opencode: false },
  vscode: { agentId: "vscode", ideName: "VS Code", opencode: false, vscode: true },
  antigravity: { agentId: "antigravity", ideName: "Antigravity", opencode: false },
};

function canonicalIdeEntry(host: string, runtime: IdeRuntime): Record<string, unknown> | null {
  const meta = IDE_HOST_META[host];
  if (meta === undefined) return null;
  const paths = runtimePaths(runtime);
  const env = {
    ...paths.env,
    METAVAULT_DAEMON_URL: IDE_DAEMON_URL,
    METAVAULT_AGENT_ID: meta.agentId,
    METAVAULT_IDE: meta.ideName,
  };
  if (meta.opencode) {
    return {
      type: "local",
      command: paths.command,
      args: paths.args,
      enabled: true,
      environment: env,
    };
  }
  if (meta.vscode === true) {
    return {
      type: "stdio",
      command: paths.command,
      args: paths.args,
      env,
    };
  }
  return {
    command: paths.command,
    args: paths.args,
    env,
  };
}

export function ideConfigIpc(
  request: IdeConfigInspectRequest,
  deps?: IdeConfigDeps,
): Promise<readonly IdeConfigInspectRow[]>;
export function ideConfigIpc(
  request: IdeConfigApplyRequest,
  deps?: IdeConfigDeps,
): Promise<IdeConfigApplyResult>;
export function ideConfigIpc(
  request: IdeConfigRequest,
  deps: IdeConfigDeps = {},
): Promise<readonly IdeConfigInspectRow[] | IdeConfigApplyResult> {
  const home = deps.home ?? homedir();
  const io = deps.io ?? defaultIdeConfigIo();
  if (request.action === "apply") {
    return Promise.resolve(
      applyToHostConfig({
        home,
        io,
        runtime: deps.runtime ?? defaultIdeRuntime(),
        ...(request.host !== undefined ? { host: request.host } : {}),
        ...(request.token !== undefined ? { token: request.token } : {}),
      }),
    );
  }
  return Promise.resolve(inspectAll({ home, io }));
}

function inspectAll({ home, io }: { home: string; io: IdeConfigIo }): readonly IdeConfigInspectRow[] {
  return ideConfigLocations(home).map((location) => {
    const raw = io.read(location.path);
    return { host: location.host, path: location.path, result: inspectIdeConfig(raw, location.containerKey) };
  });
}

function applyToHostConfig({
  home,
  io,
  runtime,
  host,
  token,
}: {
  home: string;
  io: IdeConfigIo;
  runtime: IdeRuntime;
  host?: string;
  token?: string;
}): IdeConfigApplyResult {
  const location = ideConfigLocations(home).find((l) => l.host === host);
  if (location === undefined) {
    return { ok: false, reason: `unknown host: ${host ?? "<none>"}` };
  }
  const entry = canonicalIdeEntry(location.host, runtime);
  const raw = io.read(location.path);
  const applied = applyIdeConnect({ raw: raw ?? "", containerKey: location.containerKey, entry, token: token ?? "" });
  if (!applied.ok) {
    return { ok: false, ...(applied.reason !== undefined ? { reason: applied.reason } : {}) };
  }
  const created = raw === null;
  let backupPath: string | undefined;
  if (!created && applied.mode !== "unchanged") {
    backupPath = `${location.path}.metavault-backup`;
    io.write(backupPath, raw);
  }
  if (applied.mode !== "unchanged") {
    io.mkdir(dirname(location.path));
    io.write(location.path, applied.text);
  }
  return { ok: true, mode: applied.mode, path: location.path, ...(backupPath !== undefined ? { backupPath } : {}) };
}
