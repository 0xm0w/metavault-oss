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

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { applyIdeConnect, inspectIdeConfig, type IdeApplyResult, type IdeHost, type IdeInspectResult } from "./ide-config.js";

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

export function ideConfigIpc(
  request: IdeConfigInspectRequest,
  deps?: { home?: string; io?: IdeConfigIo },
): Promise<readonly IdeConfigInspectRow[]>;
export function ideConfigIpc(
  request: IdeConfigApplyRequest,
  deps?: { home?: string; io?: IdeConfigIo },
): Promise<IdeConfigApplyResult>;
export function ideConfigIpc(
  request: IdeConfigRequest,
  deps: { home?: string; io?: IdeConfigIo } = {},
): Promise<readonly IdeConfigInspectRow[] | IdeConfigApplyResult> {
  const home = deps.home ?? homedir();
  const io = deps.io ?? defaultIdeConfigIo();
  if (request.action === "apply") {
    return Promise.resolve(
      applyToHostConfig({
        home,
        io,
        ...(request.host !== undefined ? { host: request.host } : {}),
        ...(request.entry !== undefined ? { entry: request.entry } : {}),
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
  host,
  entry,
  token,
}: {
  home: string;
  io: IdeConfigIo;
  host?: string;
  entry?: unknown;
  token?: string;
}): IdeConfigApplyResult {
  const location = ideConfigLocations(home).find((l) => l.host === host);
  if (location === undefined) {
    return { ok: false, reason: `unknown host: ${host ?? "<none>"}` };
  }
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
