// Agent-led IDE connection, main-process side (pure string logic).
//
// Flow: the OpenCode (or Claude/Cursor/Antigravity/VS Code) agent merges its
// own MCP config block itself following the copied agent instructions, with
// METAVAULT_AGENT_TOKEN set to the "{env:METAVAULT_AGENT_TOKEN}" placeholder
// so no secret passes through chat. The app then seals the real token into
// the file with one button. This module owns the merge/patch logic:
//
// - merge, never replace: every other key in the user's config survives
// - fail closed: invalid JSON is never rewritten
// - seal only what's needed: an existing block only has its token value
//   patched, never rebuilt
//
// The token placeholder is the one exception to "no secrets in config":
// the user never types it and it never appears in a chat.

export type IdeHost = "opencode" | "claude-code" | "cursor" | "vscode" | "antigravity";

export type ContainerKey = "mcp" | "mcpServers" | "servers";

export const AGENT_TOKEN_ENV = "METAVAULT_AGENT_TOKEN";
export const TOKEN_PLACEHOLDER = "{env:METAVAULT_AGENT_TOKEN}";

export interface IdeApplyResult {
  readonly ok: boolean;
  readonly mode: "added-block" | "patched-token" | "unchanged";
  readonly text: string;
  readonly reason?: string;
}

export interface IdeInspectResult {
  /** false when the file does not exist yet */
  readonly present: boolean;
  readonly valid: boolean;
  readonly hasBlock: boolean;
  readonly tokenState: "sealed" | "placeholder" | "missing";
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function envKeyOf(block: Record<string, unknown>): string {
  return block["environment"] !== undefined ? "environment" : "env";
}

function tokenStateOf(block: Record<string, unknown>): IdeInspectResult["tokenState"] {
  const env = asRecord(block[envKeyOf(block)]);
  const token = env === null ? undefined : env[AGENT_TOKEN_ENV];
  if (typeof token !== "string" || token.trim() === "") return "missing";
  return token.trim() === TOKEN_PLACEHOLDER ? "placeholder" : "sealed";
}

export function inspectIdeConfig(raw: string | null, containerKey: string): IdeInspectResult {
  if (raw === null) {
    return { present: false, valid: true, hasBlock: false, tokenState: "missing" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw === "" ? "{}" : raw);
  } catch {
    return { present: true, valid: false, hasBlock: false, tokenState: "missing" };
  }
  if (Array.isArray(parsed) || typeof parsed !== "object" || parsed === null) {
    return { present: true, valid: false, hasBlock: false, tokenState: "missing" };
  }
  const container = asRecord((parsed as Record<string, unknown>)[containerKey]);
  if (container === null) {
    return { present: true, valid: true, hasBlock: false, tokenState: "missing" };
  }
  const block = asRecord(container["metavault"]);
  if (block === null) {
    return { present: true, valid: true, hasBlock: false, tokenState: "missing" };
  }
  return { present: true, valid: true, hasBlock: true, tokenState: tokenStateOf(block) };
}

/**
 * Merges a MetaVault MCP entry into one config file's text.
 *
 * `raw` is the current file text ("" when new). `entry` is the renderer's
 * full per-host block (used only when the agent has not written the block
 * itself). `token` is the real agent token; when the block already carries
 * a real token, the call is a no-op ("unchanged").
 */
export interface IdeApplyInput {
  /** current file text ("" when new) */
  readonly raw: string;
  readonly containerKey: "mcp" | "mcpServers" | "servers";
  /** full per-host block; used only when the agent has not written the block itself */
  readonly entry: unknown;
  readonly token: string;
}

export function applyIdeConnect(input: IdeApplyInput): IdeApplyResult {
  const { raw, containerKey: key, entry, token } = input;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw === "" ? "{}" : raw);
  } catch {
    return { ok: false, mode: "unchanged", text: raw, reason: "existing config is not valid JSON - fix or rename it manually, nothing was written" };
  }
  const root = asRecord(parsed);
  if (root === null) {
    return { ok: false, mode: "unchanged", text: raw, reason: "existing config is not a JSON object" };
  }
  let container = asRecord(root[key]);
  if (container === null) {
    container = {};
    root[key] = container;
  }
  const block = asRecord(container["metavault"]);
  if (block === null) {
    if (typeof token !== "string" || token.trim() === "") {
      return { ok: false, mode: "unchanged", text: raw, reason: "no token provided" };
    }
    const clone = asRecord(structuredClone(entry ?? {})) ?? {};
    const entryEnvKey = clone["environment"] !== undefined ? "environment" : "env";
    const env = asRecord(clone[entryEnvKey]) ?? {};
    clone[entryEnvKey] = { ...env, [AGENT_TOKEN_ENV]: token };
    container["metavault"] = clone;
    return { ok: true, mode: "added-block", text: serialize(root, raw) };
  }
  const envKey = envKeyOf(block);
  const env = asRecord(block[envKey]) ?? {};
  const current = env[AGENT_TOKEN_ENV];
  if (typeof current === "string" && current.trim() !== "" && current.trim() !== TOKEN_PLACEHOLDER) {
    return { ok: true, mode: "unchanged", text: serialize(root, raw) };
  }
  if (token.trim() === "") {
    return { ok: false, mode: "unchanged", text: raw, reason: "no token provided" };
  }
  block[envKey] = { ...env, [AGENT_TOKEN_ENV]: token };
  return { ok: true, mode: "patched-token", text: serialize(root, raw) };
}

function serialize(root: Record<string, unknown>, raw: string): string {
  const newline = raw.endsWith("\n") || raw === "" ? "\n" : "";
  return `${JSON.stringify(root, null, 2)}${newline}`;
}
