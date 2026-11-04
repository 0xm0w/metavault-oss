import { spawn } from "node:child_process";
import { existsSync } from "node:fs";

// Launch-time check that the bundled MCP server (resources/vaultd/mcp.cjs)
// starts, completes the MCP handshake and exposes exactly the expected
// secret-blind tools. The IDE still launches and connects the server
// itself; this only proves the local runtime is ready for that connection
// before the user opens their IDE. It speaks newline-delimited JSON-RPC
// directly, the same way scripts/windows-mcp-smoke.ps1 does, so the app
// needs no MCP SDK dependency. No agent token is sent: initialize and
// tools/list are open reads that never touch secret values. This module
// imports no Electron APIs so it stays unit-testable headlessly.

export const EXPECTED_MCP_TOOLS: readonly string[] = [
  "enrollment_status",
  "grant_status",
  "list_aliases",
  "register_agent",
  "registration_status",
  "request_capability",
  "request_enrollment",
  "revoke",
];

const MCP_PROTOCOL_VERSION = "2025-03-26";

export type McpSelfCheckState = "pending" | "ready" | "failed" | "unavailable";

export interface McpSelfCheckResult {
  readonly state: McpSelfCheckState;
  // Sorted tool names on success; empty otherwise.
  readonly tools: readonly string[];
  readonly serverName?: string;
  readonly serverVersion?: string;
  // Short, user-safe explanation when state is failed/unavailable.
  readonly detail?: string;
  readonly checkedAt: string;
}

export const MCP_SELFCHECK_PENDING: McpSelfCheckResult = { state: "pending", tools: [], checkedAt: "" };

function lineRpc(id: number, method: string, params?: unknown): string {
  return JSON.stringify({ jsonrpc: "2.0", id, method, ...(params !== undefined ? { params } : {}) });
}

export async function checkMcpRuntime(options: {
  readonly command: string;
  readonly args: readonly string[];
  readonly env: Record<string, string>;
  readonly daemonUrl: string;
  readonly timeoutMs?: number;
  readonly exists?: (path: string) => boolean;
}): Promise<McpSelfCheckResult> {
  const timeoutMs = options.timeoutMs ?? 15000;
  const exists = options.exists ?? existsSync;
  const script = options.args[0];
  const checkedAt = new Date().toISOString();
  if (script === undefined || !exists(script)) {
    return { state: "unavailable", tools: [], detail: "MCP server file not found", checkedAt };
  }
  return await new Promise<McpSelfCheckResult>((resolve) => {
    const pendingServer: { name?: string; version?: string } = {};
    let buffer = "";
    let phase: "initialize" | "tools" = "initialize";
    let settled = false;
    const child = spawn(options.command, [...options.args], {
      env: { ...process.env, ...options.env, METAVAULT_DAEMON_URL: options.daemonUrl },
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    const timer = setTimeout(() => { finish({ state: "failed", tools: [], detail: "MCP server did not answer in time", checkedAt }); }, timeoutMs);
    const finish = (result: McpSelfCheckResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        child.kill();
      } catch {
        // Already gone.
      }
      resolve(result);
    };
    const fail = (detail: string): void => { finish({ state: "failed", tools: [], detail, checkedAt }); };

    const stdin = child.stdin;
    const stdout = child.stdout;
    child.once("error", () => { fail("MCP server could not start"); });
    child.once("exit", () => { fail("MCP server exited before answering"); });

    const handleLine = (line: string): void => {
      let msg: unknown;
      try {
        msg = JSON.parse(line);
      } catch {
        return;
      }
      if (typeof msg !== "object" || msg === null) return;
      const reply = msg as Record<string, unknown>;
      if (phase === "initialize" && reply["id"] === 1) {
        const result = reply["result"] as Record<string, unknown> | undefined;
        const info = result?.["serverInfo"] as Record<string, unknown> | undefined;
        if (info === undefined) {
          fail("MCP server did not complete the handshake");
          return;
        }
        if (typeof info["name"] === "string") pendingServer.name = info["name"];
        if (typeof info["version"] === "string") pendingServer.version = info["version"];
        phase = "tools";
        stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n');
        stdin.write(`${lineRpc(2, "tools/list")}\n`);
        return;
      }
      if (phase === "tools" && reply["id"] === 2) {
        const result = reply["result"] as Record<string, unknown> | undefined;
        const rawTools = result !== undefined && Array.isArray(result["tools"]) ? (result["tools"] as unknown[]) : [];
        const names = rawTools
          .map((tool) => (typeof tool === "object" && tool !== null ? (tool as Record<string, unknown>)["name"] : undefined))
          .filter((name): name is string => typeof name === "string")
          .sort();
        if (names.join(",") !== [...EXPECTED_MCP_TOOLS].sort().join(",")) {
          fail(`MCP server exposed an unexpected tool set (${names.join(", ") || "none"})`);
          return;
        }
        finish({
          state: "ready",
          tools: names,
          ...(pendingServer.name !== undefined ? { serverName: pendingServer.name } : {}),
          ...(pendingServer.version !== undefined ? { serverVersion: pendingServer.version } : {}),
          checkedAt,
        });
      }
    };

    stdout.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      for (;;) {
        const idx = buffer.indexOf("\n");
        if (idx === -1) return;
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (line !== "") handleLine(line);
        if (settled) return;
      }
    });

    stdin.write(
      `${lineRpc(1, "initialize", {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: "metavault-app-selfcheck", version: "1" },
      })}\n`,
    );
  });
}
