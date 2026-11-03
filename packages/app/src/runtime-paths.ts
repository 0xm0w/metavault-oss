import { join } from "node:path";

// Main-owned paths only. Installed MCP uses the shipped Electron runtime,
// not PATH, an external Node install, or a developer's source checkout.
export function runtimePaths(options: { packaged: boolean; execPath: string; resourcesPath: string; repoRoot: string; dbPath: string }): { command: string; args: string[]; env: Record<string, string>; dbPath: string } {
  return {
    command: options.execPath,
    args: [options.packaged ? join(options.resourcesPath, "vaultd", "mcp.cjs") : join(options.repoRoot, "dist", "packages", "mcp", "src", "server.js")],
    env: { ELECTRON_RUN_AS_NODE: "1" },
    dbPath: options.dbPath,
  };
}
