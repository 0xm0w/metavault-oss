import { describe, expect, it } from "vitest";
import { runtimePaths } from "../src/runtime-paths.js";
import { AGENT_INSTRUCTIONS } from "../src/renderer/onboarding.js";
import { readFileSync } from "node:fs";

describe("packaged MCP onboarding", () => {
  it("uses absolute shipped runtime and MCP paths even with spaces, not Node/PATH", () => {
    const paths = runtimePaths({ packaged: true, execPath: "/Program Files/MetaVault OSS/MetaVault OSS.exe", resourcesPath: "/Program Files/MetaVault OSS/resources", repoRoot: "/not-installed", dbPath: "/data/metavault.db" });
    expect(paths.command).toBe("/Program Files/MetaVault OSS/MetaVault OSS.exe");
    expect(paths.args).toEqual(["/Program Files/MetaVault OSS/resources/vaultd/mcp.cjs"]);
    expect(paths.env).toEqual({ ELECTRON_RUN_AS_NODE: "1" });
    expect(JSON.parse(JSON.stringify(paths))).toEqual(paths);
    expect(JSON.stringify(paths)).not.toContain("not-installed");
  });
  it("keeps a separate source-checkout path", () => {
    const paths = runtimePaths({ packaged: false, execPath: "/electron", resourcesPath: "/resources", repoRoot: "/repo", dbPath: "/dev/vault.db" });
    expect(paths.args).toEqual(["/repo/dist/packages/mcp/src/server.js"]);
    expect(paths.command).toBe("/electron");
    expect(paths.env).toEqual({ ELECTRON_RUN_AS_NODE: "1" });
  });
  it("keeps onboarding text static, secret-free, and policy-preserving", () => {
    expect(AGENT_INSTRUCTIONS).toContain("request_capability");
    expect(AGENT_INSTRUCTIONS).toContain("Never approve requests");
    expect(AGENT_INSTRUCTIONS).toContain("Never ask for or put secrets in chat");
    expect(AGENT_INSTRUCTIONS).not.toMatch(/ov_agent_|sk-|\$\{/);
  });
  it("ships both optional Windows MCP launchers and copies them", () => {
    for (const extension of ["cmd", "ps1"]) {
      const source = readFileSync(`packages/app/bin/metavault-mcp.${extension}`, "utf8");
      expect(source).toContain("ELECTRON_RUN_AS_NODE");
      expect(source).toContain("mcp.cjs");
      expect(source).not.toContain("dist/packages");
    }
    const copy = readFileSync("packages/app/scripts/copy-assets.mjs", "utf8");
    expect(copy).toContain("metavault-mcp.cmd");
    expect(copy).toContain("metavault-mcp.ps1");
  });
});
