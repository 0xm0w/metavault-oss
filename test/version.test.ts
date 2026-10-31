import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { MCP_VERSION } from "../packages/mcp/src/server.js";
import { APP_VERSION_DISPLAY } from "../packages/app/src/renderer/model.js";

function readVersion(relativePath: string): string {
  const url = new URL(relativePath, import.meta.url);
  const parsed: unknown = JSON.parse(readFileSync(url, "utf8"));
  if (typeof parsed !== "object" || parsed === null || !("version" in parsed)) {
    throw new Error(`missing version in ${relativePath}`);
  }
  const version: unknown = parsed.version;
  if (typeof version !== "string" || version.length === 0) {
    throw new Error(`invalid version in ${relativePath}`);
  }
  return version;
}

describe("release version consistency", () => {
  it("root, app, MCP package, MCP server and renderer display versions agree", () => {
    const rootVersion = readVersion("../package.json");
    const appVersion = readVersion("../packages/app/package.json");
    const mcpPkgVersion = readVersion("../packages/mcp/package.json");
    expect(rootVersion).toBe("0.1.0-alpha.1");
    expect(appVersion).toBe(rootVersion);
    expect(mcpPkgVersion).toBe(rootVersion);
    expect(MCP_VERSION).toBe(rootVersion);
    expect(APP_VERSION_DISPLAY).toBe(rootVersion);
  });
});
