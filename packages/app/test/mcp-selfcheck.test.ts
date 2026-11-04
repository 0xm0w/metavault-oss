import { describe, expect, it } from "vitest";
import { join } from "node:path";
import { checkMcpRuntime, EXPECTED_MCP_TOOLS } from "../src/mcp-selfcheck.js";

const fixture = join(__dirname, "fixtures", "fake-mcp-server.cjs");

function run(mode: string, timeoutMs = 8000) {
  return checkMcpRuntime({
    command: process.execPath,
    args: [fixture, mode],
    env: { ELECTRON_RUN_AS_NODE: "1" },
    daemonUrl: "http://127.0.0.1:7077",
    timeoutMs,
  });
}

describe("checkMcpRuntime", () => {
  it("reports ready with the eight expected tools and server info", async () => {
    const result = await run("ok");
    expect(result.state).toBe("ready");
    expect(result.tools).toEqual([...EXPECTED_MCP_TOOLS].sort());
    expect(result.serverName).toBe("fake-metavault");
    expect(result.checkedAt).not.toBe("");
  });

  it("fails when the server never answers", async () => {
    const result = await run("silent", 1500);
    expect(result.state).toBe("failed");
    expect(result.detail).toContain("did not answer");
  });

  it("fails when the server exits before answering", async () => {
    const result = await run("exit");
    expect(result.state).toBe("failed");
  });

  it("fails on an unexpected tool set", async () => {
    const result = await run("badtools");
    expect(result.state).toBe("failed");
    expect(result.detail).toContain("unexpected tool set");
  });

  it("reports unavailable when the server file is missing", async () => {
    const result = await checkMcpRuntime({
      command: process.execPath,
      args: [join(__dirname, "fixtures", "does-not-exist.cjs")],
      env: {},
      daemonUrl: "http://127.0.0.1:7077",
    });
    expect(result.state).toBe("unavailable");
  });
});
