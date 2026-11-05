// Agent-led IDE connection (main process, pure string-level logic):
// the OpenCode agent merges its own mcpServers entry with a token
// placeholder; the app later seals the real token in. Merge must never
// clobber the rest of the user's config and must fail closed on invalid
// JSON.
import { describe, expect, it } from "vitest";
import { applyIdeConnect, inspectIdeConfig } from "../src/ide-config.js";

const ENTRY = {
  type: "local",
  command: "C:\\Apps\\MetaVault OSS.exe",
  args: ["C:\\Apps\\resources\\vaultd\\mcp.cjs"],
  enabled: true,
  environment: {
    ELECTRON_RUN_AS_NODE: "1",
    METAVAULT_AGENT_ID: "opencode",
    METAVAULT_AGENT_TOKEN: "{env:METAVAULT_AGENT_TOKEN}",
    METAVAULT_IDE: "OpenCode",
  },
};

describe("applyIdeConnect", () => {
  it("creates the block in an empty config (full file placeholder)", () => {
    const out = applyIdeConnect({ raw: "", containerKey: "mcp", entry: ENTRY, token: "real-token" });
    expect(out.ok).toBe(true);
    expect(out.mode).toBe("added-block");
    const parsed = JSON.parse(out.text) as { mcp: { metavault: { environment: Record<string, string> } } };
    expect(parsed.mcp.metavault.environment["METAVAULT_AGENT_TOKEN"]).toBe("real-token");
  });

  it("merges into an existing config and preserves sibling content", () => {
    const existing = JSON.stringify({
      $schema: "https://opencode.ai/config.json",
      provider: { openai: { name: "x" } },
      mcp: { other: { type: "local", command: "foo" } },
    });
    const out = applyIdeConnect({ raw: existing, containerKey: "mcp", entry: ENTRY, token: "real-token" });
    expect(out.ok).toBe(true);
    const parsed = JSON.parse(out.text) as Record<string, unknown>;
    expect(parsed["$schema"]).toBe("https://opencode.ai/config.json");
    const mcp = parsed["mcp"] as Record<string, unknown>;
    expect(mcp["other"]).toEqual({ type: "local", command: "foo" });
    const token = (mcp["metavault"] as { environment: Record<string, string> }).environment["METAVAULT_AGENT_TOKEN"];
    expect(token).toBe("real-token");
  });

  it("patches only the token when the agent already wrote the block (env placeholder, environment key)", () => {
    const existing = JSON.stringify({ mcp: { metavault: ENTRY, other: { type: "local", command: "foo" } } });
    const out = applyIdeConnect({ raw: existing, containerKey: "mcp", entry: ENTRY, token: "real-token" });
    expect(out.ok).toBe(true);
    expect(out.mode).toBe("patched-token");
    const mcp = (JSON.parse(out.text) as { mcp: Record<string, unknown> }).mcp;
    const block = mcp["metavault"] as { type: string; environment: Record<string, string> };
    expect(block.type).toBe("local");
    expect(block.environment["METAVAULT_AGENT_TOKEN"]).toBe("real-token");
    expect(block.environment["ELECTRON_RUN_AS_NODE"]).toBe("1");
    expect(mcp["other"]).toEqual({ type: "local", command: "foo" });
  });

  it("patches the token when the block uses the env key (Claude/Cursor shape)", () => {
    const block = {
      command: "exe",
      args: ["mcp.cjs"],
      env: {
        METAVAULT_AGENT_TOKEN: "{env:METAVAULT_AGENT_TOKEN}",
        METAVAULT_AGENT_ID: "claude-code",
      },
    };
    const existing = JSON.stringify({ mcpServers: { metavault: block } });
    const out = applyIdeConnect({ raw: existing, containerKey: "mcpServers", entry: ENTRY, token: "real-token" });
    expect(out.ok).toBe(true);
    expect(out.mode).toBe("patched-token");
    const mcp = (JSON.parse(out.text) as { mcpServers: Record<string, unknown> }).mcpServers;
    const sealed = (mcp["metavault"] as { env: Record<string, string> }).env;
    expect(sealed["METAVAULT_AGENT_TOKEN"]).toBe("real-token");
  });

  it("leaves a block with a real token untouched", () => {
    const block = { command: "exe", env: { METAVAULT_AGENT_TOKEN: "already-real" } };
    const existing = JSON.stringify({ mcpServers: { metavault: block } });
    const out = applyIdeConnect({ raw: existing, containerKey: "mcpServers", entry: ENTRY, token: "fresh" });
    expect(out.ok).toBe(true);
    expect(out.mode).toBe("unchanged");
    const text = (JSON.parse(out.text) as { mcpServers: Record<string, unknown> }).mcpServers;
    expect((text["metavault"] as { env: Record<string, string> }).env["METAVAULT_AGENT_TOKEN"]).toBe("already-real");
  });

  it("fails closed on invalid JSON and never writes", () => {
    const out = applyIdeConnect({ raw: "{ mcp: broken", containerKey: "mcp", entry: ENTRY, token: "real-token" });
    expect(out.ok).toBe(false);
    expect(out.reason).toContain("not valid JSON");
  });

  it("failed inspect reports hasBlock false on invalid JSON", () => {
    const out = inspectIdeConfig("{ mcp: broken", "mcp");
    expect(out.valid).toBe(false);
    expect(out.hasBlock).toBe(false);
    expect(out.present).toBe(true);
  });

  it("inspect reports the three token states", () => {
    expect(inspectIdeConfig(null, "mcp")).toEqual({ present: false, valid: true, hasBlock: false, tokenState: "missing" });
    const placeholder = JSON.stringify({ mcp: { metavault: ENTRY } });
    expect(inspectIdeConfig(placeholder, "mcp").tokenState).toBe("placeholder");
    const sealed = JSON.stringify({ mcp: { metavault: { environment: { METAVAULT_AGENT_TOKEN: "real" } } } });
    expect(inspectIdeConfig(sealed, "mcp").tokenState).toBe("sealed");
  });
});
