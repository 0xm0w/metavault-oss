// Main-process IDE config IPC: inspect (for the wizard's live check) and
// apply (seal the token). IO is injectable so tests run on in-memory files.
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ideConfigIpc,
  type IdeConfigIo,
} from "../src/ide-config-ipc.js";

function memoryIo(files: Map<string, string>): IdeConfigIo {
  return {
    read: (path) => files.get(path) ?? null,
    write: (path, data) => {
      files.set(path, data);
    },
    mkdir: () => undefined,
  };
}

const HOME = "C:\\Users\\demo";
const OPENCODE_PATH = join(HOME, ".config", "opencode", "opencode.json");

const ENTRY = {
  command: "exe",
  args: ["mcp.cjs"],
  environment: { METAVAULT_AGENT_TOKEN: "{env:METAVAULT_AGENT_TOKEN}", METAVAULT_AGENT_ID: "opencode" },
};

describe("ideConfigIpc inspect", () => {
  it("returns one row per supported host with the token state", async () => {
    const files = new Map<string, string>();
    files.set(OPENCODE_PATH, JSON.stringify({ mcp: { metavault: ENTRY } }));
    const rows = await ideConfigIpc({ action: "inspect" }, { home: HOME, io: memoryIo(files) });
    expect(rows).toHaveLength(4);
    const opencode = rows.find((r) => r.host === "opencode");
    expect(opencode?.path).toBe(OPENCODE_PATH);
    expect(opencode?.result.hasBlock).toBe(true);
  });
});

describe("ideConfigIpc apply", () => {
  it("patches the token into an existing agent-written block, with a backup", async () => {
    const files = new Map<string, string>();
    files.set(OPENCODE_PATH, JSON.stringify({ provider: { x: 1 }, mcp: { metavault: ENTRY } }));
    const out = await ideConfigIpc(
      { action: "apply", host: "opencode", entry: ENTRY, token: "real-token" },
      { home: HOME, io: memoryIo(files) },
    );
    expect(out.ok).toBe(true);
    expect(out.path).toBe(OPENCODE_PATH);
    expect(out.backupPath).toBeDefined();
    const written = JSON.parse(files.get(OPENCODE_PATH) as string) as Record<string, unknown>;
    const block = ((written["mcp"] as Record<string, unknown>)["metavault"]) as { environment: Record<string, string> };
    expect(block.environment["METAVAULT_AGENT_TOKEN"]).toBe("real-token");
    expect(files.get(out.backupPath as string)).toBe(JSON.stringify({ provider: { x: 1 }, mcp: { metavault: ENTRY } }));
  });

  it("creates the file when missing and skips the backup", async () => {
    const files = new Map<string, string>();
    const out = await ideConfigIpc(
      { action: "apply", host: "opencode", entry: ENTRY, token: "real-token" },
      { home: HOME, io: memoryIo(files) },
    );
    expect(out.ok).toBe(true);
    expect(out.mode).toBe("added-block");
    expect(out.backupPath).toBeUndefined();
    expect(files.get(OPENCODE_PATH)).toContain("real-token");
  });

  it("ignores a renderer-supplied command and writes the canonical runtime", async () => {
    const files = new Map<string, string>();
    const out = await ideConfigIpc(
      { action: "apply", host: "opencode", entry: { command: "evil.exe", args: ["x"] }, token: "real-token" },
      { home: HOME, io: memoryIo(files) },
    );
    expect(out.ok).toBe(true);
    const written = files.get(OPENCODE_PATH) ?? "";
    expect(written).not.toContain("evil.exe");
    const parsed = JSON.parse(written) as { mcp: { metavault: { command: string } } };
    expect(parsed.mcp.metavault.command).toBe(process.execPath);
    expect(parsed.mcp.metavault.command).not.toBe("evil.exe");
  });

  it("refuses unknown hosts", async () => {
    const out = await ideConfigIpc(
      { action: "apply", host: "sudo", entry: ENTRY, token: "real-token" },
      { home: HOME, io: memoryIo(new Map()) },
    );
    expect(out.ok).toBe(false);
    expect(out.reason).toContain("unknown host");
  });

  it("reports the invalid-JSON failure instead of writing", async () => {
    const files = new Map<string, string>();
    files.set(OPENCODE_PATH, "{ mcp: broken");
    const out = await ideConfigIpc(
      { action: "apply", host: "opencode", entry: ENTRY, token: "real-token" },
      { home: HOME, io: memoryIo(files) },
    );
    expect(out.ok).toBe(false);
    expect(out.reason).toContain("not valid JSON");
    expect(files.get(OPENCODE_PATH)).toBe("{ mcp: broken");
  });
});
