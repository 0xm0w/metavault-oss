import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// `vi.hoisted` keeps the mock defined before the module under test imports it.
const execFileSync = vi.hoisted(() => vi.fn());
vi.mock("node:child_process", () => ({ execFileSync }));

const { deleteMasterKey, retrieveMasterKey, storeMasterKey } = await import("../src/keychain.js");

const realPlatform = process.platform;
function setPlatform(p: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", { value: p, configurable: true });
}

const key = Buffer.alloc(32, 7);
const keyB64 = key.toString("base64");

beforeEach(() => {
  execFileSync.mockReset();
});
afterEach(() => {
  setPlatform(realPlatform);
});

describe.each([
  ["darwin", "security"],
  ["linux", "secret-tool"],
  ["win32", "powershell"],
] as const)("keychain on %s", (platform, tool) => {
  beforeEach(() => {
    setPlatform(platform);
  });

  it("stores the key with the platform tool and reports success", () => {
    execFileSync.mockReturnValue("");
    expect(storeMasterKey(key)).toBe(true);
    expect(execFileSync).toHaveBeenCalledTimes(1);
    expect(execFileSync.mock.calls[0]?.[0]).toBe(tool);
  });

  it("returns false when the platform tool fails to store", () => {
    execFileSync.mockImplementation(() => {
      throw new Error("tool missing");
    });
    expect(storeMasterKey(key)).toBe(false);
  });

  it("round-trips a 32-byte key from the tool's output", () => {
    execFileSync.mockReturnValue(`${keyB64}\n`);
    expect(retrieveMasterKey()?.equals(key)).toBe(true);
    expect(execFileSync.mock.calls[0]?.[0]).toBe(tool);
  });

  it("rejects output that is not a 32-byte key", () => {
    execFileSync.mockReturnValue(Buffer.alloc(16).toString("base64"));
    expect(retrieveMasterKey()).toBeNull();
  });

  it("returns null when the tool fails to read", () => {
    execFileSync.mockImplementation(() => {
      throw new Error("not found");
    });
    expect(retrieveMasterKey()).toBeNull();
  });

  it("deletes the key and reports tool failures as false", () => {
    execFileSync.mockReturnValue("");
    expect(deleteMasterKey()).toBe(true);
    execFileSync.mockImplementation(() => {
      throw new Error("denied");
    });
    expect(deleteMasterKey()).toBe(false);
  });
});

describe("keychain secret handling", () => {
  it("passes the key on stdin, never argv, for secret-tool and PowerShell", () => {
    for (const p of ["linux", "win32"] as const) {
      setPlatform(p);
      execFileSync.mockReset();
      execFileSync.mockReturnValue("");
      storeMasterKey(key);
      const [, args, opts] = execFileSync.mock.calls[0] as [string, string[], { input?: string }];
      expect(args.join(" ")).not.toContain(keyB64);
      expect(opts.input).toBe(keyB64);
    }
  });

  it("does nothing on platforms without a supported keychain", () => {
    setPlatform("aix");
    expect(storeMasterKey(key)).toBe(false);
    expect(retrieveMasterKey()).toBeNull();
    expect(deleteMasterKey()).toBe(false);
    expect(execFileSync).not.toHaveBeenCalled();
  });

  it("still validates key length before touching the keychain", () => {
    setPlatform("linux");
    expect(() => storeMasterKey(Buffer.alloc(31))).toThrow("masterKey must be 32 bytes");
    expect(execFileSync).not.toHaveBeenCalled();
  });
});
