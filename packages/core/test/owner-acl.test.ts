import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  canonicalPath,
  currentWindowsUserSid,
  defaultReadAclSddl,
  hardenOwnerOnly,
} from "../src/owner-acl.js";

describe("owner-acl cross-platform hardening", () => {
  let root = "";

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "mv-core-acl-"));
  });

  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("canonicalizes existing and not-yet-created child paths", () => {
    const child = join(root, "nested", "future.key");
    expect(canonicalPath(child)).toContain("future.key");
  });

  it("enforces allowedRoots containment and Windows SID / trustee checks via injected runners", () => {
    const target = join(root, "secret.key");
    writeFileSync(target, "data", "utf8");

    const calls: (readonly string[])[] = [];
    const fakeRun = (args: readonly string[]): string => {
      calls.push(args);
      return "processed";
    };

    expect(() => { hardenOwnerOnly(target, false, "win32", fakeRun, {
        allowedRoots: [join(root, "other-subdir")],
        userSid: "S-1-5-21-100-200-300-1001",
        listSids: () => ["S-1-5-21-100-200-300-1001"],
      }); },
    ).toThrow(/outside the device credential root/);

    expect(() => { hardenOwnerOnly(target, false, "win32", fakeRun, {
        allowedRoots: [root],
        userSid: null,
        listSids: () => [],
      }); },
    ).toThrow(/current user SID is unavailable/);

    expect(() => { hardenOwnerOnly(target, false, "win32", fakeRun, {
        allowedRoots: [root],
        userSid: "S-1-5-21-100-200-300-1001",
        listSids: () => ["S-1-5-21-100-200-300-1001", "S-1-5-32-545"],
        rawSddl: () => "D:PAI(A;;FA;;;BA)",
      }); },
    ).toThrow(/could not make .* owner-only/);

    hardenOwnerOnly(target, false, "win32", fakeRun, {
      allowedRoots: [root],
      userSid: "S-1-5-21-100-200-300-1001",
      listSids: () => ["S-1-5-21-100-200-300-1001"],
    });
    expect(calls.some((args) => args.includes("/inheritance:r"))).toBe(true);
  });

  it("handles POSIX chmod verification and platform helpers safely", () => {
    const sid = currentWindowsUserSid();
    if (process.platform === "win32") {
      if (sid !== undefined) {
        expect(sid).toMatch(/^S-1-5-21-/);
      }
      const target = join(root, "sddl-probe.txt");
      writeFileSync(target, "probe", "utf8");
      expect(typeof defaultReadAclSddl(target)).toBe("string");
    } else {
      expect(sid).toBeUndefined();
      const target = join(root, "posix.key");
      writeFileSync(target, "data", { mode: 0o644 });
      hardenOwnerOnly(target, false, process.platform);
    }
  });
});
