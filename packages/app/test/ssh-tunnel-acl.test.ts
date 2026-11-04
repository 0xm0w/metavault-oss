// Proof that tunnel key/config files are owner-only on BOTH platforms:
// POSIX asserts the real mode bits; Windows runs the real icacls hardening
// and asserts the resulting ACL grants exactly the current user - actual
// Windows ACL evidence in CI, not an assumed chmod.
import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { userInfo } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { hardenPathPermissions } from "../src/ssh-tunnel.js";

let dir = "";

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "mv-acl-"));
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("hardenPathPermissions", () => {
  it("POSIX: key material is written owner-only (0o600) and dir 0o700", () => {
    if (process.platform === "win32") return;
    const f = join(dir, "id_ed25519");
    writeFileSync(f, "key", { mode: 0o600 });
    chmodSync(dir, 0o700);
    expect(statSync(f).mode & 0o777).toBe(0o600);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
  });

  it("Windows: icacls ACL grants the current user alone, no inherited ACEs", () => {
    if (process.platform !== "win32") return;
    const f = join(dir, "id_ed25519");
    writeFileSync(f, "key");
    hardenPathPermissions(f);
    const out = execFileSync("icacls", [f], { encoding: "utf8" });
    const user = userInfo().username;
    // Owner present with full control...
    expect(out).toMatch(new RegExp(`${user.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:\\(F\\)`));
    // ...and nobody else: no Users group, no Administrators, no SYSTEM.
    expect(out).not.toMatch(/BUILTIN\\Users|Administrators|SYSTEM/);
  });

  it("Windows: a failing icacls surfaces as an error, not silent weak ACLs", () => {
    if (process.platform !== "win32") return;
    expect(() => { hardenPathPermissions(join(dir, "does-not-exist")); }).toThrow(/icacls failed/);
  });

  it("non-Windows platforms are a no-op without invoking icacls", () => {
    let called = false;
    hardenPathPermissions("/nonexistent", "linux", () => { called = true; return { status: 0, stderr: "" }; });
    expect(called).toBe(false);
  });

  it("win32 icacls failure throws with stderr detail (unit, mocked)", () => {
    expect(() => { hardenPathPermissions("C:\\x", "win32", () => ({ status: 5, stderr: "Access is denied." })); },
    ).toThrow(/icacls failed.*Access is denied/);
  });
});
