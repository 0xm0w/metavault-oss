// Owner-only file protection, proven per platform:
// - POSIX: mode bits are applied AND verified (0o700 dir / 0o600 file).
// - Windows: icacls /reset + /inheritance:r + /grant:r *SID, then the
//   EFFECTIVE ACL's trustee SIDs are read back through .NET ACL APIs and
//   must be exactly the current user's SID - including a preexisting foreign
//   explicit grant (BUILTIN\Users) that must be gone after hardening. Runs
//   for real on the Windows CI runner.
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { currentWindowsUserSid, hardenPathPermissions } from "../src/ssh-tunnel.js";

let dir = "";

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "mv-acl-"));
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("hardenPathPermissions", () => {
  it("POSIX: applies and verifies owner-only mode bits", () => {
    if (process.platform === "win32") return;
    const f = join(dir, "id_ed25519");
    writeFileSync(f, "key", { mode: 0o644 }); // deliberately wrong, harden fixes it
    hardenPathPermissions(f, false);
    expect(statSync(f).mode & 0o777).toBe(0o600);
  });

  it("Windows: effective ACL ends owner-only even with a preexisting foreign grant", () => {
    if (process.platform !== "win32") return;
    const f = join(dir, "id_ed25519-win");
    writeFileSync(f, "key");
    // Preexisting foreign explicit grant that hardening must REMOVE.
    execFileSync("icacls", [f, "/grant", "BUILTIN\\Users:(R)"], { encoding: "utf8" });
    hardenPathPermissions(f, false, { allowedRoots: [dir] });
    const sid = currentWindowsUserSid();
    expect(sid).toBeDefined();
    if (sid === undefined) return;
    const escaped = f.replace(/'/g, "''");
    const out = execFileSync("powershell.exe", [
      "-NoProfile", "-NonInteractive", "-Command",
      `$sd = [System.IO.File]::GetAccessControl('${escaped}'); ` +
      "$sd.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }",
    ], { encoding: "utf8" });
    const sids = out.split(/\r?\n/).map((l) => l.trim().toUpperCase()).filter(Boolean);
    expect(sids).toEqual([sid.toUpperCase()]);
  });

  it("Windows: refuses paths outside the allowed roots", () => {
    if (process.platform !== "win32") return;
    expect(() => { hardenPathPermissions("C:\\Windows\\Temp\\x", false, { allowedRoots: [dir] }); })
      .toThrow(/outside the tunnel data root/);
  });

  it("Windows: fails closed when the user SID is unavailable", () => {
    expect(() => { hardenPathPermissions(join(dir, "f"), false, { platform: "win32", userSid: null }); },
    ).toThrow(/SID is unavailable/);
  });

  it("Windows: throws when the effective ACL still has a foreign trustee (mocked listing)", () => {
    expect(() => { hardenPathPermissions(join(dir, "f"), false, {
        platform: "win32",
        userSid: "S-1-5-21-1-2-3-1000",
        run: () => "",
        listSids: () => ["S-1-5-21-1-2-3-1000", "S-1-5-32-545"],
      }); },
    ).toThrow(/could not make .* owner-only/);
  });

  it("non-Windows never invokes icacls", () => {
    const f = join(dir, "posix-file");
    writeFileSync(f, "key");
    let icaclsRan = false;
    const run = (): string => { icaclsRan = true; return ""; };
    if (process.platform === "win32") {
      // chmodSync cannot set POSIX mode bits on a Windows host, so the POSIX
      // branch correctly fails closed here; production Windows runs never
      // take it (their platform is win32).
      expect(() => { hardenPathPermissions(f, false, { platform: "linux", run }); }).toThrow(/owner-only/);
    } else {
      hardenPathPermissions(f, false, { platform: "linux", run });
      expect(statSync(f).mode & 0o777).toBe(0o600);
    }
    expect(icaclsRan).toBe(false);
  });
});
