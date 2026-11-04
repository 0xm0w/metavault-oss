// TEMPORARY CI diagnostic (deleted before merge): settles, on a real Windows
// runner, that the mscorlib ACL APIs used by device-client's
// defaultListAclSids work through the exact node execFileSync spawn path,
// for BOTH directories and files. Prints only SIDs and SDDL - no secrets.
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function listSids(path) {
  const escaped = path.replace(/'/g, "''");
  const script =
    "$ErrorActionPreference = 'Stop'; " +
    "try { " +
    `$p = '${escaped}'; ` +
    "$sd = $null; " +
    "if ([System.IO.Directory]::Exists($p)) { $sd = [System.IO.Directory]::GetAccessControl($p) } " +
    "elseif ([System.IO.File]::Exists($p)) { $sd = [System.IO.File]::GetAccessControl($p) } " +
    "else { throw ('path not found: ' + $p) } " +
    "$sd.Access | ForEach-Object { " +
    "try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } " +
    "catch { $_.IdentityReference.Value } } " +
    "} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }";
  const out = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    encoding: "utf8",
  });
  return out.split(/\r?\n/).map((l) => l.trim().toUpperCase()).filter(Boolean);
}

const whoami = execFileSync("whoami", ["/user", "/fo", "csv", "/nh"], { encoding: "utf8" });
const sid = whoami.match(/"(S-1-5-21-[0-9-]+)"/)?.[1];
console.log("current user SID resolved:", sid ? "yes" : "NO");
if (!sid) process.exit(1);

let failed = false;
for (const kind of ["dir", "file"]) {
  const dir = mkdtempSync(join(tmpdir(), `mv-acl-diag-${kind}-`));
  const target = kind === "dir" ? dir : join(dir, "key.pem");
  if (kind === "file") writeFileSync(target, "k");
  // Same hardening sequence as production:
  execFileSync("icacls", [target, "/reset"], { encoding: "utf8" });
  execFileSync("icacls", [target, "/inheritance:r"], { encoding: "utf8" });
  execFileSync("icacls", [target, "/grant:r", `*${sid}:(F)`], { encoding: "utf8" });
  let sids;
  try {
    sids = listSids(target);
  } catch (err) {
    console.log(`${kind}: LISTING FAILED: ${err.message}`);
    failed = true;
    continue;
  }
  const ok = sids.length === 1 && sids[0] === sid.toUpperCase();
  console.log(`${kind}: trustee SIDs = [${sids.join(", ")}] -> ${ok ? "PASS" : "FAIL (expected exactly current user)"}`);
  if (!ok) failed = true;
}
console.log(failed ? "DIAG RESULT: FAIL" : "DIAG RESULT: PASS");
process.exit(failed ? 1 : 0);
