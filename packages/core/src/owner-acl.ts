import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, readFileSync, realpathSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";

export interface IcaclsRun {
  (args: readonly string[]): string;
}

const defaultIcaclsRun: IcaclsRun = (args) => execFileSync("icacls", [...args], { encoding: "utf8" });

export type AclSidList = (path: string) => string[];

export const defaultListAclSids: AclSidList = (path) => {
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
  let out: string;
  try {
    out = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
      encoding: "utf8",
    });
  } catch (err) {
    const detail = (err as { stderr?: string }).stderr?.trim() || (err as Error).message;
    throw new Error(`could not read ACL trustee SIDs for ${path}: ${detail}`);
  }
  return out
    .split(/\r?\n/)
    .map((line) => line.trim().toUpperCase())
    .filter((line) => line.length > 0);
};

export function defaultReadAclSddl(path: string): string {
  const tmp = join(tmpdir(), `mv-acl-${randomBytes(6).toString("hex")}.txt`);
  try {
    execFileSync("icacls", [path, "/save", tmp, "/C"], { encoding: "utf8" });
    const buf = readFileSync(tmp);
    let content = buf.toString("utf8");
    if (content.includes("\0")) content = buf.toString("utf16le");
    content = content.replace(/^\uFEFF/, "");
    return content.split(/\r?\n/).find((line) => /D:[A-Z]{0,4}\(/.test(line)) ?? "(unreadable)";
  } catch {
    return "(unavailable)";
  } finally {
    rmSync(tmp, { force: true });
  }
}

export interface HardenOptions {
  userSid?: string | null | undefined;
  allowedRoots: string[];
  listSids?: AclSidList | undefined;
  rawSddl?: ((path: string) => string) | undefined;
}

export function canonicalPath(p: string): string {
  let current = resolve(p);
  const missing: string[] = [];
  for (;;) {
    try {
      const real = realpathSync.native(current);
      return [real, ...missing.reverse()].join(sep);
    } catch {
      missing.push(basename(current));
      const parent = dirname(current);
      if (parent === current) return resolve(p);
      current = parent;
    }
  }
}

function normalizeForContain(p: string): string {
  let n = canonicalPath(p).toLowerCase().replace(/\\/g, "/");
  while (n.length > 1 && n.endsWith("/")) n = n.slice(0, -1);
  return n;
}

function assertWithinRoots(path: string, allowedRoots: string[]): void {
  const resolved = normalizeForContain(path);
  const inside = allowedRoots.some((root) => {
    const r = normalizeForContain(root);
    return resolved === r || resolved.startsWith(r + "/");
  });
  if (!inside) {
    throw new Error(`refusing to modify ACLs outside the device credential root: ${path}`);
  }
}

export function currentWindowsUserSid(): string | undefined {
  if (process.platform !== "win32") return undefined;
  try {
    const out = execFileSync("whoami", ["/user", "/fo", "csv", "/nh"], { encoding: "utf8" });
    const match = out.match(/"(S-1-5-21-[0-9-]+)"/);
    return match?.[1];
  } catch {
    return undefined;
  }
}

export function hardenOwnerOnly(
  path: string,
  isDir: boolean,
  platform: NodeJS.Platform = process.platform,
  run: IcaclsRun = defaultIcaclsRun,
  opts?: HardenOptions,
): void {
  if (opts !== undefined) {
    assertWithinRoots(path, opts.allowedRoots);
  }
  if (platform === "win32") {
    const sid = opts?.userSid === undefined ? currentWindowsUserSid() : (opts.userSid ?? undefined);
    if (sid === undefined || sid === "") {
      throw new Error("cannot harden device credentials on Windows: current user SID is unavailable");
    }
    run([path, "/reset"]);
    run([path, "/inheritance:r"]);
    run([path, "/grant:r", `*${sid}:(F)`]);
    const listSids = opts?.listSids ?? defaultListAclSids;
    const sids = listSids(path);
    if (sids.length === 0 || !sids.every((entry) => entry === sid.toUpperCase())) {
      const rawSddl = opts?.rawSddl
        ? opts.rawSddl(path)
        : opts?.listSids
          ? "(injected trustee list)"
          : defaultReadAclSddl(path);
      throw new Error(
        `refusing to store device credentials: could not make ${path} owner-only (effective ACL trustee SIDs: ${sids.join(", ") || "none"}; SDDL: ${rawSddl})`,
      );
    }
    return;
  }
  chmodSync(path, isDir ? 0o700 : 0o600);
  const mode = statSync(path).mode & 0o777;
  const expected = isDir ? 0o700 : 0o600;
  if (mode !== expected) {
    throw new Error(`refusing to store device credentials without owner-only permissions on ${path}`);
  }
}
