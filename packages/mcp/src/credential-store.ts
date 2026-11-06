import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { hardenOwnerOnly } from "../../core/src/owner-acl.js";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

// Private home for the agent credential issued by a verified registration.
// The model never sees it. The file is owner-only: mode 0600 on POSIX, and on
// Windows the inherited ACL is removed and only the current user is granted
// access. If that cannot be done the credential is not stored.

export function defaultCredentialPath(agentId: string, dir?: string): string {
  const base = dir ?? join(homedir(), ".metavault", "agents");
  return join(base, `${agentId.replace(/[^a-zA-Z0-9_-]/g, "_")}.token`);
}

export function loadStoredCredential(path: string): string | undefined {
  try {
    if (!existsSync(path)) return undefined;
    const value = readFileSync(path, "utf8").trim();
    return value === "" ? undefined : value;
  } catch {
    return undefined;
  }
}

export function storeCredentialPrivately(path: string, token: string): { ok: true } | { ok: false; reason: string } {
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, token, { mode: 0o600 });
    hardenOwnerOnly(dirname(path), true);
    hardenOwnerOnly(path, false);
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message.slice(0, 120) : "write failed" };
  }
}
