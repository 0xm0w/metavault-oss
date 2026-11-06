import { mkdtempSync, rmSync, statSync, writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { defaultCredentialPath, loadStoredCredential, storeCredentialPrivately } from "../src/credential-store.js";

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), "mv-cred-"));
  dirs.push(d);
  return d;
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("credential-store", () => {
  it("sanitises the agent id into a file name inside the chosen directory", () => {
    const d = tmp();
    const p = defaultCredentialPath("../evil/agent id", d);
    expect(p.startsWith(d)).toBe(true);
    expect(p.endsWith(".token")).toBe(true);
    expect(p).not.toContain("..");
    expect(defaultCredentialPath("a", undefined)).toContain(join(".metavault", "agents"));
  });

  it.skipIf(process.platform === "win32")("stores owner-only (0600) in a private (0700) directory and reads it back trimmed", () => {
    const d = tmp();
    const p = join(d, "nested", "agent.token");
    expect(storeCredentialPrivately(p, "mvshim_synthetic-token\n")).toEqual({ ok: true });
    expect(statSync(p).mode & 0o777).toBe(0o600);
    expect(statSync(join(d, "nested")).mode & 0o777).toBe(0o700);
    expect(loadStoredCredential(p)).toBe("mvshim_synthetic-token");
  });

  it("returns undefined for a missing, empty or unreadable credential", () => {
    const d = tmp();
    expect(loadStoredCredential(join(d, "missing.token"))).toBeUndefined();
    const empty = join(d, "empty.token");
    writeFileSync(empty, "  \n");
    expect(loadStoredCredential(empty)).toBeUndefined();
    const asDir = join(d, "isdir");
    mkdirSync(asDir);
    expect(loadStoredCredential(asDir)).toBeUndefined();
  });

  it("reports failure instead of throwing when the path cannot be written", () => {
    const d = tmp();
    const blocker = join(d, "file");
    writeFileSync(blocker, "x");
    const res = storeCredentialPrivately(join(blocker, "sub", "agent.token"), "synthetic");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason.length).toBeGreaterThan(0);
  });

  it("on Windows, stores the credential from the process SID when USERNAME is empty", () => {
    if (process.platform !== "win32") return;
    const d = tmp();
    vi.stubEnv("USERNAME", "");
    const p = join(d, "agent.token");
    const res = storeCredentialPrivately(p, "synthetic");
    expect(res.ok).toBe(true);
    expect(readFileSync(p, "utf8")).toBe("synthetic");
  });

  it.skipIf(process.platform === "win32")("on Windows, reports failure when the ACL restriction cannot be applied", () => {
    const d = tmp();
    vi.spyOn(process, "platform", "get").mockReturnValue("win32");
    vi.stubEnv("USERNAME", "synthetic-user");
    vi.stubEnv("PATH", "");
    const p = join(d, "agent.token");
    const res = storeCredentialPrivately(p, "synthetic");
    expect(res.ok).toBe(false);
    expect(readFileSync(p, "utf8")).toBe("synthetic");
  });
});
