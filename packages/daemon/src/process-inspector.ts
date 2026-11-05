import { execSync } from "node:child_process";
import { readlinkSync } from "node:fs";
import { basename } from "node:path";

export interface ProcessInspectionResult {
  readonly ok: boolean;
  readonly pid: number;
  readonly binary: string;
  readonly reason?: string;
  // True when the binary is a generic runtime (node, bun, deno). A generic
  // runtime can execute arbitrarily re-written code, so its name proves
  // nothing about what the caller actually runs; such callers are accepted
  // only with an enrolled, human-approved agent token.
  readonly genericRuntime?: boolean;
}

// Generic runtimes: whitelisting them as "agents" lets any shell-executed
// script pass as an IDE agent (node -e "..."), so they are separated out and
// never enough on their own (Issue 2).
export const GENERIC_RUNTIME_BINARIES: ReadonlySet<string> = new Set([
  "node",
  "node.exe",
  "bun",
  "bun.exe",
  "deno",
  "deno.exe",
]);

export const ALLOWED_AGENT_BINARIES: ReadonlySet<string> = new Set([
  "cursor",
  "cursor.exe",
  "code",
  "code.exe",
  "code - oss",
  "electron",
  "electron.exe",
  "claude",
  "claude.exe",
  "opencode",
  "opencode.exe",
  "metavault",
  "metavault.exe",
  "metavault",
  "metavault.exe",
  "metavault oss",
  "metavault oss.exe",
  "bun",
  "bun.exe",
  "vitest",
]);

export const DISALLOWED_BINARIES: ReadonlySet<string> = new Set([
  "python",
  "python.exe",
  "python3",
  "python3.exe",
  "curl",
  "curl.exe",
  "powershell",
  "powershell.exe",
  "pwsh",
  "pwsh.exe",
  "cmd",
  "cmd.exe",
  "bash",
  "bash.exe",
  "sh",
  "zsh",
  "ruby",
  "ruby.exe",
  "perl",
  "perl.exe",
  "wget",
  "wget.exe",
  "nc",
  "ncat",
]);

// Test hook for simulated process environments
let customProcessResolver: ((pid: number) => string | null) | null = null;

export function setTestProcessResolver(resolver: ((pid: number) => string | null) | null): void {
  customProcessResolver = resolver;
}

export function resolveProcessBinary(pid: number): string | null {
  if (customProcessResolver !== null) {
    return customProcessResolver(pid);
  }

  if (pid <= 0 || !Number.isInteger(pid)) {
    return null;
  }

  // Current process fast-path
  if (pid === process.pid) {
    return basename(process.execPath || process.argv0 || "node");
  }

  if (process.platform === "win32") {
    try {
      const out = execSync(`tasklist /FI "PID eq ${String(pid)}" /FO CSV /NH`, {
        encoding: "utf8",
        timeout: 1000,
        stdio: ["ignore", "pipe", "ignore"],
      });
      // Output format: "image.exe","1234","Console","1","10,000 K"
      const match = out.match(/"([^"]+)"/);
      if (match && match[1]) {
        return match[1].trim();
      }
    } catch {
      // Fallback
    }
  } else if (process.platform === "linux") {
    try {
      // /proc/<pid>/exe is the kernel's readlink to the real image; unlike
      // /proc/<pid>/comm it cannot be renamed from userspace with
      // prctl(PR_SET_NAME). When the link is not readable for this process
      // (different user, yama ptrace scope, vanished pid) we answer
      // null: the caller verification gate fails closed rather than
      // trusting a spoofable name.
      return basename(readlinkSync(`/proc/${String(pid)}/exe`));
    } catch {
      return null;
    }
  }

  // Generic POSIX ps fallback. On Linux this is unreachable (the /proc exe
  // branch now answers null instead of falling back to a spoofable name);
  // it covers macOS and other POSIX targets without kernel peer
  // credentials, which cannot fully verify a binary name.
  try {
    const out = execSync(`ps -p ${String(pid)} -o comm=`, {
      encoding: "utf8",
      timeout: 1000,
      stdio: ["ignore", "pipe", "ignore"],
    });
    const line = out.trim().split("\n")[0]?.trim();
    if (line) {
      return basename(line);
    }
  } catch {
    // Process not found or failed
  }

  return null;
}

export function inspectProcess(pid: number): ProcessInspectionResult {
  const binary = resolveProcessBinary(pid);
  if (!binary) {
    return {
      ok: false,
      pid,
      binary: "unknown",
      reason: "process-not-found",
    };
  }

  const normalized = binary.toLowerCase();
  if (DISALLOWED_BINARIES.has(normalized)) {
    return {
      ok: false,
      pid,
      binary,
      reason: `disallowed-binary: ${binary}`,
    };
  }

  if (GENERIC_RUNTIME_BINARIES.has(normalized)) {
    return {
      ok: true,
      pid,
      binary,
      genericRuntime: true,
    };
  }

  if (ALLOWED_AGENT_BINARIES.has(normalized)) {
    return {
      ok: true,
      pid,
      binary,
    };
  }

  return {
    ok: false,
    pid,
    binary,
    reason: `unauthorized-binary: ${binary}`,
  };
}
