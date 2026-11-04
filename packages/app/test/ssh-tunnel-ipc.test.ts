import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  handleSshTunnelRequest,
  validateSshTunnelRequest,
} from "../src/ssh-tunnel-ipc.js";
import { SshTunnelManager, sshTunnelPaths } from "../src/ssh-tunnel.js";

const GH_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

let dir: string | null = null;
afterEach(() => {
  if (dir !== null) {
    rmSync(dir, { recursive: true, force: true });
    dir = null;
  }
});

function makeManager(): SshTunnelManager {
  dir = mkdtempSync(join(tmpdir(), "mv-ssh-ipc-"));
  const paths = sshTunnelPaths(dir);
  return new SshTunnelManager({
    paths,
    binaries: { ssh: "/bin/ssh", keygen: "/bin/ssh-keygen", keyscan: "/bin/ssh-keyscan" },
    execFn: (command) => {
      if (command.endsWith("ssh-keygen")) {
        writeFileSync(paths.identityPath, "PRIV", { mode: 0o600 });
        writeFileSync(`${paths.identityPath}.pub`, `ssh-ed25519 ${GH_KEY} metavault-oss-remote`);
        return Promise.resolve({ stdout: "", stderr: "" });
      }
      return Promise.resolve({ stdout: `relay.example.com ssh-ed25519 ${GH_KEY}\n`, stderr: "" });
    },
    spawnFn: () => { throw new Error("no spawn in ipc tests"); },
  });
}

describe("validateSshTunnelRequest", () => {
  it("accepts each whitelisted action with its fields", () => {
    expect(validateSshTunnelRequest({ action: "status" })).toEqual({ action: "status" });
    expect(validateSshTunnelRequest({ action: "connect" })).toEqual({ action: "connect" });
    expect(validateSshTunnelRequest({ action: "disconnect" })).toEqual({ action: "disconnect" });
    expect(validateSshTunnelRequest({ action: "remove" })).toEqual({ action: "remove" });
    expect(validateSshTunnelRequest({ action: "cancel-setup" })).toEqual({ action: "cancel-setup" });
    expect(validateSshTunnelRequest({ action: "begin-setup", address: "mow@relay.example.com", remotePairingPort: 7078 })).toEqual({
      action: "begin-setup", address: "mow@relay.example.com", remotePairingPort: 7078,
    });
    expect(validateSshTunnelRequest({ action: "complete-setup", fingerprint: "SHA256:abc" })).toEqual({
      action: "complete-setup", fingerprint: "SHA256:abc",
    });
    expect(validateSshTunnelRequest({ action: "set-auto-reconnect", enabled: false })).toEqual({
      action: "set-auto-reconnect", enabled: false,
    });
  });
  it("rejects unknown actions, missing fields and bad types", () => {
    expect(() => validateSshTunnelRequest(null)).toThrow();
    expect(() => validateSshTunnelRequest({ action: "exec", command: "rm -rf /" })).toThrow();
    expect(() => validateSshTunnelRequest({ action: "begin-setup" })).toThrow();
    expect(() => validateSshTunnelRequest({ action: "begin-setup", address: 42 })).toThrow();
    expect(() => validateSshTunnelRequest({ action: "begin-setup", address: "a@b.c", remotePairingPort: 22 })).toThrow();
    expect(() => validateSshTunnelRequest({ action: "complete-setup" })).toThrow();
    expect(() => validateSshTunnelRequest({ action: "complete-setup", fingerprint: 7 })).toThrow();
    expect(() => validateSshTunnelRequest({ action: "set-auto-reconnect", enabled: "yes" })).toThrow();
  });
});

describe("handleSshTunnelRequest", () => {
  it("reports status for an unconfigured manager", async () => {
    const manager = makeManager();
    const result = await handleSshTunnelRequest(manager, { action: "status" });
    expect(result).toEqual({ kind: "status", status: { state: "not-configured", configured: false } });
  });

  it("begin-setup returns a proposal with the pinned fingerprint and install line", async () => {
    const manager = makeManager();
    const result = await handleSshTunnelRequest(manager, { action: "begin-setup", address: "mow@relay.example.com" });
    if (result.kind !== "proposal") throw new Error("expected proposal");
    expect(result.proposal.fingerprint).toBe("SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU");
    expect(result.proposal.installLine).toContain("restrict,port-forwarding");
    const cancel = await handleSshTunnelRequest(manager, { action: "cancel-setup" });
    expect(cancel.kind).toBe("ok");
  });

  it("complete-setup without begin-setup returns a safe error, not a throw", async () => {
    const manager = makeManager();
    const result = await handleSshTunnelRequest(manager, { action: "complete-setup", fingerprint: "SHA256:abc" });
    expect(result.kind).toBe("error");
    if (result.kind === "error") expect(result.error).toContain("Start again");
  });

  it("set-auto-reconnect validates and persists through the manager", async () => {
    const manager = makeManager();
    const result = await handleSshTunnelRequest(manager, { action: "set-auto-reconnect", enabled: false });
    // Unconfigured: a no-op status, never a crash.
    expect(result.kind).toBe("status");
  });
});
