import { EventEmitter } from "node:events";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import {
  SshTunnelManager,
  fingerprintsMatch,
  hostKeyFingerprint,
  installLine,
  isValidForwardPort,
  knownHostsLine,
  parseKeyscanOutput,
  parseSshAddress,
  resolveSshBinaries,
  sanitizeConfig,
  sshTunnelPaths,
  tunnelArgs,
  type SshTunnelConfig,
} from "../src/ssh-tunnel.js";

// github.com's published ssh-ed25519 host key and SHA256 fingerprint.
const GH_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
const GH_FP = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU";

const SAMPLE_CONFIG: SshTunnelConfig = {
  host: "relay.example.com",
  user: "mow",
  port: 22,
  remotePairingPort: 7078,
  remoteDevicePort: 7080,
  hostKeyType: "ssh-ed25519",
  hostKeyBase64: GH_KEY,
  hostKeyFingerprint: GH_FP,
  autoReconnect: true,
  desiredState: "off",
};

let dir: string | null = null;
const liveManagers: SshTunnelManager[] = [];
afterEach(async () => {
  for (const m of liveManagers.splice(0)) await m.shutdown();
  if (dir !== null) {
    rmSync(dir, { recursive: true, force: true });
    dir = null;
  }
});

async function waitForState(manager: SshTunnelManager, state: string, ms = 2000): Promise<void> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (manager.getStatus().state === state) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`timed out waiting for state ${state}, still ${manager.getStatus().state}`);
}

function tmpPaths() {
  dir = mkdtempSync(join(tmpdir(), "mv-ssh-test-"));
  return sshTunnelPaths(dir);
}

describe("parseSshAddress", () => {
  it("parses user@host with default port", () => {
    expect(parseSshAddress("mow@relay.example.com", "fallback")).toEqual({ host: "relay.example.com", user: "mow", port: 22 });
  });
  it("parses host-only with the current user and a custom port", () => {
    expect(parseSshAddress("relay.example.com:2222", "mow")).toEqual({ host: "relay.example.com", user: "mow", port: 2222 });
  });
  it("parses IPv4 and bracketed IPv6", () => {
    expect(parseSshAddress("mow@192.168.1.10", "x")).toEqual({ host: "192.168.1.10", user: "mow", port: 22 });
    expect(parseSshAddress("mow@[2001:db8::1]:2222", "x")).toEqual({ host: "[2001:db8::1]", user: "mow", port: 2222 });
  });
  it("rejects option injection, whitespace and shell metacharacters", () => {
    expect(parseSshAddress("-oProxyCommand=evil", "mow")).toBeNull();
    expect(parseSshAddress("mow@-host", "mow")).toBeNull();
    expect(parseSshAddress("mow@host;rm -rf /", "mow")).toBeNull();
    expect(parseSshAddress("mow@host other", "mow")).toBeNull();
    expect(parseSshAddress("mow@host:0", "mow")).toBeNull();
    expect(parseSshAddress("mow@host:70000", "mow")).toBeNull();
    expect(parseSshAddress("-baduser@host", "mow")).toBeNull();
    expect(parseSshAddress("", "mow")).toBeNull();
    expect(parseSshAddress(42, "mow")).toBeNull();
  });
});

describe("isValidForwardPort", () => {
  it("accepts unprivileged ports only", () => {
    expect(isValidForwardPort(7078)).toBe(true);
    expect(isValidForwardPort(1024)).toBe(true);
    expect(isValidForwardPort(1023)).toBe(false);
    expect(isValidForwardPort(65536)).toBe(false);
    expect(isValidForwardPort(7078.5)).toBe(false);
    expect(isValidForwardPort("7078")).toBe(false);
  });
});

describe("host keys", () => {
  it("computes the OpenSSH SHA256 fingerprint of a key blob", () => {
    expect(hostKeyFingerprint(GH_KEY)).toBe(GH_FP);
  });
  it("parses keyscan output and prefers ed25519 over rsa", () => {
    const out = [
      "# relay.example.com:22 SSH-2.0-OpenSSH_9.6",
      "relay.example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7",
      "relay.example.com ssh-ed25519 " + GH_KEY,
      "garbage line that should be dropped",
    ].join("\n");
    const key = parseKeyscanOutput(out);
    expect(key).not.toBeNull();
    expect(key?.type).toBe("ssh-ed25519");
    expect(key?.fingerprint).toBe(GH_FP);
  });
  it("returns null when no usable key line exists", () => {
    expect(parseKeyscanOutput("# only comments\n")).toBeNull();
    expect(parseKeyscanOutput("")).toBeNull();
  });
  it("matches fingerprints exactly after whitespace normalization", () => {
    expect(fingerprintsMatch(GH_FP, GH_FP)).toBe(true);
    expect(fingerprintsMatch(`  ${GH_FP}\n`, GH_FP)).toBe(true);
    expect(fingerprintsMatch(GH_FP.toLowerCase(), GH_FP)).toBe(false);
    expect(fingerprintsMatch("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", GH_FP)).toBe(false);
    expect(fingerprintsMatch("", GH_FP)).toBe(false);
    expect(fingerprintsMatch(undefined, GH_FP)).toBe(false);
  });
  it("brackets non-default ports in known_hosts lines", () => {
    expect(knownHostsLine("relay.example.com", 22, "ssh-ed25519", GH_KEY)).toBe(`relay.example.com ssh-ed25519 ${GH_KEY}\n`);
    expect(knownHostsLine("relay.example.com", 2222, "ssh-ed25519", GH_KEY)).toBe(`[relay.example.com]:2222 ssh-ed25519 ${GH_KEY}\n`);
  });
});

describe("tunnelArgs", () => {
  it("builds a pinned, secret-free argv with loopback-only remote forwards", () => {
    const paths = sshTunnelPaths("/data");
    const args = tunnelArgs(SAMPLE_CONFIG, paths);
    expect(args[0]).toBe("-N");
    expect(args).toContain("-T");
    expect(args).toContain("BatchMode=yes");
    expect(args).toContain("StrictHostKeyChecking=yes");
    expect(args).toContain(`UserKnownHostsFile=${paths.knownHostsPath}`);
    expect(args).toContain("ExitOnForwardFailure=yes");
    // ClearAllForwardings must NOT be set: it clears the command-line -R options
    // too (verified against real OpenSSH 8.9: the tunnel idled with zero forwards).
    expect(args).not.toContain("ClearAllForwardings=yes");
    expect(args).toContain("ForwardAgent=no");
    expect(args).toContain("ForwardX11=no");
    expect(args).toContain("PermitLocalCommand=no");
    expect(args).toContain("-F");
    expect(args[args.indexOf("-F") + 1]).toBe(paths.emptyConfigPath);
    expect(args).toContain(`127.0.0.1:7078:127.0.0.1:7078`);
    expect(args).toContain(`127.0.0.1:7080:127.0.0.1:7080`);
    expect(args[args.length - 1]).toBe("mow@relay.example.com");
    // No password, no key material, no shell.
    expect(args.join(" ")).not.toMatch(/password|sshpass/i);
    for (const a of args) expect(a.startsWith("-oProxyCommand")).toBe(false);
  });
});

describe("resolveSshBinaries", () => {
  it("prefers the Windows inbox OpenSSH path when it exists", () => {
    const bins = resolveSshBinaries("win32", { WINDIR: "C:\\Windows" }, () => true);
    expect(bins?.ssh).toBe(join("C:\\Windows", "System32", "OpenSSH", "ssh.exe"));
  });
  it("returns null on Windows when the OpenSSH client is not installed", () => {
    expect(resolveSshBinaries("win32", { WINDIR: "C:\\Windows" }, () => false)).toBeNull();
  });
  it("honours the test override directory", () => {
    const bins = resolveSshBinaries("linux", { METAVAULT_SSH_BIN_DIR: "/opt/ssh" }, () => true);
    expect(bins?.ssh).toBe(join("/opt/ssh", "ssh"));
  });
});

describe("sanitizeConfig", () => {
  it("round-trips a valid config", () => {
    expect(sanitizeConfig(JSON.parse(JSON.stringify(SAMPLE_CONFIG)))).toEqual(SAMPLE_CONFIG);
  });
  it("rejects a tampered fingerprint (recomputed from the blob)", () => {
    expect(sanitizeConfig({ ...SAMPLE_CONFIG, hostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" })).toBeNull();
  });
  it("rejects bad ports, unknown key types and option-injection hosts", () => {
    expect(sanitizeConfig({ ...SAMPLE_CONFIG, remotePairingPort: 80 })).toBeNull();
    expect(sanitizeConfig({ ...SAMPLE_CONFIG, remotePairingPort: 7080 })).toBeNull();
    expect(sanitizeConfig({ ...SAMPLE_CONFIG, hostKeyType: "ssh-dss" })).toBeNull();
    expect(sanitizeConfig({ ...SAMPLE_CONFIG, host: "-oEvil=yes" })).toBeNull();
    expect(sanitizeConfig("nope")).toBeNull();
    expect(sanitizeConfig(null)).toBeNull();
  });
  it("defaults autoReconnect on and clamps desiredState", () => {
    const rest: Record<string, unknown> = { ...SAMPLE_CONFIG };
    delete rest["autoReconnect"];
    delete rest["desiredState"];
    const clean = sanitizeConfig(rest);
    expect(clean?.autoReconnect).toBe(true);
    expect(clean?.desiredState).toBe("off");
    expect(sanitizeConfig({ ...SAMPLE_CONFIG, desiredState: "weird" })?.desiredState).toBe("off");
    expect(sanitizeConfig({ ...SAMPLE_CONFIG, desiredState: "connected" })?.desiredState).toBe("connected");
  });
});

describe("installLine", () => {
  it("restricts the key to exactly the two loopback forwards", () => {
    const line = installLine(`ssh-ed25519 ${GH_KEY} metavault-oss-remote`, 7078, 7080);
    expect(line.startsWith('restrict,port-forwarding,command="false",permitlisten="127.0.0.1:7078",permitlisten="127.0.0.1:7080",permitopen="127.0.0.1:1" ')).toBe(true);
    expect(line).toContain(GH_KEY);
  });
});

// --- Manager state machine --------------------------------------------------

class FakeChild extends EventEmitter {
  stderr = new PassThrough();
  killed = false;
  kill(): boolean {
    if (!this.killed) {
      this.killed = true;
      queueMicrotask(() => this.emit("exit", 0, null));
    }
    return true;
  }
}

interface FakeSpawnLog {
  readonly command: string;
  readonly args: string[];
  readonly child: FakeChild;
}

function successSoon(child: FakeChild): void {
  queueMicrotask(() => {
    child.stderr.write("debug1: remote forward success for: listen 127.0.0.1:7078, connect 127.0.0.1:7078\r\n");
    child.stderr.write("debug1: remote forward success for: listen 127.0.0.1:7080, connect 127.0.0.1:7080\r\n");
  });
}

function makeManager(overrides: {
  spawnBehavior?: (child: FakeChild) => void;
  gatewayReady?: () => Promise<boolean>;
  keyscanOutput?: string;
  rawProbeStdout?: Buffer;
  rawProbeStderr?: string;
  rawProbeCode?: number;
  policyProbe?: "enforced" | "open" | "inconclusive";
} = {}) {
  const paths = tmpPaths();
  const spawned: FakeSpawnLog[] = [];
  const manager = new SshTunnelManager({
    paths,
    binaries: { ssh: "/bin/ssh", keygen: "/bin/ssh-keygen", keyscan: "/bin/ssh-keyscan" },
    wait: () => Promise.resolve(),
    forwardReadyTimeoutMs: 50,
    gatewayReady: overrides.gatewayReady ?? (() => Promise.resolve(true)),
    execFn: (command) => {
      if (command.endsWith("ssh-keygen")) {
        writeFileSync(paths.identityPath, "PRIVATE-KEY-PLACEHOLDER", { mode: 0o600 });
        writeFileSync(`${paths.identityPath}.pub`, `ssh-ed25519 ${GH_KEY} metavault-oss-remote`);
        return Promise.resolve({ stdout: "", stderr: "" });
      }
      if (command.endsWith("ssh-keyscan")) {
        return Promise.resolve({
          stdout: `relay.example.com ssh-ed25519 ${GH_KEY}\n`,
          stderr: "",
        });
      }
      return Promise.resolve({ stdout: "", stderr: "" });
    },
    spawnFn: (command, args) => {
      const child = new FakeChild();
      spawned.push({ command, args, child });
      (overrides.spawnBehavior ?? successSoon)(child);
      return child;
    },
    // Default: every negative probe shows a locked-down server.
    rawProbeFn: () => Promise.resolve({
      code: overrides.rawProbeCode ?? 1,
      stdout: overrides.rawProbeStdout ?? Buffer.alloc(0),
      stderr: overrides.rawProbeStderr ?? "PTY allocation request failed",
    }),
    policyProbeFn: () => Promise.resolve(overrides.policyProbe ?? "enforced"),
  });
  liveManagers.push(manager);
  return { manager, spawned, paths };
}

async function completeSetupFlow(manager: SshTunnelManager): Promise<void> {
  const proposal = await manager.beginSetup({ address: "mow@relay.example.com", currentUser: "localuser" });
  expect("error" in proposal).toBe(false);
  const done = await manager.completeSetup(GH_FP);
  // The probe reuses the test's spawn behavior, which may intentionally
  // fail; setup is complete once the config is pinned, probe or not.
  expect(done.configured).toBe(true);
}

describe("SshTunnelManager setup", () => {
  it("starts not-configured and completes a full verified setup", async () => {
    const { manager, paths } = makeManager();
    expect(manager.getStatus().state).toBe("not-configured");
    const proposal = await manager.beginSetup({ address: "mow@relay.example.com", currentUser: "localuser" });
    if ("error" in proposal) throw new Error(proposal.error);
    expect(proposal.fingerprint).toBe(GH_FP);
    expect(proposal.installLine).toContain("restrict,port-forwarding");
    const done = await manager.completeSetup(GH_FP);
    expect(done).toMatchObject({ configured: true, verified: true });
    expect(manager.getStatus().state).toBe("off");
    // Config persisted with owner-only permissions and passes revalidation.
    const onDisk = JSON.parse(readFileSync(paths.configPath, "utf8")) as unknown;
    expect(sanitizeConfig(onDisk)).not.toBeNull();
    if (process.platform !== "win32") {
      expect(statSync(paths.configPath).mode & 0o777).toBe(0o600);
    }
    expect(readFileSync(paths.knownHostsPath, "utf8")).toBe(`relay.example.com ssh-ed25519 ${GH_KEY}\n`);
  });

  it("pins nothing when the confirmed fingerprint does not match", async () => {
    const { manager, paths } = makeManager();
    await manager.beginSetup({ address: "mow@relay.example.com", currentUser: "localuser" });
    const done = await manager.completeSetup("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    expect(done).toMatchObject({ configured: false, verified: false, reason: "host-key-changed" });
    expect(manager.getStatus().state).toBe("not-configured");
    expect(existsSync(paths.configPath)).toBe(false);
  });

  it("reports an unreachable server at begin-setup", async () => {
    const paths = tmpPaths();
    const manager = new SshTunnelManager({
      paths,
      binaries: { ssh: "/bin/ssh", keygen: "/bin/ssh-keygen", keyscan: "/bin/ssh-keyscan" },
      execFn: (command) => {
        if (command.endsWith("ssh-keygen")) {
          writeFileSync(paths.identityPath, "PRIV", { mode: 0o600 });
          writeFileSync(`${paths.identityPath}.pub`, `ssh-ed25519 ${GH_KEY} metavault-oss-remote`);
          return Promise.resolve({ stdout: "", stderr: "" });
        }
        return Promise.reject(new Error("timed out"));
      },
      spawnFn: () => { throw new Error("must not spawn"); },
    });
    liveManagers.push(manager);
    const proposal = await manager.beginSetup({ address: "mow@down.example.com", currentUser: "x" });
    expect("error" in proposal).toBe(true);
  });

  it("remove() rolls back config, keys and known_hosts", async () => {
    const { manager, paths } = makeManager();
    await completeSetupFlow(manager);
    expect(manager.getStatus().configured).toBe(true);
    await manager.remove();
    expect(manager.getStatus().state).toBe("not-configured");
    expect(existsSync(paths.dir)).toBe(false);
  });
});

describe("SshTunnelManager connect", () => {
  it("reports connected only after the server confirms both forwards", async () => {
    const { manager, spawned } = makeManager();
    await completeSetupFlow(manager);
    const before = spawned.length;
    const status = await manager.connect();
    expect(status.state).toBe("connected");
    expect(spawned.length).toBe(before + 1);
    expect(spawned[spawned.length - 1]?.args.join(" ")).toContain("ExitOnForwardFailure=yes");
    expect(manager.wantsConnection()).toBe(true);
    await manager.shutdown();
  });

  it("fails without retry on auth failure and keeps the config", async () => {
    const { manager } = makeManager({
      spawnBehavior: (child) => {
        queueMicrotask(() => {
          child.stderr.write("mow@relay.example.com: Permission denied (publickey).\r\n");
          child.emit("exit", 255, null);
        });
      },
    });
    await completeSetupFlow(manager);
    const status = await manager.connect();
    expect(status.state).toBe("error");
    expect(status.detail).toContain("refused the key");
  });

  it("retries bounded times on a plain drop, then reports error", async () => {
    let spawns = 0;
    const { manager } = makeManager({
      spawnBehavior: (child) => {
        spawns += 1;
        queueMicrotask(() => child.emit("exit", 255, null));
      },
    });
    await completeSetupFlow(manager);
    spawns = 0;
    const status = await manager.connect();
    expect(status.state).toBe("error");
    expect(spawns).toBe(5); // MAX_CONNECT_ATTEMPTS default
  });

  it("requires the local gateway before reporting connected", async () => {
    const { manager } = makeManager({ gatewayReady: () => Promise.resolve(false) });
    const proposal = await manager.beginSetup({ address: "mow@relay.example.com", currentUser: "localuser" });
    expect("error" in proposal).toBe(false);
    const done = await manager.completeSetup(GH_FP);
    expect(done).toMatchObject({ configured: true, verified: false, reason: "gateway-down" });
  });

  it("a changed host key errors and flips desiredState off (no silent reconnect)", async () => {
    const { manager, paths } = makeManager({
      spawnBehavior: (child) => {
        queueMicrotask(() => {
          child.stderr.write("@@@@@@@@@@@@@@@@@@@@@@@@\r\n@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @\r\nHost key verification failed.\r\n");
          child.emit("exit", 255, null);
        });
      },
    });
    // completeSetup's probe hits the same behaviour, so setup verifies false
    // but still pins the (matching) config; connect then fails terminally.
    const proposal = await manager.beginSetup({ address: "mow@relay.example.com", currentUser: "localuser" });
    expect("error" in proposal).toBe(false);
    await manager.completeSetup(GH_FP);
    const status = await manager.connect();
    expect(status.state).toBe("error");
    expect(status.detail).toContain("host key no longer matches");
    const onDisk = sanitizeConfig(JSON.parse(readFileSync(paths.configPath, "utf8")));
    expect(onDisk?.desiredState).toBe("off");
  });

  it("watchdog reconnects an established tunnel after an unexpected drop", async () => {
    const { manager, spawned } = makeManager();
    await completeSetupFlow(manager);
    await manager.connect();
    expect(manager.getStatus().state).toBe("connected");
    const live = spawned[spawned.length - 1]?.child;
    expect(live).toBeDefined();
    // Unexpected drop (not our kill): watchdog must reconnect.
    live?.emit("exit", 255, null);
    await waitForState(manager, "connected");
    expect(manager.getStatus().state).toBe("connected");
    expect(spawned.length).toBeGreaterThan(2);
    await manager.shutdown();
  });

  it("disconnect kills only the spawned child and persists desiredState off", async () => {
    const { manager, spawned, paths } = makeManager();
    await completeSetupFlow(manager);
    await manager.connect();
    const live = spawned[spawned.length - 1]?.child;
    const status = await manager.disconnect();
    expect(status.state).toBe("off");
    expect(live?.killed).toBe(true);
    const onDisk = sanitizeConfig(JSON.parse(readFileSync(paths.configPath, "utf8")));
    expect(onDisk?.desiredState).toBe("off");
  });
});

describe("SshTunnelManager negative server probes", () => {
  it("refuses setup and saves nothing when shell exec escapes (canary returned)", async () => {
    const { manager, paths } = makeManager({ rawProbeStdout: Buffer.from("MV-PROBE-CANARY-7f3a9c21\n") });
    const proposal = await manager.beginSetup({ address: "mow@relay.example.com", currentUser: "localuser" });
    expect("error" in proposal).toBe(false);
    const done = await manager.completeSetup(GH_FP);
    expect(done.configured).toBe(false);
    expect(done.reason).toBe("server-unrestricted");
    expect(existsSync(paths.configPath)).toBe(false);
    expect(existsSync(paths.knownHostsPath)).toBe(false);
    expect(manager.getStatus().state).toBe("not-configured");
  });

  it("refuses setup when the sftp subsystem answers SSH_FXP_INIT", async () => {
    const version = Buffer.alloc(9);
    version.writeUInt32BE(9, 0);
    version.writeUInt8(2, 4); // SSH_FXP_VERSION
    version.writeUInt32BE(3, 5);
    const { manager, paths } = makeManager({ rawProbeStdout: version });
    const proposal = await manager.beginSetup({ address: "mow@relay.example.com", currentUser: "localuser" });
    expect("error" in proposal).toBe(false);
    const done = await manager.completeSetup(GH_FP);
    expect(done.configured).toBe(false);
    expect(done.reason).toBe("server-unrestricted");
    expect(existsSync(paths.configPath)).toBe(false);
  });

  it("refuses setup when local forwarding is only blackholed, not denied", async () => {
    const { manager, paths } = makeManager({ policyProbe: "open" });
    const proposal = await manager.beginSetup({ address: "mow@relay.example.com", currentUser: "localuser" });
    expect("error" in proposal).toBe(false);
    const done = await manager.completeSetup(GH_FP);
    expect(done.configured).toBe(false);
    expect(done.reason).toBe("server-policy-missing");
    expect(existsSync(paths.configPath)).toBe(false);
    expect(manager.getStatus().state).toBe("not-configured");
  });

  it("an inconclusive policy probe is retryable, not a refusal", async () => {
    const { manager, paths } = makeManager({ policyProbe: "inconclusive" });
    const proposal = await manager.beginSetup({ address: "mow@relay.example.com", currentUser: "localuser" });
    expect("error" in proposal).toBe(false);
    const done = await manager.completeSetup(GH_FP);
    expect(done.configured).toBe(true);
    expect(done.verified).toBe(false);
    expect(done.reason).toBe("timeout");
    expect(existsSync(paths.configPath)).toBe(true);
  });

  it("a pty that allocates counts as unrestricted", async () => {
    const { manager } = makeManager({ rawProbeCode: 0, rawProbeStderr: "" });
    const proposal = await manager.beginSetup({ address: "mow@relay.example.com", currentUser: "localuser" });
    expect("error" in proposal).toBe(false);
    const done = await manager.completeSetup(GH_FP);
    expect(done.configured).toBe(false);
    expect(done.reason).toBe("server-unrestricted");
  });
});
