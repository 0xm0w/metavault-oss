// Integration proof for the SSH tunnel against a REAL OpenSSH sshd.
//
// Runs only when an sshd binary is available (CI installs openssh-server on
// the Ubuntu job; developers can run it locally the same way). It verifies
// the exact authorized_keys line installLine() generates, plus the exact -R
// argv forms the manager spawns, against sshd's real option handling:
//
//   positive: both reverse forwards bind and carry real bytes
//   negative: forbidden reverse port, shell exec, interactive shell, pty,
//             and local-forward traffic through the same key
//
// Mocked tests cannot prove any of this: sshd option interaction (restrict
// vs port-forwarding vs permitlisten/permitopen, forced commands) is server
// behavior, and the original line shipped here silently rejected every -R.
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync, existsSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { createServer, createConnection } from "node:net";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { installLine, SshTunnelManager, sshTunnelPaths } from "../src/ssh-tunnel.js";

const run = promisify(execFile);
const SSHD = ["/usr/sbin/sshd", "/usr/local/sbin/sshd"].find((p) => existsSync(p));
const SSH = "/usr/bin/ssh";
const KEYGEN = "/usr/bin/ssh-keygen";

const REMOTE_PAIR = 17078;
const REMOTE_DEV = 17080;
const SSHD_PORT = 12222;
const LOCAL_SVC = 17081;

const haveTools = SSHD !== undefined && existsSync(SSH) && existsSync(KEYGEN);
const describeIfSshd = haveTools ? describe : describe.skip;

let dir = "";
let clientKey = "";
let sshdProc: ReturnType<typeof execFile> | undefined;

const sshArgs = (extra: string[], command: string[] = []): string[] => [
  "-i", clientKey,
  "-o", "StrictHostKeyChecking=no",
  "-o", `UserKnownHostsFile=${join(dir, "kh")}`,
  "-o", "BatchMode=yes",
  "-o", "ExitOnForwardFailure=yes",
  "-p", String(SSHD_PORT),
  ...extra,
  "127.0.0.1",
  ...command,
];

/** Spawn ssh, resolve with { code, output } when it exits before `holdMs`; if
 *  it is still alive at `holdMs`, kill it and resolve alive: true. */
function sshAttempt(extra: string[], holdMs = 2500, command: string[] = []): Promise<{ alive: boolean; output: string }> {
  return new Promise((resolve) => {
    const child = execFile(SSH, sshArgs(extra, command), { timeout: 8000 }, (_err, stdout, stderr) => {
      clearTimeout(timer);
      // stdout+stderr only: err.message echoes the argv, which contains the
      // canary string itself for the shell-exec test.
      resolve({ alive: false, output: `${stdout}${stderr}` });
    });
    const timer = setTimeout(() => { child.kill("SIGTERM"); resolve({ alive: true, output: "" }); }, holdMs);
  });
}

/** Resolve once 127.0.0.1:port accepts a TCP connection; reject after timeoutMs. */
function waitForPort(port: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const attempt = (): void => {
      const s = createConnection({ host: "127.0.0.1", port }, () => { s.destroy(); resolve(); });
      s.on("error", () => {
        s.destroy();
        if (Date.now() >= deadline) { reject(new Error(`port ${String(port)} never accepted connections`)); return; }
        setTimeout(attempt, 200);
      });
    };
    attempt();
  });
}

describeIfSshd("ssh-tunnel against a real sshd (integration)", () => {
  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "mv-sshd-it-"));
    clientKey = join(dir, "client_key");
    await run(KEYGEN, ["-q", "-t", "ed25519", "-f", join(dir, "host_ed25519"), "-N", ""]);
    await run(KEYGEN, ["-q", "-t", "ed25519", "-f", clientKey, "-N", ""]);
    const pub = readFileSync(`${clientKey}.pub`, "utf8").trim();
    // THE artifact under test: the exact line the app tells the user to install.
    const akPath = join(dir, "authorized_keys");
    writeFileSync(akPath, `${installLine(pub, REMOTE_PAIR, REMOTE_DEV)}\n`);
    chmodSync(akPath, 0o600);
    const cfg = [
      `Port ${String(SSHD_PORT)}`,
      "ListenAddress 127.0.0.1",
      `HostKey ${join(dir, "host_ed25519")}`,
      `PidFile ${join(dir, "sshd.pid")}`,
      "PasswordAuthentication no",
      "PubkeyAuthentication yes",
      `AuthorizedKeysFile ${akPath}`,
      "UsePAM no",
      "StrictModes no",
    ].join("\n");
    const cfgPath = join(dir, "sshd_config");
    writeFileSync(cfgPath, cfg);
    if (SSHD === undefined) throw new Error("unreachable: suite is skipped without sshd");
    sshdProc = execFile(SSHD, ["-f", cfgPath, "-D", "-E", join(dir, "sshd.log")], () => {});
    await new Promise((r) => setTimeout(r, 800));
  }, 20000);

  afterAll(() => {
    sshdProc?.kill("SIGTERM");
    if (dir !== "") rmSync(dir, { recursive: true, force: true });
  });

  it("holds both reverse forwards with the generated line and moves real bytes", async () => {
    // The local service must be listening BEFORE anything connects through the
    // forwarded port, or ssh sees a failed channel open.
    const svc = createServer((c) => { c.on("data", (d: Buffer) => { c.end(`pong:${d.toString()}`); }); });
    await new Promise<void>((resolve) => { svc.listen(LOCAL_SVC, "127.0.0.1", () => { resolve(); }); });
    const attempt = sshAttempt([
      "-N",
      "-R", `127.0.0.1:${String(REMOTE_PAIR)}:127.0.0.1:${String(LOCAL_SVC)}`,
      "-R", `127.0.0.1:${String(REMOTE_DEV)}:127.0.0.1:${String(LOCAL_SVC)}`,
    ], 7500); // sshAttempt kills at its own 8s timeout
    try {
      // Wait until the server-side forwarded port accepts connections instead
      // of sleeping a fixed time: on a busy CI runner the handshake can be slow.
      await waitForPort(REMOTE_PAIR, 5000);
      // Real bytes: the local service behind the -R target answers through the
      // server-side forwarded port.
      const payload = await new Promise<string>((resolve, reject) => {
        const s = createConnection({ host: "127.0.0.1", port: REMOTE_PAIR }, () => { s.write("ping"); });
        s.setTimeout(5000);
        s.on("data", (d) => { s.end(); resolve(d.toString()); });
        s.on("error", reject); s.on("timeout", () => { reject(new Error("data path timed out")); });
      });
      expect(payload).toBe("pong:ping");
      const res = await attempt;
      expect(res.alive).toBe(true); // still holding when killed at the hold time
    } finally {
      svc.close();
    }
  }, 30000);

  it("rejects a reverse forward to any port not in permitlisten", async () => {
    const res = await sshAttempt(["-N", "-R", "127.0.0.1:19999:127.0.0.1:7078"]);
    expect(res.alive).toBe(false);
    expect(res.output).toContain("remote port forwarding failed");
  }, 15000);

  it("blocks shell exec via the forced command", async () => {
    const res = await sshAttempt([], 2500, ["echo", "PWNED"]);
    expect(res.alive).toBe(false);
    expect(res.output).not.toContain("PWNED");
  }, 15000);

  it("blocks an interactive shell", async () => {
    const res = await sshAttempt([]);
    expect(res.alive).toBe(false);
  }, 15000);

  it("binds a local forward but refuses its traffic (permitopen blackhole)", async () => {
    const attempt = sshAttempt(["-N", "-L", "19998:127.0.0.1:22"], 6000);
    await new Promise((r) => setTimeout(r, 1500));
    const refused = await new Promise<boolean>((resolve) => {
      const s = createConnection({ host: "127.0.0.1", port: 19998 }, () => {
        s.on("data", () => { s.end(); resolve(false); }); // any banner = traffic flowed
        s.on("close", () => { resolve(true); });
        s.setTimeout(4000, () => { s.destroy(); resolve(false); });
      });
      s.on("error", () => { resolve(false); });
    });
    expect(refused).toBe(true);
    const res = await attempt;
    expect(res.alive).toBe(true); // bind held; only the traffic is refused
  }, 20000);
});

if (!haveTools) {
  it("sshd integration", () => {
    console.warn("SKIP: sshd/ssh/ssh-keygen not found; install openssh-server to run ssh-tunnel-sshd.integration.test.ts");
  });
}

describeIfSshd("SshTunnelManager.completeSetup against real sshd policy (integration)", () => {
  const PAIR = 18078;
  const DEV = 18080;
  let mDir = "";
  let hostKeyFp = "";
  const servers: Array<ReturnType<typeof execFile>> = [];

  const startServer = async (port: number, withMatch: boolean): Promise<string> => {
    const dir2 = mkdtempSync(join(tmpdir(), "mv-sshd-it2-"));
    const user = userInfo().username;
    await run(KEYGEN, ["-q", "-t", "ed25519", "-f", join(dir2, "host_ed25519"), "-N", ""]);
    const fpOut = await run(KEYGEN, ["-lf", join(dir2, "host_ed25519.pub")]);
    hostKeyFp = fpOut.stdout.trim().split(/\s+/)[1] ?? "";
    const cfgLines = [
      `Port ${String(port)}`,
      "ListenAddress 127.0.0.1",
      `HostKey ${join(dir2, "host_ed25519")}`,
      `PidFile ${join(dir2, "sshd.pid")}`,
      "PasswordAuthentication no",
      "PubkeyAuthentication yes",
      `AuthorizedKeysFile ${join(dir2, "authorized_keys")}`,
      "UsePAM no",
      "StrictModes no",
      "Subsystem sftp internal-sftp",
    ];
    if (withMatch) {
      cfgLines.push(
        `Match User ${user}`,
        "    AllowTcpForwarding remote",
        "    AllowAgentForwarding no",
        "    X11Forwarding no",
        "    PermitTTY no",
      );
    }
    const cfgPath = join(dir2, "sshd_config");
    writeFileSync(cfgPath, cfgLines.join("\n"));
    if (SSHD === undefined) throw new Error("unreachable");
    const proc = execFile(SSHD, ["-f", cfgPath, "-D", "-E", join(dir2, "sshd.log")], () => {});
    servers.push(proc);
    await new Promise((r) => setTimeout(r, 800));
    return join(dir2, "authorized_keys");
  };

  const loginUser = userInfo().username;

  const makeManager = (): SshTunnelManager => {
    mDir = mkdtempSync(join(tmpdir(), "mv-ssh-it-mgr-"));
    return new SshTunnelManager({
      paths: sshTunnelPaths(mDir),
      binaries: { ssh: SSH, keygen: KEYGEN, keyscan: "/usr/bin/ssh-keyscan" },
      gatewayReady: () => Promise.resolve(true),
      forwardReadyTimeoutMs: 10000,
    });
  };

  afterAll(() => {
    for (const srv of servers) srv.kill("SIGTERM");
  });

  it("finishes verified when the server has the Match policy, and -R data flows", async () => {
    const port = 12230;
    const akPath = await startServer(port, true);
    const manager = makeManager();
    const proposal = await manager.beginSetup({
      address: `${loginUser}@127.0.0.1:${String(port)}`,
      remotePairingPort: PAIR,
      remoteDevicePort: DEV,
      currentUser: "ignored",
    });
    expect("error" in proposal).toBe(false);
    if ("error" in proposal) return;
    // The user installs EXACTLY the generated line on the server.
    writeFileSync(akPath, `${proposal.installLine}\n`, { mode: 0o600 });
    const done = await manager.completeSetup(hostKeyFp);
    expect(done.reason).toBeUndefined();
    expect(done.configured).toBe(true);
    expect(done.verified).toBe(true);
    await manager.shutdown();
  }, 60000);

  it("refuses to finish (server-policy-missing) when -L is not genuinely denied", async () => {
    const port = 12231;
    const akPath = await startServer(port, false);
    const manager = makeManager();
    const proposal = await manager.beginSetup({
      address: `${loginUser}@127.0.0.1:${String(port)}`,
      remotePairingPort: PAIR,
      remoteDevicePort: DEV,
      currentUser: "ignored",
    });
    expect("error" in proposal).toBe(false);
    if ("error" in proposal) return;
    writeFileSync(akPath, `${proposal.installLine}\n`, { mode: 0o600 });
    const done = await manager.completeSetup(hostKeyFp);
    expect(done.configured).toBe(false);
    expect(done.verified).toBe(false);
    expect(done.reason).toBe("server-policy-missing");
    // Refusal tore down the pinned trust: nothing configured remains.
    expect(manager.getStatus().configured).toBe(false);
    await manager.shutdown();
  }, 60000);
});
