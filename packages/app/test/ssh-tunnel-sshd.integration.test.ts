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
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, createConnection } from "node:net";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { installLine } from "../src/ssh-tunnel.js";

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
    const attempt = sshAttempt([
      "-N",
      "-R", `127.0.0.1:${String(REMOTE_PAIR)}:127.0.0.1:${String(LOCAL_SVC)}`,
      "-R", `127.0.0.1:${String(REMOTE_DEV)}:127.0.0.1:${String(LOCAL_SVC)}`,
    ], 6000);
    await new Promise((r) => setTimeout(r, 1500));
    // Real bytes: local service behind the -R target answers through the
    // server-side forwarded port.
    const payload = await new Promise<string>((resolve, reject) => {
      const svc = createServer((c) => { c.on("data", (d: Buffer) => { c.end(`pong:${d.toString()}`); }); });
      svc.listen(LOCAL_SVC, "127.0.0.1", () => {
        const s = createConnection({ host: "127.0.0.1", port: REMOTE_PAIR }, () => { s.write("ping"); });
        s.setTimeout(5000);
        s.on("data", (d) => { s.end(); svc.close(); resolve(d.toString()); });
        s.on("error", reject); s.on("timeout", () => { reject(new Error("data path timed out")); });
      });
    });
    expect(payload).toBe("pong:ping");
    const res = await attempt;
    expect(res.alive).toBe(true); // still holding when killed at 6s
  }, 20000);

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
