import { spawn as nodeSpawn, execFile as nodeExecFile, spawnSync } from "node:child_process";
import { userInfo } from "node:os";
import { createHash } from "node:crypto";
import {
  createWriteStream, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync,
  type WriteStream,
} from "node:fs";
import { join } from "node:path";

// App-managed outbound reverse-SSH transport for Remote Connections.
//
// The vault PC dials OUT to an SSH server the user controls and reverse-
// forwards the two loopback gateway listeners there, bound to the relay's
// own loopback only. No SSH server runs on this PC; no gateway port is ever
// exposed beyond the relay's 127.0.0.1. The tunnel carries transport only:
// it grants no capabilities (pairing, mTLS, policy and PIN approval are
// unchanged and enforced by vaultd and the gateway).
//
// Security rules baked in here:
// - key-only auth (BatchMode, IdentitiesOnly, our generated ed25519 key)
// - host key pinned at setup: the user confirms the SHA256 fingerprint they
//   verified out-of-band; StrictHostKeyChecking=yes with our own known_hosts
//   file. No blind trust-on-first-use.
// - no secrets on the command line or in logs: argv carries host, user,
//   ports and file paths only; ssh writes no key material to stderr.
// - ClearAllForwardings + agent/X11/local-command off, so the session
//   carries exactly the two reverse forwards and nothing else.
// - the app only ever stops the child process it spawned itself.
//
// This module imports no Electron APIs so it is unit-testable headlessly.

export const SSH_TUNNEL_DIR_NAME = "ssh-tunnel";
export const SSH_TUNNEL_CONFIG_FILE = "config.json";
export const SSH_TUNNEL_LOG_FILE = "ssh-tunnel.log";
export const SSH_IDENTITY_FILE = "id_ed25519";
export const SSH_KNOWN_HOSTS_FILE = "known_hosts";
export const SSH_EMPTY_CONFIG_FILE = "ssh_config.empty";

export const DEFAULT_SSH_PORT = 22;
export const DEFAULT_REMOTE_PAIRING_PORT = 7078;
export const DEFAULT_REMOTE_DEVICE_PORT = 7080;
export const MAX_CONNECT_ATTEMPTS = 5;
export const RETRY_DELAYS_MS: readonly number[] = [2000, 4000, 8000, 16000, 32000];
const STABLE_RESET_MS = 60_000;
const FORWARD_READY_TIMEOUT_MS = 15_000;
const KEYSCAN_TIMEOUT_MS = 10_000;

export type SshTunnelState =
  | "not-configured"
  | "off"
  | "connecting"
  | "connected"
  | "reconnecting"
  | "error";

export interface SshTunnelStatus {
  readonly state: SshTunnelState;
  readonly configured: boolean;
  readonly host?: string;
  readonly user?: string;
  readonly port?: number;
  readonly remotePairingPort?: number;
  readonly remoteDevicePort?: number;
  readonly fingerprint?: string;
  readonly autoReconnect?: boolean;
  readonly detail?: string;
  readonly attempts?: number;
  readonly connectedSince?: string;
}

export interface SshTunnelConfig {
  readonly host: string;
  readonly user: string;
  readonly port: number;
  readonly remotePairingPort: number;
  readonly remoteDevicePort: number;
  readonly hostKeyType: string;
  readonly hostKeyBase64: string;
  readonly hostKeyFingerprint: string;
  readonly autoReconnect: boolean;
  readonly desiredState: "off" | "connected";
}

export interface SshTunnelSetupProposal {
  readonly host: string;
  readonly user: string;
  readonly port: number;
  readonly remotePairingPort: number;
  readonly remoteDevicePort: number;
  readonly keyType: string;
  readonly fingerprint: string;
  readonly publicKey: string;
  readonly installLine: string;
}

// --- Address parsing ------------------------------------------------------

const USER_PATTERN = /^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$/;
const HOSTNAME_PATTERN =
  /^(?=.{1,253}$)[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$/;
const IPV4_PATTERN = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const BRACKETED_IPV6_PATTERN = /^\[[0-9A-Fa-f:.%]+\]$/;

export interface ParsedAddress {
  readonly host: string;
  readonly user: string;
  readonly port: number;
}

function validHost(host: string): boolean {
  if (host === "" || host.startsWith("-")) return false;
  if (HOSTNAME_PATTERN.test(host)) return true;
  const v4 = IPV4_PATTERN.exec(host);
  if (v4 !== null) return v4.slice(1).every((octet) => Number(octet) <= 255);
  return BRACKETED_IPV6_PATTERN.test(host) && host.length <= 47;
}

// Parses "[user@]host[:port]" into a validated target. Anything that could
// smuggle an ssh option (leading dashes, whitespace, shell metacharacters)
// is rejected; we never run through a shell, but argv hygiene stays strict.
export function parseSshAddress(input: unknown, currentUser: string): ParsedAddress | null {
  if (typeof input !== "string") return null;
  const trimmed = input.trim();
  if (trimmed === "" || trimmed.length > 320 || /\s/.test(trimmed)) return null;
  let rest = trimmed;
  let user = currentUser;
  const at = rest.lastIndexOf("@");
  if (at !== -1) {
    user = rest.slice(0, at);
    rest = rest.slice(at + 1);
  }
  let port = DEFAULT_SSH_PORT;
  let host = rest;
  if (rest.startsWith("[")) {
    const close = rest.indexOf("]");
    if (close === -1) return null;
    host = rest.slice(0, close + 1);
    const tail = rest.slice(close + 1);
    if (tail !== "") {
      if (!/^:\d+$/.test(tail)) return null;
      port = Number(tail.slice(1));
    }
  } else if (rest.includes(":")) {
    const colon = rest.lastIndexOf(":");
    if (!/^\d+$/.test(rest.slice(colon + 1))) return null;
    host = rest.slice(0, colon);
    port = Number(rest.slice(colon + 1));
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  if (!validHost(host)) return null;
  if (!USER_PATTERN.test(user) || user.startsWith("-")) return null;
  return { host, user, port };
}

export function isValidForwardPort(value: unknown): value is number {
  // Relay-side listeners are unprivileged by policy.
  return typeof value === "number" && Number.isInteger(value) && value >= 1024 && value <= 65535;
}

// --- Host key handling -----------------------------------------------------

export interface ScannedHostKey {
  readonly type: string;
  readonly base64: string;
  readonly fingerprint: string;
}

const KEY_TYPE_RANK: Readonly<Record<string, number>> = {
  "ssh-ed25519": 0,
  "ecdsa-sha2-nistp256": 1,
  "ssh-rsa": 2,
};

const KEY_BLOB_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

// Parses ssh-keyscan output and returns the strongest key found. Comment
// and banner lines are ignored; malformed lines are dropped, never trusted.
export function parseKeyscanOutput(text: string): ScannedHostKey | null {
  const found: { type: string; base64: string }[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmedLine = line.trim();
    if (trimmedLine === "" || trimmedLine.startsWith("#")) continue;
    const parts = trimmedLine.split(/\s+/);
    if (parts.length !== 3) continue;
    const type = parts[1] as string;
    const base64 = parts[2] as string;
    if (!(type in KEY_TYPE_RANK)) continue;
    if (!KEY_BLOB_PATTERN.test(base64) || base64.length > 2048) continue;
    found.push({ type, base64 });
  }
  if (found.length === 0) return null;
  found.sort((a, b) => (KEY_TYPE_RANK[a.type] ?? 99) - (KEY_TYPE_RANK[b.type] ?? 99));
  const best = found[0] as { type: string; base64: string };
  return { ...best, fingerprint: hostKeyFingerprint(best.base64) };
}

// OpenSSH-style SHA256 fingerprint of a base64 key blob (padding stripped).
export function hostKeyFingerprint(base64: string): string {
  const digest = createHash("sha256").update(Buffer.from(base64, "base64")).digest("base64");
  return `SHA256:${digest.replace(/=+$/, "")}`;
}

// Exact match after whitespace normalization. Base64 is case-sensitive, so
// case is preserved; a fingerprint that differs at all does not match.
export function fingerprintsMatch(expected: unknown, actual: string): boolean {
  if (typeof expected !== "string") return false;
  const normalized = expected.replace(/\s+/g, "");
  return normalized !== "" && normalized === actual;
}

export function knownHostsLine(host: string, port: number, type: string, base64: string): string {
  const hostField = port === DEFAULT_SSH_PORT ? host : `[${host}]:${String(port)}`;
  return `${hostField} ${type} ${base64}\n`;
}

// --- Paths, argv, binaries --------------------------------------------------

export interface SshTunnelPaths {
  readonly dir: string;
  readonly configPath: string;
  readonly identityPath: string;
  readonly knownHostsPath: string;
  readonly emptyConfigPath: string;
  readonly logPath: string;
}

export function sshTunnelPaths(dataDir: string): SshTunnelPaths {
  const dir = join(dataDir, SSH_TUNNEL_DIR_NAME);
  return {
    dir,
    configPath: join(dir, SSH_TUNNEL_CONFIG_FILE),
    identityPath: join(dir, SSH_IDENTITY_FILE),
    knownHostsPath: join(dir, SSH_KNOWN_HOSTS_FILE),
    emptyConfigPath: join(dir, SSH_EMPTY_CONFIG_FILE),
    logPath: join(dir, SSH_TUNNEL_LOG_FILE),
  };
}

// The exact tunnel invocation. Every forwarding-relevant option is pinned
// on the command line (which beats user and system ssh config), and -F
// points at an empty file so a stray per-user config cannot add forwards,
// proxies or local commands. No secret ever appears in argv.
export function tunnelArgs(config: SshTunnelConfig, paths: SshTunnelPaths): string[] {
  return [
    "-N",
    "-T",
    "-v",
    "-F", paths.emptyConfigPath,
    "-p", String(config.port),
    "-i", paths.identityPath,
    "-o", "BatchMode=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", `UserKnownHostsFile=${paths.knownHostsPath}`,
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=3",
    "-o", "ClearAllForwardings=yes",
    "-o", "ForwardAgent=no",
    "-o", "ForwardX11=no",
    "-o", "PermitLocalCommand=no",
    "-o", "UpdateHostKeys=no",
    "-o", "ControlMaster=no",
    "-o", "ControlPath=none",
    "-R", `127.0.0.1:${String(config.remotePairingPort)}:127.0.0.1:7078`,
    "-R", `127.0.0.1:${String(config.remoteDevicePort)}:127.0.0.1:7080`,
    `${config.user}@${config.host}`,
  ];
}

// Resolves the OpenSSH client binaries. Prefers the Windows inbox OpenSSH
// location over PATH so a shadowed PATH cannot substitute another binary.
// METAVAULT_SSH_BIN_DIR overrides for tests only.
export interface SshBinaries {
  readonly ssh: string;
  readonly keygen: string;
  readonly keyscan: string;
}

export function resolveSshBinaries(
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
  exists: (path: string) => boolean = existsSync,
): SshBinaries | null {
  const overrideDir = env["METAVAULT_SSH_BIN_DIR"];
  if (overrideDir !== undefined && overrideDir !== "") {
    const ext = platform === "win32" ? ".exe" : "";
    const ssh = join(overrideDir, `ssh${ext}`);
    if (!exists(ssh)) return null;
    return { ssh, keygen: join(overrideDir, `ssh-keygen${ext}`), keyscan: join(overrideDir, `ssh-keyscan${ext}`) };
  }
  if (platform === "win32") {
    const windir = env["WINDIR"] ?? env["SystemRoot"] ?? "C:\\Windows";
    const dir = join(windir, "System32", "OpenSSH");
    const ssh = join(dir, "ssh.exe");
    if (!exists(ssh)) return null;
    return { ssh, keygen: join(dir, "ssh-keygen.exe"), keyscan: join(dir, "ssh-keyscan.exe") };
  }
  return { ssh: "ssh", keygen: "ssh-keygen", keyscan: "ssh-keyscan" };
}

// POSIX mode bits are set at write time; on Windows they are mostly a no-op,
// so the same owner-only guarantee needs real ACLs: strip inheritance and
// grant full control to the current user alone. Applied to the tunnel
// directory and every file in it. Throws when icacls fails - for the
// keypair and pinned files a weak ACL is a security failure, not a warning.
const icaclsRun = (command: string, args: string[]): { status: number | null; stderr: string } => {
  const res = spawnSync(command, args, { encoding: "utf8", windowsHide: true });
  return { status: res.status, stderr: res.stderr };
};

export function hardenPathPermissions(
  target: string,
  platform: NodeJS.Platform = process.platform,
  run: (command: string, args: string[]) => { status: number | null; stderr: string } = icaclsRun,
): void {
  if (platform !== "win32") return;
  const user = userInfo().username;
  const res = run("icacls", [target, "/inheritance:r", "/grant:r", `${user}:(F)`]);
  if (res.status !== 0) {
    throw new Error(`icacls failed for ${target}: ${res.stderr}`);
  }
}

// The authorized_keys line the user installs on the relay. Verified against
// OpenSSH 8.9 sshd (see test/ssh-tunnel-sshd.integration.test.ts):
// - "restrict" disables forwarding/pty/agent/X11/rc, and "port-forwarding" is
//   REQUIRED to opt tcp forwarding back in (permitlisten alone only narrows,
//   it does not re-enable - restrict,permitlisten=... rejects every -R).
// - "restrict" does NOT block shell/exec; command="false" is the forced
//   command that makes shell and exec attempts exit 1 with no output.
// - port-forwarding also enables -L; permitopen="127.0.0.1:1" blackholes
//   every useful local-forward target (connections are refused per-open).
// - permitlisten pins the only two reverse-forward listens; the client binds
//   127.0.0.1 explicitly so the match is literal and GatewayPorts-safe.
// Residual, by design and documented: sshd subsystem (sftp) ignores forced
// commands, so server-side account policy (dedicated locked-down user) is
// the control there - the key cannot fix it.
export function installLine(publicKeyLine: string, remotePairingPort: number, remoteDevicePort: number): string {
  const key = publicKeyLine.trim();
  return `restrict,port-forwarding,command="false",permitlisten="127.0.0.1:${String(remotePairingPort)}",permitlisten="127.0.0.1:${String(remoteDevicePort)}",permitopen="127.0.0.1:1" ${key}`;
}

// --- Config persistence -----------------------------------------------------

// Reads a stored config back into a valid value; anything off (tampered,
// corrupt, surprising types) drops the whole config rather than repairing
// it, so a damaged file can never produce a connection the user did not
// set up. Callers treat null as "not configured".
export function sanitizeConfig(raw: unknown): SshTunnelConfig | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const host = r["host"];
  const user = r["user"];
  const port = r["port"];
  const remotePairingPort = r["remotePairingPort"];
  const remoteDevicePort = r["remoteDevicePort"];
  const hostKeyType = r["hostKeyType"];
  const hostKeyBase64 = r["hostKeyBase64"];
  const storedFingerprint = r["hostKeyFingerprint"];
  if (typeof host !== "string" || typeof user !== "string") return null;
  if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  const withPort = port === DEFAULT_SSH_PORT ? `${user}@${host}` : `${user}@${host}:${String(port)}`;
  const parsed = parseSshAddress(withPort, user);
  if (parsed === null || parsed.host !== host || parsed.user !== user || parsed.port !== port) return null;
  if (!isValidForwardPort(remotePairingPort) || !isValidForwardPort(remoteDevicePort)) return null;
  if (remotePairingPort === remoteDevicePort) return null;
  if (typeof hostKeyType !== "string" || !(hostKeyType in KEY_TYPE_RANK)) return null;
  if (typeof hostKeyBase64 !== "string" || !KEY_BLOB_PATTERN.test(hostKeyBase64)) return null;
  if (typeof storedFingerprint !== "string" || storedFingerprint !== hostKeyFingerprint(hostKeyBase64)) return null;
  const autoReconnect = r["autoReconnect"];
  const desiredState = r["desiredState"];
  return {
    host,
    user,
    port,
    remotePairingPort,
    remoteDevicePort,
    hostKeyType,
    hostKeyBase64,
    hostKeyFingerprint: storedFingerprint,
    autoReconnect: autoReconnect !== false,
    desiredState: desiredState === "connected" ? "connected" : "off",
  };
}

// --- Manager -----------------------------------------------------------------

export interface SpawnedProcess {
  readonly pid?: number;
  readonly stderr?: NodeJS.ReadableStream | null;
  once(event: "exit", listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown;
  kill(signal?: string): boolean;
}

export type SpawnFn = (command: string, args: string[], options: {
  stdio: ["ignore", "ignore", "pipe"];
  readonly windowsHide: boolean;
  readonly env: NodeJS.ProcessEnv;
}) => SpawnedProcess;

export type ExecFn = (command: string, args: string[], timeoutMs: number) => Promise<{ stdout: string; stderr: string }>;

export interface SshTunnelManagerDeps {
  readonly paths: SshTunnelPaths;
  readonly binaries: SshBinaries;
  readonly spawnFn?: SpawnFn;
  readonly execFn?: ExecFn;
  // Windows ACL / POSIX no-op hardening; injectable for tests.
  readonly hardenFn?: (path: string) => void;
  readonly wait?: (ms: number) => Promise<void>;
  readonly retryDelaysMs?: readonly number[];
  readonly maxAttempts?: number;
  readonly forwardReadyTimeoutMs?: number;
  readonly now?: () => Date;
  // Proves the local gateway listeners are up before "connected" is
  // reported; the app wires its real gateway check in here.
  readonly gatewayReady?: () => Promise<boolean>;
  readonly onStatus?: (status: SshTunnelStatus) => void;
}

const defaultSpawn: SpawnFn = (command, args, options) =>
  nodeSpawn(command, args, options as Parameters<typeof nodeSpawn>[2]) as unknown as SpawnedProcess;

const defaultExec: ExecFn = (command, args, timeoutMs) =>
  new Promise((resolve, reject) => {
    nodeExecFile(
      command,
      args,
      { timeout: timeoutMs, maxBuffer: 1024 * 1024, encoding: "utf8" },
      (error: Error | null, stdout: string, stderr: string) => {
        if (error !== null && stdout === "" && stderr === "") {
          reject(error);
          return;
        }
        resolve({ stdout, stderr });
      },
    );
  });

interface PendingSetup {
  readonly address: ParsedAddress;
  readonly remotePairingPort: number;
  readonly remoteDevicePort: number;
  readonly key: ScannedHostKey;
}

export type SetupFailureReason =
  | "auth-failed"
  | "forward-refused"
  | "host-key-changed"
  | "gateway-down"
  | "timeout";

export interface SetupVerification {
  readonly verified: boolean;
  readonly reason?: SetupFailureReason;
}

interface AttemptResult {
  readonly ok: boolean;
  readonly retryable: boolean;
  readonly reason?: SetupFailureReason;
  readonly detail?: string;
}

export class SshTunnelManager {
  private readonly deps: SshTunnelManagerDeps & {
    spawnFn: SpawnFn;
    execFn: ExecFn;
    hardenFn: (path: string) => void;
    wait: (ms: number) => Promise<void>;
    retryDelaysMs: readonly number[];
    maxAttempts: number;
    forwardReadyTimeoutMs: number;
    now: () => Date;
  };
  private config: SshTunnelConfig | null = null;
  private pendingSetup: PendingSetup | null = null;
  private child: SpawnedProcess | null = null;
  private state: SshTunnelState = "not-configured";
  private detail: string | undefined;
  private attempts = 0;
  private connectedAt: Date | null = null;
  private stableTimer: ReturnType<typeof setTimeout> | null = null;
  private logStream: WriteStream | null = null;
  private intentionalStop = false;
  private connectInFlight: Promise<SshTunnelStatus> | null = null;

  constructor(deps: SshTunnelManagerDeps) {
    this.deps = {
      ...deps,
      spawnFn: deps.spawnFn ?? defaultSpawn,
      execFn: deps.execFn ?? defaultExec,
      hardenFn: deps.hardenFn ?? hardenPathPermissions,
      wait: deps.wait ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))),
      retryDelaysMs: deps.retryDelaysMs ?? RETRY_DELAYS_MS,
      maxAttempts: deps.maxAttempts ?? MAX_CONNECT_ATTEMPTS,
      forwardReadyTimeoutMs: deps.forwardReadyTimeoutMs ?? FORWARD_READY_TIMEOUT_MS,
      now: deps.now ?? (() => new Date()),
    };
    this.config = this.loadConfig();
    if (this.config !== null) this.state = "off";
  }

  private loadConfig(): SshTunnelConfig | null {
    try {
      return sanitizeConfig(JSON.parse(readFileSync(this.deps.paths.configPath, "utf8")));
    } catch {
      return null;
    }
  }

  private persistConfig(): void {
    if (this.config === null) return;
    mkdirSync(this.deps.paths.dir, { recursive: true, mode: 0o700 });
    writeFileSync(this.deps.paths.configPath, `${JSON.stringify(this.config, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    this.deps.hardenFn(this.deps.paths.dir);
    this.deps.hardenFn(this.deps.paths.configPath);
  }

  getStatus(): SshTunnelStatus {
    if (this.config === null) return { state: this.state, configured: false };
    return {
      state: this.state,
      configured: true,
      host: this.config.host,
      user: this.config.user,
      port: this.config.port,
      remotePairingPort: this.config.remotePairingPort,
      remoteDevicePort: this.config.remoteDevicePort,
      fingerprint: this.config.hostKeyFingerprint,
      autoReconnect: this.config.autoReconnect,
      ...(this.detail !== undefined ? { detail: this.detail } : {}),
      ...(this.state === "connecting" || this.state === "reconnecting" ? { attempts: this.attempts } : {}),
      ...(this.state === "connected" && this.connectedAt !== null
        ? { connectedSince: this.connectedAt.toISOString() }
        : {}),
    };
  }

  private setState(state: SshTunnelState, detail?: string): void {
    this.state = state;
    this.detail = detail;
    this.deps.onStatus?.(this.getStatus());
  }

  // Step 1 of setup: validate the address, make sure a keypair exists, and
  // scan the server's host key. Nothing is trusted or persisted yet; the
  // scanned key only becomes pinned after the user confirms the fingerprint
  // they verified out-of-band with their server provider.
  async beginSetup(input: {
    readonly address: string;
    readonly remotePairingPort?: number;
    readonly remoteDevicePort?: number;
    readonly currentUser: string;
  }): Promise<SshTunnelSetupProposal | { error: string }> {
    const address = parseSshAddress(input.address, input.currentUser);
    if (address === null) {
      return { error: "Enter the server as user@host or user@host:port. Letters, digits, dots and dashes only." };
    }
    const remotePairingPort = input.remotePairingPort ?? DEFAULT_REMOTE_PAIRING_PORT;
    const remoteDevicePort = input.remoteDevicePort ?? DEFAULT_REMOTE_DEVICE_PORT;
    if (!isValidForwardPort(remotePairingPort) || !isValidForwardPort(remoteDevicePort)) {
      return { error: "Relay ports must be whole numbers between 1024 and 65535." };
    }
    if (remotePairingPort === remoteDevicePort) {
      return { error: "The pairing and device ports on the relay must differ." };
    }
    try {
      await this.ensureKeypair();
    } catch {
      return { error: "Could not create the SSH keypair (ssh-keygen failed)." };
    }
    let scanned: ScannedHostKey | null = null;
    try {
      const result = await this.deps.execFn(
        this.deps.binaries.keyscan,
        ["-T", String(Math.ceil(KEYSCAN_TIMEOUT_MS / 1000)), "-p", String(address.port), "-t", "ed25519,ecdsa,rsa", address.host],
        KEYSCAN_TIMEOUT_MS + 2000,
      );
      scanned = parseKeyscanOutput(`${result.stdout}\n${result.stderr}`);
    } catch {
      scanned = null;
    }
    if (scanned === null) {
      return { error: "Could not reach an SSH server at that address. Check the host and port." };
    }
    this.pendingSetup = { address, remotePairingPort, remoteDevicePort, key: scanned };
    let publicKey = "";
    try {
      publicKey = readFileSync(`${this.deps.paths.identityPath}.pub`, "utf8").trim();
    } catch {
      return { error: "Could not read the generated public key." };
    }
    return {
      host: address.host,
      user: address.user,
      port: address.port,
      remotePairingPort,
      remoteDevicePort,
      keyType: scanned.type,
      fingerprint: scanned.fingerprint,
      publicKey,
      installLine: installLine(publicKey, remotePairingPort, remoteDevicePort),
    };
  }

  cancelSetup(): void {
    this.pendingSetup = null;
  }

  // Final setup step: the user pastes the fingerprint they verified with
  // their server provider; only on an exact match is the host key pinned,
  // the config written and an install-proving probe connection attempted.
  // The probe's tunnel is always torn down before this returns.
  async completeSetup(expectedFingerprint: string): Promise<SetupVerification & { configured: boolean }> {
    const pending = this.pendingSetup;
    if (pending === null) {
      return { configured: false, verified: false, reason: "timeout" };
    }
    if (!fingerprintsMatch(expectedFingerprint, pending.key.fingerprint)) {
      return { configured: false, verified: false, reason: "host-key-changed" };
    }
    const config: SshTunnelConfig = {
      host: pending.address.host,
      user: pending.address.user,
      port: pending.address.port,
      remotePairingPort: pending.remotePairingPort,
      remoteDevicePort: pending.remoteDevicePort,
      hostKeyType: pending.key.type,
      hostKeyBase64: pending.key.base64,
      hostKeyFingerprint: pending.key.fingerprint,
      autoReconnect: true,
      desiredState: "off",
    };
    mkdirSync(this.deps.paths.dir, { recursive: true, mode: 0o700 });
    this.deps.hardenFn(this.deps.paths.dir);
    writeFileSync(this.deps.paths.emptyConfigPath, "# MetaVault OSS pins every ssh option on the command line.\n", {
      encoding: "utf8",
      mode: 0o600,
    });
    writeFileSync(
      this.deps.paths.knownHostsPath,
      knownHostsLine(config.host, config.port, config.hostKeyType, config.hostKeyBase64),
      { encoding: "utf8", mode: 0o600 },
    );
    this.deps.hardenFn(this.deps.paths.knownHostsPath);
    this.deps.hardenFn(this.deps.paths.emptyConfigPath);
    this.config = config;
    this.persistConfig();
    this.pendingSetup = null;
    this.setState("off");
    const probe = await this.probeOnce();
    return { configured: true, ...probe };
  }

  // Full rollback: removes the pinned host key, config and keypair. The
  // user removes the public key line on the server (the UI says so).
  async remove(): Promise<void> {
    await this.disconnect();
    this.pendingSetup = null;
    this.config = null;
    rmSync(this.deps.paths.dir, { recursive: true, force: true });
    this.attempts = 0;
    this.setState("not-configured");
  }

  setAutoReconnect(on: boolean): void {
    if (this.config === null) return;
    this.config = { ...this.config, autoReconnect: on };
    this.persistConfig();
    this.deps.onStatus?.(this.getStatus());
  }

  // True when setup is complete and the user left the tunnel connected; the
  // app uses this to restore the tunnel after a restart.
  wantsConnection(): boolean {
    return this.config !== null && this.config.desiredState === "connected";
  }

  private async ensureKeypair(): Promise<void> {
    if (existsSync(this.deps.paths.identityPath) && existsSync(`${this.deps.paths.identityPath}.pub`)) {
      return;
    }
    mkdirSync(this.deps.paths.dir, { recursive: true, mode: 0o700 });
    this.deps.hardenFn(this.deps.paths.dir);
    await this.deps.execFn(
      this.deps.binaries.keygen,
      ["-t", "ed25519", "-N", "", "-C", "metavault-oss-remote", "-f", this.deps.paths.identityPath],
      KEYSCAN_TIMEOUT_MS,
    );
    this.deps.hardenFn(this.deps.paths.identityPath);
    this.deps.hardenFn(`${this.deps.paths.identityPath}.pub`);
  }

  private openLog(): void {
    if (this.logStream !== null) return;
    try {
      mkdirSync(this.deps.paths.dir, { recursive: true, mode: 0o700 });
      const stream = createWriteStream(this.deps.paths.logPath, { flags: "a", mode: 0o600 });
      // The log is diagnostics only: a logging failure must never take the
      // tunnel down, so stream errors are swallowed (no unhandled 'error').
      stream.on("error", () => {
        if (this.logStream === stream) this.logStream = null;
      });
      this.logStream = stream;
    } catch {
      this.logStream = null;
    }
  }

  private closeLog(): void {
    this.logStream?.end();
    this.logStream = null;
  }

  // Spawns the tunnel and resolves once the server has confirmed BOTH
  // reverse forwards (verbose ssh prints "remote forward success" only
  // after the server's confirmation reply), or fails with a safe reason.
  private spawnTunnel(): { child: SpawnedProcess; ready: Promise<AttemptResult> } {
    const config = this.config as SshTunnelConfig;
    this.openLog();
    const child = this.deps.spawnFn(this.deps.binaries.ssh, tunnelArgs(config, this.deps.paths), {
      stdio: ["ignore", "ignore", "pipe"],
      windowsHide: true,
      env: process.env,
    });
    let forwardsUp = 0;
    let buffer = "";
    let settled = false;
    let sawAuthFailure = false;
    let sawHostKeyFailure = false;
    const ready = new Promise<AttemptResult>((resolve) => {
      const finish = (result: AttemptResult): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(result);
      };
      const timer = setTimeout(() => {
        finish({ ok: false, retryable: true, reason: "timeout", detail: "The server did not confirm the port forwards in time." });
      }, this.deps.forwardReadyTimeoutMs);
      timer.unref();
      const onData = (chunk: Buffer | string): void => {
        const text = chunk.toString();
        this.logStream?.write(text);
        buffer += text;
        let nl = buffer.indexOf("\n");
        while (nl !== -1) {
          const line = buffer.slice(0, nl);
          buffer = buffer.slice(nl + 1);
          if (/remote forward success/i.test(line)) forwardsUp += 1;
          if (/Permission denied/i.test(line)) sawAuthFailure = true;
          if (/REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed/i.test(line)) sawHostKeyFailure = true;
          if (forwardsUp >= 2) finish({ ok: true, retryable: false });
          nl = buffer.indexOf("\n");
        }
      };
      child.stderr?.on("data", onData);
      child.once("exit", () => {
        if (sawHostKeyFailure) {
          finish({ ok: false, retryable: false, reason: "host-key-changed", detail: "The server's host key no longer matches the pinned fingerprint. Remove this connection and set it up again only if you expected the key to change." });
        } else if (sawAuthFailure) {
          finish({ ok: false, retryable: false, reason: "auth-failed", detail: "The server refused the key. Reinstall the public key on the server, then try again." });
        } else {
          finish({ ok: false, retryable: true, reason: "forward-refused", detail: "The server closed the connection before the port forwards were confirmed." });
        }
      });
    });
    return { child, ready };
  }

  // One full connect attempt: spawn, wait for the server to confirm both
  // reverse forwards, then require the local gateway listeners too. The
  // spawned process keeps running after success - it IS the tunnel.
  private async attempt(): Promise<AttemptResult> {
    if (this.config === null) return { ok: false, retryable: false, reason: "timeout" };
    const { child, ready } = this.spawnTunnel();
    this.child = child;
    const result = await ready;
    if (!result.ok) {
      this.killChild();
      return result;
    }
    const gatewayOk = this.deps.gatewayReady !== undefined ? await this.deps.gatewayReady() : true;
    if (!gatewayOk) {
      this.killChild();
      return { ok: false, retryable: false, reason: "gateway-down", detail: "The local gateway is not running. Turn remote access on first." };
    }
    return { ok: true, retryable: false };
  }

  async connect(): Promise<SshTunnelStatus> {
    if (this.config === null) {
      this.setState("not-configured");
      return this.getStatus();
    }
    this.connectInFlight ??= this.doConnect();
    try {
      return await this.connectInFlight;
    } finally {
      this.connectInFlight = null;
    }
  }

  private async doConnect(): Promise<SshTunnelStatus> {
    if (this.config === null) return this.getStatus();
    this.intentionalStop = false;
    if (this.config.desiredState !== "connected") {
      this.config = { ...this.config, desiredState: "connected" };
      this.persistConfig();
    }
    while (this.wantsConnection() && !this.stopRequested()) {
      this.attempts += 1;
      this.setState(this.attempts > 1 ? "reconnecting" : "connecting");
      const result = await this.attempt();
      if (this.stopRequested()) return this.getStatus();
      if (result.ok) {
        this.connectedAt = this.deps.now();
        this.setState("connected");
        this.armWatchdog();
        return this.getStatus();
      }
      if (!result.retryable) {
        // Terminal failure (auth, host key, gateway): never auto-retry, and
        // a changed host key additionally flips desiredState off so a
        // restart cannot silently reconnect to an unpinned server.
        if (result.reason === "host-key-changed" || result.reason === "gateway-down") {
          this.config = { ...this.config, desiredState: "off" };
          this.persistConfig();
        }
        this.setState("error", result.detail ?? "The tunnel could not be established.");
        return this.getStatus();
      }
      const maxAttempts = this.config.autoReconnect ? this.deps.maxAttempts : 1;
      if (this.attempts >= maxAttempts) {
        this.setState("error", "Could not establish the tunnel. Check that the server is reachable and try again.");
        return this.getStatus();
      }
      const delay = this.deps.retryDelaysMs[Math.min(this.attempts - 1, this.deps.retryDelaysMs.length - 1)] ?? 32000;
      await this.deps.wait(delay);
    }
    return this.getStatus();
  }

  // Watches an established tunnel: an unexpected drop reconnects with the
  // same bounded backoff, as long as the user still wants the connection.
  private armWatchdog(): void {
    const child = this.child;
    if (child === null) return;
    if (this.stableTimer !== null) clearTimeout(this.stableTimer);
    this.stableTimer = setTimeout(() => {
      this.attempts = 0;
      this.stableTimer = null;
    }, STABLE_RESET_MS);
    this.stableTimer.unref();
    child.once("exit", () => {
      if (this.child !== child) return;
      this.child = null;
      if (this.stableTimer !== null) {
        clearTimeout(this.stableTimer);
        this.stableTimer = null;
      }
      this.connectedAt = null;
      if (this.intentionalStop) return;
      if (this.config === null || this.config.desiredState !== "connected") {
        this.setState("off");
        return;
      }
      if (this.config.autoReconnect) {
        this.attempts = 0;
        void this.connect();
      } else {
        this.setState("error", "The tunnel dropped. Connect again when you are ready.");
      }
    });
  }

  // Read through a method so cross-await intent is explicit (and property
  // narrowing does not hide a disconnect that landed during an await).
  private stopRequested(): boolean {
    return this.intentionalStop;
  }

  private killChild(): void {
    const child = this.child;
    this.child = null;
    if (child !== null) {
      try {
        child.kill();
      } catch {
        // Already gone.
      }
    }
  }

  disconnect(): Promise<SshTunnelStatus> {
    this.intentionalStop = true;
    if (this.config !== null && this.config.desiredState !== "off") {
      this.config = { ...this.config, desiredState: "off" };
      this.persistConfig();
    }
    if (this.stableTimer !== null) {
      clearTimeout(this.stableTimer);
      this.stableTimer = null;
    }
    this.killChild();
    this.connectedAt = null;
    this.attempts = 0;
    this.closeLog();
    if (this.config !== null) this.setState("off");
    return Promise.resolve(this.getStatus());
  }

  // App quit: stop the tunnel we own. desiredState survives so the next
  // launch restores the connection.
  shutdown(): Promise<void> {
    this.intentionalStop = true;
    if (this.stableTimer !== null) {
      clearTimeout(this.stableTimer);
      this.stableTimer = null;
    }
    this.killChild();
    this.closeLog();
    return Promise.resolve();
  }

  // Proves the key is installed and the forwards are accepted, using one
  // short-lived tunnel that is always torn down before returning.
  private async probeOnce(): Promise<SetupVerification> {
    const gatewayOk = this.deps.gatewayReady !== undefined ? await this.deps.gatewayReady() : true;
    if (!gatewayOk) {
      return { verified: false, reason: "gateway-down" };
    }
    const { child, ready } = this.spawnTunnel();
    const result = await ready;
    try {
      child.kill();
    } catch {
      // Already gone.
    }
    if (result.ok) return { verified: true };
    return { verified: false, reason: result.reason ?? "timeout" };
  }
}
