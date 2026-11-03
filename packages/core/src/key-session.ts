// The unlocked-session holder for the vault master key.
//
// In passphrase mode the daemon starts LOCKED. A human unlocks it with the
// passphrase; the key then lives in one Buffer until the session goes idle
// for autoLockMs (default 15 min), at which point the Buffer is zero-filled
// and every decrypt fails with VaultLocked until the next unlock.
//
// Legacy modes (OS keychain, opt-in env var, injected for tests) have no
// passphrase to re-derive the key, so they never auto-lock. That is the
// main reason to migrate (see docs/SECURITY.md#master-key-protection).

import { randomBytes } from "node:crypto";
import {
  checkPassphraseStrength,
  readWrappedKeyFile,
  unwrapMasterKey,
  wrapMasterKey,
  writeWrappedKeyFile,
  WrongPassphrase,
  type WrappedMasterKey,
} from "./keywrap.js";

// "uninitialized" is the first-run state of a fresh desktop install: no
// key exists yet, every decrypt fails as locked, and the only way forward
// is setup(passphrase) (or `metavault init` writing the wrapped key file).
export type KeyMode = "passphrase" | "keychain-legacy" | "env" | "injected" | "uninitialized";

export const DEFAULT_AUTO_LOCK_MS = 15 * 60_000;
export const UNLOCK_FREE_ATTEMPTS = 5;
export const UNLOCK_BASE_BACKOFF_MS = 30_000;
export const UNLOCK_MAX_BACKOFF_MS = 15 * 60_000;

export class VaultLockedError extends Error {
  constructor() {
    super("VaultLocked: vault is locked");
    this.name = "VaultLocked";
  }
}

export interface KeySessionStatus {
  readonly mode: KeyMode;
  readonly locked: boolean;
  readonly autoLockMs: number | null;
  readonly kdf: string | null;
  readonly lockedUntilRetryMs: number | null;
}

export type UnlockResult =
  | "unlocked"
  | "already-unlocked"
  | "wrong-passphrase"
  | "throttled"
  | "not-passphrase-mode"
  | "not-initialized";

export type SetupResult = "initialized" | "already-initialized" | "too-short";

export interface KeySession {
  readonly mode: KeyMode;
  readonly key: () => Buffer;
  readonly isLocked: () => boolean;
  readonly lock: () => void;
  readonly unlock: (passphrase: string) => Promise<UnlockResult>;
  readonly status: () => KeySessionStatus;
  readonly dispose: () => void;
  // Only first-run sessions can create a key; other modes omit it.
  readonly setup?: (passphrase: string) => Promise<SetupResult>;
}

export interface KeySessionOptions {
  readonly mode: KeyMode;
  readonly key?: Buffer;
  readonly wrapped?: WrappedMasterKey;
  readonly autoLockMs?: number;
  readonly now?: () => number;
  // Proactive sweep interval; 0 disables the timer (tests use lazy checks).
  readonly sweepMs?: number;
}

export function createKeySession(options: KeySessionOptions): KeySession {
  const now = options.now ?? Date.now;
  const relockable = options.mode === "passphrase";
  const autoLockMs = relockable ? (options.autoLockMs ?? DEFAULT_AUTO_LOCK_MS) : null;
  if (relockable && options.wrapped === undefined) {
    throw new Error("passphrase mode needs a wrapped key");
  }
  if (!relockable && options.key?.length !== 32) {
    throw new Error("master key must be 32 bytes");
  }
  let key: Buffer | null = options.key !== undefined ? Buffer.from(options.key) : null;
  let lastUsed = now();
  let failures = 0;
  let blockedUntil = 0;

  const lock = (): void => {
    if (key !== null) {
      key.fill(0);
      key = null;
    }
  };

  const expired = (): boolean =>
    autoLockMs !== null && autoLockMs > 0 && key !== null && now() - lastUsed >= autoLockMs;

  const sweepMs = options.sweepMs ?? 30_000;
  const timer =
    relockable && sweepMs > 0
      ? setInterval(() => {
          if (expired()) lock();
        }, sweepMs)
      : null;
  timer?.unref();

  return {
    mode: options.mode,
    key: () => {
      if (expired()) lock();
      if (key === null) throw new VaultLockedError();
      lastUsed = now();
      return key;
    },
    isLocked: () => {
      if (expired()) lock();
      return key === null;
    },
    lock: () => {
      // Legacy modes cannot be re-unlocked without restarting, so lock is
      // a no-op there rather than a self-inflicted outage.
      if (relockable) lock();
    },
    unlock: async (passphrase) => {
      if (!relockable || options.wrapped === undefined) return "not-passphrase-mode";
      if (expired()) lock();
      if (key !== null) return "already-unlocked";
      if (now() < blockedUntil) return "throttled";
      try {
        const unwrapped = await unwrapMasterKey(options.wrapped, passphrase);
        key = unwrapped;
        lastUsed = now();
        failures = 0;
        blockedUntil = 0;
        return "unlocked";
      } catch (err) {
        if (!(err instanceof WrongPassphrase)) throw err;
        failures += 1;
        if (failures >= UNLOCK_FREE_ATTEMPTS) {
          const exp = failures - UNLOCK_FREE_ATTEMPTS;
          blockedUntil = now() + Math.min(UNLOCK_MAX_BACKOFF_MS, UNLOCK_BASE_BACKOFF_MS * 2 ** exp);
        }
        return "wrong-passphrase";
      }
    },
    status: () => {
      if (expired()) lock();
      const t = now();
      return {
        mode: options.mode,
        locked: key === null,
        autoLockMs,
        kdf: options.wrapped?.kdf ?? null,
        lockedUntilRetryMs: blockedUntil > t ? blockedUntil - t : null,
      };
    },
    dispose: () => {
      if (timer !== null) clearInterval(timer);
      lock();
    },
  };
}

// The env-var master key is a legacy, opt-in path: any process running as
// the user can read another process's environment on most systems, and it
// leaks into shell history and crash reports. It is ignored unless
// METAVAULT_ALLOW_ENV_MASTER_KEY=1 is also set; setting the key without the
// opt-in is an error, not a silent fallback.
export function envMasterKeyIfAllowed(env: NodeJS.ProcessEnv = process.env): Buffer | undefined {
  const raw = env["METAVAULT_MASTER_KEY"];
  if (raw === undefined || raw === "") return undefined;
  if (env["METAVAULT_ALLOW_ENV_MASTER_KEY"] !== "1") {
    throw new Error(
      "METAVAULT_MASTER_KEY is set but env-var keys are disabled by default. Migrate with `metavault key protect`, or set METAVAULT_ALLOW_ENV_MASTER_KEY=1 to accept the risk.",
    );
  }
  const decoded = Buffer.from(raw, "base64");
  if (decoded.length !== 32) {
    throw new Error("METAVAULT_MASTER_KEY must be base64-encoded 32 bytes");
  }
  return decoded;
}

export function autoLockMsFromEnv(env: NodeJS.ProcessEnv = process.env): number | undefined {
  const raw = env["METAVAULT_AUTO_LOCK_MINUTES"];
  if (raw === undefined || raw.trim() === "") return undefined;
  const minutes = Number(raw);
  if (!Number.isFinite(minutes) || minutes < 1 || minutes > 24 * 60) {
    throw new Error("METAVAULT_AUTO_LOCK_MINUTES must be between 1 and 1440");
  }
  return Math.round(minutes * 60_000);
}

export interface FirstRunKeySessionOptions {
  // Where the passphrase-wrapped key lives (wrappedKeyFilePath(dbPath)).
  readonly wrappedKeyPath: string;
  readonly autoLockMs?: number;
  readonly now?: () => number;
  readonly sweepMs?: number;
  // Seams for tests; production uses the real keywrap helpers.
  readonly readWrapped?: (path: string) => WrappedMasterKey | null;
  readonly writeWrapped?: (path: string, wrapped: WrappedMasterKey) => void;
  readonly wrap?: (key: Buffer, passphrase: string) => Promise<WrappedMasterKey>;
}

// A session for a vault that has no key yet. It reports mode
// "uninitialized" until a wrapped key file appears, either from setup()
// here or from `metavault init` in a terminal, and from then on behaves
// exactly like a passphrase session (auto-lock, throttled unlock). The
// fresh master key is wrapped and written before it is ever used, so no
// unwrapped copy touches disk.
export function createFirstRunKeySession(options: FirstRunKeySessionOptions): KeySession {
  const readWrapped = options.readWrapped ?? readWrappedKeyFile;
  const writeWrapped = options.writeWrapped ?? writeWrappedKeyFile;
  const wrap = options.wrap ?? ((key: Buffer, passphrase: string) => wrapMasterKey(key, passphrase));
  const base = {
    ...(options.autoLockMs !== undefined ? { autoLockMs: options.autoLockMs } : {}),
    ...(options.now !== undefined ? { now: options.now } : {}),
    ...(options.sweepMs !== undefined ? { sweepMs: options.sweepMs } : {}),
  };
  let inner: KeySession | null = null;
  let settingUp = false;

  const current = (): KeySession | null => {
    if (inner !== null) return inner;
    const wrapped = readWrapped(options.wrappedKeyPath);
    if (wrapped !== null) {
      inner = createKeySession({ mode: "passphrase", wrapped, ...base });
    }
    return inner;
  };

  return {
    get mode(): KeyMode {
      return current()?.mode ?? "uninitialized";
    },
    key: () => {
      const session = current();
      if (session === null) throw new VaultLockedError();
      return session.key();
    },
    isLocked: () => current()?.isLocked() ?? true,
    lock: () => {
      current()?.lock();
    },
    unlock: async (passphrase) => {
      const session = current();
      return session === null ? "not-initialized" : session.unlock(passphrase);
    },
    status: () =>
      current()?.status() ?? {
        mode: "uninitialized",
        locked: true,
        autoLockMs: null,
        kdf: null,
        lockedUntilRetryMs: null,
      },
    dispose: () => {
      inner?.dispose();
    },
    setup: async (passphrase) => {
      if (current() !== null || settingUp) return "already-initialized";
      if (checkPassphraseStrength(passphrase) !== "ok") return "too-short";
      settingUp = true;
      const key = randomBytes(32);
      try {
        const wrapped = await wrap(key, passphrase);
        // Another writer (e.g. `metavault init`) may have won the race.
        if (current() !== null) return "already-initialized";
        writeWrapped(options.wrappedKeyPath, wrapped);
        inner = createKeySession({ mode: "passphrase", wrapped, key, ...base });
        return "initialized";
      } finally {
        key.fill(0);
        settingUp = false;
      }
    },
  };
}
