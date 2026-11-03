import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { Writable, type Readable } from "node:stream";
import { pathToFileURL } from "node:url";
import { Cause, Data, Effect, Exit, Schema } from "effect";
import { DEFAULT_MARSHAL_MODEL } from "../../brain/src/ollama.js";
import { decryptSecret, encryptSecret } from "../../core/src/crypto.js";
import { metavaultEnv } from "../../core/src/env.js";
import { parseDotEnvWithInference } from "../../core/src/dotenv.js";
import { deleteMasterKey, retrieveMasterKey, storeMasterKey } from "../../core/src/keychain.js";
import { CARD_KIND, DEFAULT_CARD_SCOPE } from "../../core/src/card.js";
import { envMasterKeyIfAllowed } from "../../core/src/key-session.js";
import {
  argon2Available,
  checkPassphraseStrength,
  MIN_PASSPHRASE_LENGTH,
  readWrappedKeyFile,
  unwrapMasterKey,
  wrapMasterKey,
  wrappedKeyFilePath,
  writeWrappedKeyFile,
  type KdfName,
  type WrapOptions,
} from "../../core/src/keywrap.js";
import { MarshalUnavailable, StorageError } from "../../core/src/errors.js";
import { VaultStore, VaultStoreLive } from "../../core/src/storage.js";
import type { AuditEvent } from "../../core/src/types.js";
import { EnrollmentIdSchema, EnrollmentRequestSchema, GrantIdSchema, RevokeSchema } from "../../daemon/src/schemas.js";

// The CLI is a system edge, like the daemon HTTP handler and the MCP
// adapter: it composes core Effects and daemon HTTP calls, then converts
// the result with Effect.runPromiseExit. No business logic lives here —
// policy, grants, and audit are the daemon's; encryption is core's.
// Failures print only the tagged error name, never messages or payloads,
// so a secret (or anything derived from one) cannot reach the terminal.

export class UsageError extends Data.TaggedError("UsageError")<{
  readonly message?: string;
}> {
  constructor(props: { readonly message?: string } = {}) {
    super(props);
  }
}

export class MasterKeyUnavailable extends Data.TaggedError("MasterKeyUnavailable")<{
  readonly message?: string;
}> {
  constructor(props: { readonly message?: string } = {}) {
    super(props);
  }
}

export class DaemonError extends Data.TaggedError("DaemonError")<{
  readonly upstreamTag?: string;
  readonly message?: string;
}> {
  constructor(
    props: { readonly upstreamTag?: string; readonly message?: string } = {},
  ) {
    super(props);
  }
}

type CliFailure =
  | UsageError
  | MasterKeyUnavailable
  | DaemonError
  | MarshalUnavailable
  | StorageError;

export type CliFetch = typeof fetch;

export type CliSpawn = (
  command: string,
  args: readonly string[],
  options: {
    readonly stdio: "inherit";
    readonly shell?: boolean;
    readonly env: NodeJS.ProcessEnv;
  },
) => {
  readonly on: (event: string, cb: (code: number | null) => void) => void;
};

export interface CliDeps {
  readonly daemonUrl?: string | undefined;
  readonly ollamaUrl?: string | undefined;
  readonly fetchFn?: CliFetch | undefined;
  readonly readSecret?: ((prompt: string) => Promise<string>) | undefined;
  readonly masterKey?: Buffer | undefined;
  readonly dbPath?: string | undefined;
  readonly daemonToken?: string | undefined;
  readonly out?: ((text: string) => void) | undefined;
  readonly err?: ((text: string) => void) | undefined;
  readonly input?: Readable | undefined;
  readonly output?: Writable | undefined;
  readonly spawnFn?: CliSpawn | undefined;
  // Test seams for key protection: KDF cost and the OS keychain.
  readonly keyWrapOptions?: WrapOptions | undefined;
  readonly keychain?: CliKeychain | undefined;
}

export interface CliKeychain {
  readonly retrieve: () => Buffer | null;
  readonly store: (key: Buffer) => boolean;
  readonly remove: () => boolean;
}

const OS_KEYCHAIN: CliKeychain = {
  retrieve: retrieveMasterKey,
  store: storeMasterKey,
  remove: deleteMasterKey,
};

function keychainOf(deps: CliDeps): CliKeychain {
  return deps.keychain ?? OS_KEYCHAIN;
}

interface ResolvedIo {
  readonly out: (text: string) => void;
  readonly err: (text: string) => void;
  readonly fetchFn: CliFetch;
  readonly daemonUrl: string;
  readonly ollamaBase: string;
  readonly daemonToken: string | undefined;
  readonly readSecret: (prompt: string) => Promise<string>;
}

const USAGE =
  "usage: metavault <init [--kdf scrypt|argon2id] [--legacy-keychain]|key status|key protect [--kdf scrypt|argon2id] [--keep-keychain]|unlock|lock|add <alias> --scope <s>|add-card <alias> [--scope <s>] [--website <w>]|import <path>|run -- <command...>|approve <grantId>|audit|revoke <target>|enroll --alias <a> --scope <s> [--website <w>]|enroll-status <enrollmentId>|model pull>\n";

function trimTrailingSlashes(url: string): string {
  return url.replace(/\/+$/, "");
}

// Daemon token for the human-decision routes: explicit dep, then
// METAVAULT_DAEMON_TOKEN, then the metavault.token file the daemon writes
// next to the vault DB. The token itself is never printed.
function resolveDaemonToken(deps: CliDeps): string | undefined {
  if (deps.daemonToken !== undefined && deps.daemonToken !== "") {
    return deps.daemonToken;
  }
  const fromEnv = metavaultEnv("DAEMON_TOKEN");
  if (fromEnv !== undefined && fromEnv !== "") {
    return fromEnv;
  }
  try {
    const text = readFileSync(
      join(dirname(resolveDbPath(deps)), "metavault.token"),
      "utf8",
    ).trim();
    return text === "" ? undefined : text;
  } catch {
    return undefined;
  }
}

function resolveIo(deps: CliDeps): ResolvedIo {
  const out =
    deps.out ??
    ((text: string): void => {
      process.stdout.write(text);
    });
  const err =
    deps.err ??
    ((text: string): void => {
      process.stderr.write(text);
    });
  return {
    out,
    err,
    fetchFn: deps.fetchFn ?? fetch,
    daemonUrl: trimTrailingSlashes(
      deps.daemonUrl ?? metavaultEnv("DAEMON_URL") ?? "http://127.0.0.1:7077",
    ),
    ollamaBase: trimTrailingSlashes(
      deps.ollamaUrl ?? metavaultEnv("OLLAMA_URL") ?? "http://localhost:11434",
    ),
    daemonToken: resolveDaemonToken(deps),
    readSecret:
      deps.readSecret ??
      ((prompt: string): Promise<string> =>
        readSecretHidden(prompt, deps.input ?? process.stdin, deps.output ?? process.stdout)),
  };
}

function resolveDbPath(deps: CliDeps): string {
  return deps.dbPath ?? metavaultEnv("DB_PATH") ?? join(process.cwd(), "metavault.db");
}

// Hidden secret prompt built on node:readline. The prompt itself goes to
// the real output; everything readline would echo (the typed secret) is
// routed to a discarding sink, so the secret is never echoed.
export function readSecretHidden(
  prompt: string,
  input: Readable,
  output: Writable,
): Promise<string> {
  return new Promise((resolve, reject) => {
    try {
      output.write(prompt);
      const sink = new Writable({
        write: (_chunk, _encoding, callback) => {
          callback();
        },
      });
      const rl = createInterface({ input, output: sink, terminal: true });
      let settled = false;
      // EOF/close without a newline never invokes the question callback;
      // without this handler the promise would hang forever.
      rl.on("close", () => {
        if (!settled) {
          settled = true;
          reject(new Error("failed to read secret: input closed"));
        }
      });
      rl.question("", (answer) => {
        settled = true;
        rl.close();
        output.write("\n");
        resolve(answer);
      });
    } catch (cause) {
      reject(cause instanceof Error ? cause : new Error("failed to read secret"));
    }
  });
}

// Where the CLI finds the master key, in order: injected (tests), the
// opt-in env var, the passphrase-wrapped key file (prompts), then a legacy
// raw key in the OS keychain (with a migration warning).
type KeySource = "injected" | "env" | "passphrase" | "keychain-legacy";

function legacyMasterKey(deps: CliDeps): { key: Buffer; source: KeySource } | null {
  if (deps.masterKey !== undefined) {
    if (deps.masterKey.length !== 32) {
      throw new Error("masterKey must be 32 bytes");
    }
    return { key: deps.masterKey, source: "injected" };
  }
  const fromEnv = envMasterKeyIfAllowed();
  if (fromEnv !== undefined) return { key: fromEnv, source: "env" };
  const fromKeychain = keychainOf(deps).retrieve();
  return fromKeychain !== null ? { key: fromKeychain, source: "keychain-legacy" } : null;
}

function masterKeyEffect(deps: CliDeps, io: ResolvedIo): Effect.Effect<Buffer, MasterKeyUnavailable> {
  return Effect.gen(function* () {
    if (deps.masterKey !== undefined) {
      const injected = yield* Effect.try({
        try: () => legacyMasterKey(deps),
        catch: () => new MasterKeyUnavailable({ message: "masterKey must be 32 bytes" }),
      });
      if (injected !== null) return injected.key;
    }
    const wrapped = yield* Effect.try({
      try: () => readWrappedKeyFile(wrappedKeyFilePath(resolveDbPath(deps))),
      catch: () => new MasterKeyUnavailable({ message: "key file is unreadable" }),
    });
    if (wrapped !== null) {
      const passphrase = yield* Effect.tryPromise({
        try: () => io.readSecret("Vault passphrase: "),
        catch: () => new MasterKeyUnavailable({ message: "failed to read passphrase" }),
      });
      return yield* Effect.tryPromise({
        try: () => unwrapMasterKey(wrapped, passphrase),
        catch: () => new MasterKeyUnavailable({ message: "wrong passphrase" }),
      });
    }
    const legacy = yield* Effect.try({
      try: () => legacyMasterKey(deps),
      catch: (err) =>
        new MasterKeyUnavailable({ message: err instanceof Error ? err.message : "master key unavailable" }),
    });
    if (legacy === null) {
      return yield* Effect.fail(
        new MasterKeyUnavailable({ message: "master key unavailable: run `metavault init`" }),
      );
    }
    if (legacy.source === "keychain-legacy") {
      io.err("warning: using an unwrapped legacy keychain key; run `metavault key protect` to add a passphrase\n");
    }
    return legacy.key;
  });
}

function parseKdf(args: readonly string[]): KdfName | null | undefined {
  const i = args.indexOf("--kdf");
  const value = i >= 0 ? args[i + 1] : args.find((a) => a.startsWith("--kdf="))?.slice("--kdf=".length);
  if (value === undefined) return undefined;
  return value === "scrypt" || value === "argon2id" ? value : null;
}

function promptNewPassphrase(io: ResolvedIo): Effect.Effect<string, UsageError> {
  return Effect.gen(function* () {
    const first = yield* Effect.tryPromise({
      try: () => io.readSecret(`New vault passphrase (min ${String(MIN_PASSPHRASE_LENGTH)} chars): `),
      catch: () => new UsageError({ message: "failed to read passphrase" }),
    });
    if (checkPassphraseStrength(first) !== "ok") {
      return yield* Effect.fail(
        new UsageError({ message: `passphrase must be at least ${String(MIN_PASSPHRASE_LENGTH)} characters` }),
      );
    }
    const second = yield* Effect.tryPromise({
      try: () => io.readSecret("Repeat passphrase: "),
      catch: () => new UsageError({ message: "failed to read passphrase" }),
    });
    if (first !== second) {
      return yield* Effect.fail(new UsageError({ message: "passphrases do not match" }));
    }
    return first;
  });
}

function wrapAndWrite(
  deps: CliDeps,
  key: Buffer,
  passphrase: string,
  kdf: KdfName,
): Effect.Effect<string, MasterKeyUnavailable> {
  return Effect.tryPromise({
    try: async () => {
      if (kdf === "argon2id" && !argon2Available()) {
        throw new Error("argon2id needs Node >= 24.7 (node:crypto argon2)");
      }
      const options: WrapOptions = { ...(deps.keyWrapOptions ?? {}), kdf };
      const wrapped = await wrapMasterKey(key, passphrase, options);
      // Verify before anything else is torn down.
      const check = await unwrapMasterKey(wrapped, passphrase);
      const same = check.equals(key);
      check.fill(0);
      if (!same) throw new Error("wrap verification failed");
      const path = wrappedKeyFilePath(resolveDbPath(deps));
      writeWrappedKeyFile(path, wrapped);
      return path;
    },
    catch: (err) =>
      new MasterKeyUnavailable({ message: err instanceof Error ? err.message : "failed to protect key" }),
  });
}

interface DaemonReply {
  readonly status: number;
  readonly body: unknown;
}

function errorTagOf(body: unknown): string | undefined {
  if (typeof body !== "object" || body === null) {
    return undefined;
  }
  const error: unknown = (body as Record<string, unknown>)["error"];
  if (typeof error !== "object" || error === null) {
    return undefined;
  }
  const tag: unknown = (error as Record<string, unknown>)["_tag"];
  return typeof tag === "string" ? tag : undefined;
}

function daemonCall(
  io: ResolvedIo,
  method: "GET" | "POST",
  path: string,
  body?: unknown,
): Effect.Effect<DaemonReply, DaemonError> {
  const request: Effect.Effect<DaemonReply, DaemonError> = Effect.tryPromise({
    try: async (): Promise<DaemonReply> => {
      const res = await io.fetchFn(`${io.daemonUrl}${path}`, {
        method,
        headers: {
          "content-type": "application/json",
          ...(io.daemonToken !== undefined
            ? { "x-metavault-token": io.daemonToken }
            : {}),
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
      const text = await res.text();
      const parsed: unknown = JSON.parse(text) as unknown;
      return { status: res.status, body: parsed };
    },
    catch: () => new DaemonError({ message: "daemon request failed" }),
  });
  return request.pipe(
    Effect.flatMap((reply) => {
      if (reply.status < 400) {
        return Effect.succeed(reply);
      }
      const tag = errorTagOf(reply.body);
      return Effect.fail(
        new DaemonError(tag !== undefined ? { upstreamTag: tag } : { message: "daemon error" }),
      );
    }),
  );
}

const AUDIT_STAGES: readonly string[] = [
  "requested",
  "marshal",
  "policy",
  "approved",
  "denied",
  "executed",
  "expired",
  "revoked",
  "credential-added",
  "credential-deleted",
  "enrollment-created",
  "enrollment-completed",
];

function toAuditEvent(value: unknown): AuditEvent | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const record = value as Record<string, unknown>;
  const ts = record["ts"];
  const agentId = record["agentId"];
  const alias = record["alias"];
  const scope = record["scope"];
  const stage = record["stage"];
  const detail = record["detail"];
  const modelId = record["modelId"];
  const explanation = record["explanation"];
  if (
    typeof ts !== "string" ||
    typeof agentId !== "string" ||
    typeof alias !== "string" ||
    typeof scope !== "string" ||
    typeof stage !== "string" ||
    !AUDIT_STAGES.includes(stage) ||
    typeof detail !== "string"
  ) {
    return null;
  }
  const base: AuditEvent = {
    ts,
    agentId,
    alias,
    scope,
    stage: stage as AuditEvent["stage"],
    detail,
  };
  let event: AuditEvent = base;
  if (typeof modelId === "string") event = { ...event, modelId };
  if (typeof explanation === "string") event = { ...event, explanation };
  return event;
}

function auditEventsOf(body: unknown): AuditEvent[] | null {
  if (typeof body !== "object" || body === null) {
    return null;
  }
  const events: unknown = (body as Record<string, unknown>)["events"];
  if (!Array.isArray(events)) {
    return null;
  }
  const parsed: AuditEvent[] = [];
  for (const item of events as unknown[]) {
    const event = toAuditEvent(item);
    if (event === null) {
      return null;
    }
    parsed.push(event);
  }
  return parsed;
}

function formatAuditEvent(event: AuditEvent): string {
  const base = `${event.ts} ${event.agentId} ${event.alias} ${event.scope} ${event.stage} ${event.detail}`;
  const withModel = event.modelId !== undefined ? `${base} model=${event.modelId}` : base;
  return event.explanation !== undefined ? `${withModel} ${event.explanation}\n` : `${withModel}\n`;
}

function stringifyBody(body: unknown): string {
  // body always comes from JSON.parse, so stringify always yields a string.
  return `${JSON.stringify(body)}\n`;
}

function initProgram(deps: CliDeps, io: ResolvedIo, args: readonly string[]): Effect.Effect<string, CliFailure> {
  return Effect.gen(function* () {
    const dbPath = resolveDbPath(deps);
    const openStore = Effect.gen(function* () {
      const store = yield* VaultStore;
      yield* store.listAudit();
    }).pipe(Effect.provide(VaultStoreLive(dbPath)));
    const header = `initialized vault at ${dbPath}\n`;
    const wrapped = yield* Effect.try({
      try: () => readWrappedKeyFile(wrappedKeyFilePath(dbPath)),
      catch: () => new MasterKeyUnavailable({ message: "key file is unreadable" }),
    });
    if (wrapped !== null) {
      yield* openStore;
      return `${header}master key: existing passphrase-protected key reused (${wrapped.kdf})\n`;
    }
    const existing = yield* Effect.try({
      try: () => legacyMasterKey(deps),
      catch: () =>
        new MasterKeyUnavailable({
          message: "existing master key is malformed (must be base64-encoded 32 bytes)",
        }),
    });
    if (existing !== null) {
      yield* openStore;
      const hint = existing.source === "injected" ? "" : "run `metavault key protect` to add a passphrase\n";
      return `${header}master key: existing key reused (not shown)\n${hint}`;
    }
    const masterKey = yield* Effect.sync(() => randomBytes(32));
    if (args.includes("--legacy-keychain")) {
      // Old behaviour, kept for scripted setups: raw key in the keychain,
      // no passphrase, no auto-lock.
      const saved = keychainOf(deps).store(masterKey);
      yield* openStore;
      const notice = saved
        ? "master key saved to the OS keychain UNWRAPPED (legacy mode, no auto-lock)\n"
        : "store this key yourself; it will not be shown again\n";
      return `${header}master key (shown once): ${masterKey.toString("base64")}\n${notice}`;
    }
    const kdf = parseKdf(args);
    if (kdf === null) {
      return yield* Effect.fail(new UsageError({ message: "--kdf must be scrypt or argon2id" }));
    }
    const passphrase = yield* promptNewPassphrase(io);
    const path = yield* wrapAndWrite(deps, masterKey, passphrase, kdf ?? "scrypt");
    masterKey.fill(0);
    yield* openStore;
    return (
      `${header}master key: generated and sealed with your passphrase (${kdf ?? "scrypt"}) at ${path}\n` +
      "the raw key is never shown or stored; if you forget the passphrase the vault cannot be decrypted\n"
    );
  });
}

function keyStatusProgram(deps: CliDeps): Effect.Effect<string, CliFailure> {
  return Effect.try({
    try: () => {
      const path = wrappedKeyFilePath(resolveDbPath(deps));
      const wrapped = readWrappedKeyFile(path);
      const envSet = (process.env["METAVAULT_MASTER_KEY"] ?? "") !== "";
      const envAllowed = process.env["METAVAULT_ALLOW_ENV_MASTER_KEY"] === "1";
      const keychain = keychainOf(deps).retrieve() !== null;
      const lines = [
        wrapped !== null
          ? `passphrase-protected key: yes (${wrapped.kdf}, ${JSON.stringify(wrapped.params)}) at ${path}`
          : "passphrase-protected key: no",
        `legacy keychain key present: ${keychain ? "yes" : "no"}`,
        `METAVAULT_MASTER_KEY set: ${envSet ? "yes" : "no"}${envSet ? (envAllowed ? " (allowed by opt-in)" : " (ignored: opt-in not set)") : ""}`,
      ];
      if (wrapped === null && (keychain || envSet)) lines.push("recommendation: run `metavault key protect`");
      if (wrapped !== null && keychain) lines.push("recommendation: remove the legacy keychain copy (`metavault key protect` deletes it)");
      return `${lines.join("\n")}\n`;
    },
    catch: () => new MasterKeyUnavailable({ message: "key file is unreadable" }),
  });
}

function keyProtectProgram(deps: CliDeps, io: ResolvedIo, args: readonly string[]): Effect.Effect<string, CliFailure> {
  return Effect.gen(function* () {
    const kdf = parseKdf(args);
    if (kdf === null) {
      return yield* Effect.fail(new UsageError({ message: "--kdf must be scrypt or argon2id" }));
    }
    const path = wrappedKeyFilePath(resolveDbPath(deps));
    const already = yield* Effect.try({
      try: () => readWrappedKeyFile(path),
      catch: () => new MasterKeyUnavailable({ message: "key file is unreadable" }),
    });
    if (already !== null) {
      return yield* Effect.fail(new UsageError({ message: "the key is already passphrase-protected" }));
    }
    const legacy = yield* Effect.try({
      try: () => legacyMasterKey(deps),
      catch: (err) =>
        new MasterKeyUnavailable({ message: err instanceof Error ? err.message : "master key unavailable" }),
    });
    if (legacy === null) {
      return yield* Effect.fail(new MasterKeyUnavailable({ message: "no legacy key to protect; run `metavault init`" }));
    }
    const passphrase = yield* promptNewPassphrase(io);
    const written = yield* wrapAndWrite(deps, legacy.key, passphrase, kdf ?? "scrypt");
    const lines = [`master key sealed with your passphrase (${kdf ?? "scrypt"}) at ${written}`];
    if (legacy.source === "keychain-legacy") {
      if (args.includes("--keep-keychain")) {
        lines.push("legacy keychain copy kept (--keep-keychain); remove it once the daemon unlocks with the passphrase");
      } else {
        lines.push(
          keychainOf(deps).remove()
            ? "legacy unwrapped keychain copy deleted"
            : "could not delete the legacy keychain copy; remove it by hand (service=metavault, account=master-key)",
        );
      }
    }
    if (legacy.source === "env") {
      lines.push("now unset METAVAULT_MASTER_KEY and METAVAULT_ALLOW_ENV_MASTER_KEY wherever they are set");
    }
    lines.push("restart the daemon; it starts locked: run `metavault unlock`");
    return `${lines.join("\n")}\n`;
  });
}

function unlockProgram(io: ResolvedIo): Effect.Effect<string, CliFailure> {
  return Effect.gen(function* () {
    const passphrase = yield* Effect.tryPromise({
      try: () => io.readSecret("Vault passphrase: "),
      catch: () => new UsageError({ message: "failed to read passphrase" }),
    });
    const reply = yield* daemonCall(io, "POST", "/unlock", { passphrase });
    return stringifyBody(reply.body);
  });
}

function lockProgram(io: ResolvedIo): Effect.Effect<string, CliFailure> {
  return daemonCall(io, "POST", "/lock", {}).pipe(Effect.map((reply) => stringifyBody(reply.body)));
}

function parseCardArgs(rest: readonly string[]): { alias: string; scope: string; website?: string } | null {
  let alias: string | undefined;
  let scope: string | undefined;
  let website: string | undefined;
  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i];
    if (arg === "--scope") { scope = rest[i + 1]; i += 1; }
    else if (arg !== undefined && arg.startsWith("--scope=")) { scope = arg.slice("--scope=".length); }
    else if (arg === "--website") { website = rest[i + 1]; i += 1; }
    else if (arg !== undefined && arg.startsWith("--website=")) { website = arg.slice("--website=".length); }
    else if (arg !== undefined && !arg.startsWith("--") && alias === undefined) { alias = arg; }
    else { return null; }
  }
  if (alias === undefined || alias === "" || scope === "") return null;
  return { alias, scope: scope ?? DEFAULT_CARD_SCOPE, ...(website !== undefined && website !== "" ? { website } : {}) };
}

// Card entry goes to the daemon (which validates and encrypts it); the
// CLI never needs the master key for it. All four fields are read hidden.
function addCardProgram(
  io: ResolvedIo,
  input: { alias: string; scope: string; website?: string },
): Effect.Effect<string, CliFailure> {
  return Effect.gen(function* () {
    const ask = (prompt: string) =>
      Effect.tryPromise({
        try: () => io.readSecret(prompt),
        catch: () => new UsageError({ message: "failed to read card details" }),
      });
    const number = yield* ask(`Card number for ${input.alias}: `);
    const name = yield* ask("Name on card: ");
    const expiry = yield* ask("Expiry (MM/YY): ");
    const cvv = yield* ask("CVV: ");
    const m = /^\s*(\d{1,2})\s*\/\s*(\d{2}|\d{4})\s*$/.exec(expiry);
    if (m === null) {
      return yield* Effect.fail(new UsageError({ message: "expiry must be MM/YY" }));
    }
    const reply = yield* daemonCall(io, "POST", "/cards", {
      alias: input.alias,
      number,
      name,
      expMonth: Number(m[1]),
      expYear: Number(m[2]),
      cvv,
      scope: input.scope,
      ...(input.website !== undefined ? { website: input.website } : {}),
    });
    const body = reply.body as { card?: { brand?: unknown; masked?: unknown } };
    const brand = typeof body.card?.brand === "string" ? body.card.brand : "card";
    const masked = typeof body.card?.masked === "string" ? body.card.masked : "";
    return `added card ${input.alias}: ${brand} ${masked} (scope ${input.scope}; every use needs your approval)\n`;
  });
}

function parseAddArgs(
  rest: readonly string[],
): { readonly alias: string; readonly scope: string } | null {
  let alias: string | undefined;
  let scope: string | undefined;
  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i];
    if (arg === "--scope") {
      scope = rest[i + 1];
      i += 1;
    } else if (arg !== undefined && arg.startsWith("--scope=")) {
      scope = arg.slice("--scope=".length);
    } else if (arg !== undefined && !arg.startsWith("--") && alias === undefined) {
      alias = arg;
    } else {
      return null;
    }
  }
  if (alias === undefined || alias === "" || scope === undefined || scope === "") {
    return null;
  }
  return { alias, scope };
}

function addProgram(
  deps: CliDeps,
  io: ResolvedIo,
  alias: string,
  scope: string,
): Effect.Effect<string, CliFailure> {
  return Effect.gen(function* () {
    const secret = yield* Effect.tryPromise({
      try: () => io.readSecret(`Secret for ${alias}: `),
      catch: () => new UsageError({ message: "failed to read secret" }),
    });
    if (secret.length === 0) {
      return yield* Effect.fail(new UsageError({ message: "secret must not be empty" }));
    }
    const masterKey = yield* masterKeyEffect(deps, io);
    const ciphertext = yield* Effect.sync(() => encryptSecret(masterKey, secret));
    yield* Effect.gen(function* () {
      const store = yield* VaultStore;
      yield* store.addCredential(alias, scope, ciphertext);
    }).pipe(Effect.provide(VaultStoreLive(resolveDbPath(deps))));
    return `added ${alias} (scope ${scope})\n`;
  });
}

function importProgram(
  deps: CliDeps,
  io: ResolvedIo,
  filePath: string,
): Effect.Effect<string, CliFailure> {
  return Effect.gen(function* () {
    const content = yield* Effect.try({
      try: () => readFileSync(filePath, "utf8"),
      catch: () => new UsageError({ message: `failed to read .env file at ${filePath}` }),
    });
    const items = parseDotEnvWithInference(content);
    if (items.length === 0) {
      return `no credentials found in ${filePath}\n`;
    }
    const masterKey = yield* masterKeyEffect(deps, io);
    const dbPath = resolveDbPath(deps);

    yield* Effect.gen(function* () {
      const store = yield* VaultStore;
      for (const item of items) {
        const ciphertext = encryptSecret(masterKey, item.value);
        yield* store.addCredential(item.alias, item.scope, ciphertext, `env:${item.rawKey}`);
      }
    }).pipe(Effect.provide(VaultStoreLive(dbPath)));

    let out = `imported ${String(items.length)} credential${items.length === 1 ? "" : "s"} from ${filePath}:\n`;
    for (const item of items) {
      out += `  • ${item.rawKey} -> alias: ${item.alias} (scope ${item.scope})\n`;
    }
    return out;
  });
}

function runProgram(
  deps: CliDeps,
  io: ResolvedIo,
  commandAndArgs: readonly string[],
): Effect.Effect<string, CliFailure> {
  return Effect.gen(function* () {
    if (commandAndArgs.length === 0) {
      return yield* Effect.fail(new UsageError({ message: "run requires a command to execute" }));
    }
    const masterKey = yield* masterKeyEffect(deps, io);
    const dbPath = resolveDbPath(deps);

    const envSecrets: Record<string, string> = {};
    yield* Effect.gen(function* () {
      const store = yield* VaultStore;
      const aliases = yield* store.listCredentialAliases();
      for (const alias of aliases) {
        const rec = yield* store.getCredential(alias);
        // Payment cards are never exported into a child environment.
        if (rec && rec.kind !== CARD_KIND) {
          try {
            const secret = decryptSecret(masterKey, rec.ciphertext);
            const envKey = rec.website.startsWith("env:")
              ? rec.website.slice(4)
              : alias.toUpperCase().replace(/[^A-Z0-9_]/g, "_");
            envSecrets[envKey] = secret;
          } catch {
            // Ignore un-decryptable records
          }
        }
      }
    }).pipe(Effect.provide(VaultStoreLive(dbPath)));

    const [cmd, ...args] = commandAndArgs;
    if (!cmd) {
      return yield* Effect.fail(new UsageError({ message: "command cannot be empty" }));
    }

    const spawnExecutor = deps.spawnFn ?? ((c, a, opt) => spawn(c, a as string[], opt));

    yield* Effect.tryPromise({
      try: () =>
        new Promise<void>((resolve, reject) => {
          const child = spawnExecutor(cmd, args, {
            stdio: "inherit",
            shell: process.platform === "win32",
            env: {
              ...process.env,
              ...envSecrets,
            },
          });
          child.on("close", (code: number | null) => {
            if (code !== 0 && code !== null) {
              process.exitCode = code;
            }
            resolve();
          });
          child.on("error", (err: unknown) => {
            reject(err instanceof Error ? err : new Error(String(err)));
          });
        }),
      catch: () => new UsageError({ message: "failed to spawn child process" }),
    });

    return "";
  });
}

function approveProgram(
  io: ResolvedIo,
  grantId: string,
): Effect.Effect<string, CliFailure> {
  return Effect.gen(function* () {
    const decoded = yield* Schema.decodeUnknown(GrantIdSchema)({ grantId }).pipe(
      Effect.mapError(() => new UsageError({ message: "invalid grant id" })),
    );
    const reply = yield* daemonCall(io, "POST", "/approve", decoded);
    return stringifyBody(reply.body);
  });
}

function revokeProgram(io: ResolvedIo, target: string): Effect.Effect<string, CliFailure> {
  return Effect.gen(function* () {
    const decoded = yield* Schema.decodeUnknown(RevokeSchema)({ target }).pipe(
      Effect.mapError(() => new UsageError({ message: "invalid revoke target" })),
    );
    const reply = yield* daemonCall(io, "POST", "/revoke", decoded);
    return stringifyBody(reply.body);
  });
}

function parseEnrollArgs(rest: readonly string[]): { alias: string; scope: string; website?: string } | null {
  let alias: string | undefined; let scope: string | undefined; let website: string | undefined;
  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i];
    const next = rest[i + 1];
    if (arg === "--alias") { alias = next; i += 1; }
    else if (arg !== undefined && arg.startsWith("--alias=")) { alias = arg.slice("--alias=".length); }
    else if (arg === "--scope") { scope = next; i += 1; }
    else if (arg !== undefined && arg.startsWith("--scope=")) { scope = arg.slice("--scope=".length); }
    else if (arg === "--website") { website = next; i += 1; }
    else if (arg !== undefined && arg.startsWith("--website=")) { website = arg.slice("--website=".length); }
    else { return null; }
  }
  if (alias === undefined || alias === "" || scope === undefined || scope === "") { return null; }
  return website !== undefined && website !== "" ? { alias, scope, website } : { alias, scope };
}

function enrollProgram(io: ResolvedIo, input: { alias: string; scope: string; website?: string }): Effect.Effect<string, CliFailure> {
  return Effect.gen(function* () {
    const decoded = yield* Schema.decodeUnknown(EnrollmentRequestSchema)(input).pipe(Effect.mapError(() => new UsageError({ message: "invalid enroll arguments" })));
    const reply = yield* daemonCall(io, "POST", "/enrollments", decoded);
    const body = reply.body as { enrollmentId?: unknown; deeplink?: unknown };
    if (typeof body.enrollmentId !== "string" || typeof body.deeplink !== "string") {
      return yield* Effect.fail(new DaemonError({ message: "daemon returned malformed enrollment" }));
    }
    return `enrollmentId: ${body.enrollmentId}\ndeeplink: ${body.deeplink}\n`;
  });
}

function enrollStatusProgram(io: ResolvedIo, enrollmentId: string): Effect.Effect<string, CliFailure> {
  return Effect.gen(function* () {
    const decoded = yield* Schema.decodeUnknown(EnrollmentIdSchema)({ enrollmentId }).pipe(Effect.mapError(() => new UsageError({ message: "invalid enrollment id" })));
    const reply = yield* daemonCall(io, "GET", `/enrollments/${encodeURIComponent(decoded.enrollmentId)}`);
    return stringifyBody(reply.body);
  });
}

function auditProgram(io: ResolvedIo): Effect.Effect<string, CliFailure> {
  return Effect.gen(function* () {
    const reply = yield* daemonCall(io, "GET", "/audit");
    const events = auditEventsOf(reply.body);
    if (events === null) {
      return yield* Effect.fail(new DaemonError({ message: "daemon returned malformed audit" }));
    }
    return events.map(formatAuditEvent).join("");
  });
}

function modelPullProgram(io: ResolvedIo, model: string): Effect.Effect<string, CliFailure> {
  const pull: Effect.Effect<void, MarshalUnavailable> = Effect.tryPromise({
    try: async (): Promise<void> => {
      const res = await io.fetchFn(`${io.ollamaBase}/api/pull`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: model, stream: false }),
      });
      await res.text();
      if (!res.ok) {
        throw new Error(`ollama pull returned HTTP ${String(res.status)}`);
      }
    },
    catch: () => new MarshalUnavailable({ message: "MarshalUnavailable: model pull failed" }),
  });
  return pull.pipe(Effect.map(() => `pulled ${model}\n`));
}

function programFor(
  argv: readonly string[],
  deps: CliDeps,
  io: ResolvedIo,
): Effect.Effect<string, CliFailure> {
  const command = argv[0];
  switch (command) {
    case "init":
      return initProgram(deps, io, argv.slice(1));
    case "key": {
      if (argv[1] === "status") return keyStatusProgram(deps);
      if (argv[1] === "protect") return keyProtectProgram(deps, io, argv.slice(2));
      return Effect.fail(new UsageError({ message: "key requires status or protect" }));
    }
    case "unlock":
      return unlockProgram(io);
    case "lock":
      return lockProgram(io);
    case "add-card": {
      const parsed = parseCardArgs(argv.slice(1));
      if (parsed === null) {
        return Effect.fail(new UsageError({ message: "add-card requires <alias> [--scope <s>] [--website <w>]" }));
      }
      return addCardProgram(io, parsed);
    }
    case "add": {
      const parsed = parseAddArgs(argv.slice(1));
      if (parsed === null) {
        return Effect.fail(new UsageError({ message: "add requires <alias> --scope <s>" }));
      }
      return addProgram(deps, io, parsed.alias, parsed.scope);
    }
    case "import": {
      const filePath = argv[1];
      if (filePath === undefined || filePath === "") {
        return Effect.fail(new UsageError({ message: "import requires <filePath>" }));
      }
      return importProgram(deps, io, filePath);
    }
    case "run": {
      const rest = argv.slice(1);
      const commandArgs = rest[0] === "--" ? rest.slice(1) : rest;
      if (commandArgs.length === 0) {
        return Effect.fail(new UsageError({ message: "run requires -- <command> [args...]" }));
      }
      return runProgram(deps, io, commandArgs);
    }
    case "approve": {
      const grantId = argv[1];
      if (grantId === undefined || grantId === "") {
        return Effect.fail(new UsageError({ message: "approve requires <grantId>" }));
      }
      return approveProgram(io, grantId);
    }
    case "audit":
      return auditProgram(io);
    case "revoke": {
      const target = argv[1];
      if (target === undefined || target === "") {
        return Effect.fail(new UsageError({ message: "revoke requires <target>" }));
      }
      return revokeProgram(io, target);
    }
    case "enroll": {
      const parsed = parseEnrollArgs(argv.slice(1));
      if (parsed === null) { return Effect.fail(new UsageError({ message: "enroll requires --alias <a> --scope <s> [--website <w>]" })); }
      return enrollProgram(io, parsed);
    }
    case "enroll-status": {
      const enrollmentId = argv[1];
      if (enrollmentId === undefined || enrollmentId === "") { return Effect.fail(new UsageError({ message: "enroll-status requires <enrollmentId>" })); }
      return enrollStatusProgram(io, enrollmentId);
    }
    case "model": {
      if (argv[1] !== "pull") {
        return Effect.fail(new UsageError({ message: "model requires the pull subcommand" }));
      }
      return modelPullProgram(io, argv[2] ?? DEFAULT_MARSHAL_MODEL);
    }
    default:
      return Effect.fail(new UsageError({ message: "unknown command" }));
  }
}

function failureName(cause: Cause.Cause<CliFailure>): string {
  const failure = Cause.failureOption(cause);
  if (failure._tag === "None") {
    return "InternalError";
  }
  const error: unknown = failure.value;
  if (error instanceof DaemonError && error.upstreamTag !== undefined) {
    return error.upstreamTag;
  }
  if (typeof error === "object" && error !== null && "_tag" in error) {
    const tag: unknown = (error as { readonly _tag: unknown })._tag;
    if (typeof tag === "string") {
      return tag;
    }
  }
  return "InternalError";
}

function isUsageFailure(cause: Cause.Cause<CliFailure>): boolean {
  const failure = Cause.failureOption(cause);
  return failure._tag === "Some" && failure.value instanceof UsageError;
}

export async function runCli(argv: readonly string[], deps: CliDeps = {}): Promise<number> {
  const io = resolveIo(deps);
  const exit = await Effect.runPromiseExit(programFor(argv, deps, io));
  if (Exit.isSuccess(exit)) {
    if (exit.value !== "") {
      io.out(exit.value);
    }
    return 0;
  }
  io.err(`error: ${failureName(exit.cause)}\n`);
  if (isUsageFailure(exit.cause)) {
    io.err(USAGE);
    return 2;
  }
  return 1;
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  runCli(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch(() => {
      process.stderr.write("error: InternalError\n");
      process.exitCode = 1;
    });
}

