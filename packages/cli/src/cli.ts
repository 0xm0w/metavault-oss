import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { Writable, type Readable } from "node:stream";
import { pathToFileURL } from "node:url";
import { Cause, Data, Effect, Exit, Schema } from "effect";
import { DEFAULT_MARSHAL_MODEL } from "../../brain/src/ollama.js";
import { encryptSecret } from "../../core/src/crypto.js";
import { MarshalUnavailable, StorageError } from "../../core/src/errors.js";
import { VaultStore, VaultStoreLive } from "../../core/src/storage.js";
import type { AuditEvent } from "../../core/src/types.js";
import { GrantIdSchema, RevokeSchema } from "../../daemon/src/schemas.js";

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
  "usage: openvault <init|add <alias> --scope <s>|approve <grantId>|audit|revoke <target>|model pull>\n";

function trimTrailingSlashes(url: string): string {
  return url.replace(/\/+$/, "");
}

// Daemon token for the human-decision routes: explicit dep, then
// OPENVAULT_DAEMON_TOKEN, then the openvault.token file the daemon writes
// next to the vault DB. The token itself is never printed.
function resolveDaemonToken(deps: CliDeps): string | undefined {
  if (deps.daemonToken !== undefined && deps.daemonToken !== "") {
    return deps.daemonToken;
  }
  const fromEnv = process.env["OPENVAULT_DAEMON_TOKEN"];
  if (fromEnv !== undefined && fromEnv !== "") {
    return fromEnv;
  }
  try {
    const text = readFileSync(
      join(dirname(resolveDbPath(deps)), "openvault.token"),
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
      deps.daemonUrl ?? process.env["OPENVAULT_DAEMON_URL"] ?? "http://127.0.0.1:7077",
    ),
    ollamaBase: trimTrailingSlashes(
      deps.ollamaUrl ?? process.env["OPENVAULT_OLLAMA_URL"] ?? "http://localhost:11434",
    ),
    daemonToken: resolveDaemonToken(deps),
    readSecret:
      deps.readSecret ??
      ((prompt: string): Promise<string> =>
        readSecretHidden(prompt, deps.input ?? process.stdin, deps.output ?? process.stdout)),
  };
}

function resolveDbPath(deps: CliDeps): string {
  return deps.dbPath ?? process.env["OPENVAULT_DB_PATH"] ?? join(process.cwd(), "openvault.db");
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

function envMasterKey(): Buffer | null {
  const fromEnv = process.env["OPENVAULT_MASTER_KEY"];
  if (fromEnv === undefined || fromEnv === "") {
    return null;
  }
  const decoded = Buffer.from(fromEnv, "base64");
  if (decoded.length !== 32) {
    throw new Error("OPENVAULT_MASTER_KEY must be base64-encoded 32 bytes");
  }
  return decoded;
}

function keychainMasterKey(): Buffer | null {
  try {
    let raw = "";
    if (process.platform === "darwin") {
      raw = execFileSync(
        "security",
        ["find-generic-password", "-s", "openvault", "-a", "master-key", "-w"],
        { encoding: "utf8" },
      ).trim();
    } else if (process.platform === "linux") {
      raw = execFileSync(
        "secret-tool",
        ["lookup", "service", "openvault", "account", "master-key"],
        { encoding: "utf8" },
      ).trim();
    } else {
      return null;
    }
    const decoded = Buffer.from(raw, "base64");
    return decoded.length === 32 ? decoded : null;
  } catch {
    return null;
  }
}

function existingMasterKey(deps: CliDeps): Buffer | null {
  if (deps.masterKey !== undefined) {
    if (deps.masterKey.length !== 32) {
      throw new Error("masterKey must be 32 bytes");
    }
    return deps.masterKey;
  }
  return envMasterKey() ?? keychainMasterKey();
}

function masterKeyEffect(deps: CliDeps): Effect.Effect<Buffer, MasterKeyUnavailable> {
  return Effect.try({
    try: () => {
      const key = existingMasterKey(deps);
      if (key === null) {
        throw new Error("no master key available");
      }
      return key;
    },
    catch: () =>
      new MasterKeyUnavailable({
        message:
          "master key unavailable: set OPENVAULT_MASTER_KEY (base64, 32 bytes) or store it in the OS keychain",
      }),
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
            ? { "x-openvault-token": io.daemonToken }
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
  return typeof modelId === "string" ? { ...base, modelId } : base;
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
  return event.modelId !== undefined ? `${base} model=${event.modelId}\n` : `${base}\n`;
}

function stringifyBody(body: unknown): string {
  // body always comes from JSON.parse, so stringify always yields a string.
  return `${JSON.stringify(body)}\n`;
}

function initProgram(deps: CliDeps): Effect.Effect<string, CliFailure> {
  return Effect.gen(function* () {
    const existing = yield* Effect.try({
      try: () => existingMasterKey(deps),
      catch: () =>
        new MasterKeyUnavailable({
          message: "existing master key is malformed (must be base64-encoded 32 bytes)",
        }),
    });
    const generated = existing === null;
    const masterKey = existing ?? (yield* Effect.sync(() => randomBytes(32)));
    const dbPath = resolveDbPath(deps);
    // Force the vault open so init actually creates the encrypted store.
    yield* Effect.gen(function* () {
      const store = yield* VaultStore;
      yield* store.listAudit();
    }).pipe(Effect.provide(VaultStoreLive(dbPath, masterKey)));
    const header = `initialized vault at ${dbPath}\n`;
    if (!generated) {
      return `${header}master key: existing key reused (not shown)\n`;
    }
    return (
      `${header}master key (shown once): ${masterKey.toString("base64")}\n` +
      "store this key in your OS keychain or set OPENVAULT_MASTER_KEY; it will not be shown again\n"
    );
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
    const masterKey = yield* masterKeyEffect(deps);
    const ciphertext = yield* Effect.sync(() => encryptSecret(masterKey, secret));
    yield* Effect.gen(function* () {
      const store = yield* VaultStore;
      yield* store.addCredential(alias, scope, ciphertext);
    }).pipe(Effect.provide(VaultStoreLive(resolveDbPath(deps), masterKey)));
    return `added ${alias} (scope ${scope})\n`;
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
      return initProgram(deps);
    case "add": {
      const parsed = parseAddArgs(argv.slice(1));
      if (parsed === null) {
        return Effect.fail(new UsageError({ message: "add requires <alias> --scope <s>" }));
      }
      return addProgram(deps, io, parsed.alias, parsed.scope);
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

