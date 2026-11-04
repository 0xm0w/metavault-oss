import { createHash, timingSafeEqual } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync } from "node:fs";
import Database from "better-sqlite3";
import { Context, Effect, Layer } from "effect";
import { StorageError } from "./errors.js";
import { DEFAULT_AGENT_SECURITY_SETTINGS, DEFAULT_LOCAL_AUTH_RECORD, DEFAULT_WARDEN_SETTINGS, LEGACY_LOCAL_PROVIDERS, SUGGESTED_LOCAL_BASE_URL, defaultWardenSettings, normalizeWardenProvider, type AgentSecuritySettings, type LocalAuthRecord, type WardenSettings } from "./settings.js";
import type { AuditEvent, DecisionSource, Risk } from "./types.js";
import { CARD_KIND, SECRET_KIND, type CredentialKind } from "./card.js";

// kind is "secret" (API key / token) or "card" (payment card). publicMeta
// is non-secret JSON kept in clear (for cards: brand + last 4 only).
export interface CredentialRecord {
  readonly scopeCeiling: string;
  readonly ciphertext: string;
  readonly website: string;
  readonly kind: CredentialKind;
  readonly publicMeta: string;
}

export interface CredentialMeta {
  readonly alias: string;
  readonly scopeCeiling: string;
  readonly website: string;
  readonly kind?: CredentialKind;
  readonly publicMeta?: string;
}

export interface AgentRecord {
  readonly id: string;
  readonly name: string;
  readonly token: string; // Empty on stored/listed records. Raw token is returned only at creation/rotation.
  readonly tokenPrefix?: string;
  readonly createdAt: string;
  readonly revoked: boolean;
}

export interface VaultStoreService {
  readonly addCredential: (
    alias: string,
    scopeCeiling: string,
    ciphertext: string,
    website?: string,
    kind?: CredentialKind,
    publicMeta?: string,
  ) => Effect.Effect<void, StorageError>;
  readonly updateCredential: (
    alias: string,
    scopeCeiling: string,
    ciphertext: string,
    website: string,
  ) => Effect.Effect<void, StorageError>;
  readonly deleteCredential: (alias: string) => Effect.Effect<void, StorageError>;
  readonly listCredentials: () => Effect.Effect<CredentialMeta[], StorageError>;
  readonly getCredential: (
    alias: string,
  ) => Effect.Effect<CredentialRecord | undefined, StorageError>;
  readonly listCredentialAliases: () => Effect.Effect<string[], StorageError>;
  readonly appendAudit: (e: AuditEvent) => Effect.Effect<void, StorageError>;
  readonly listAudit: () => Effect.Effect<AuditEvent[], StorageError>;
  readonly getWardenSettings: () => Effect.Effect<WardenSettings, StorageError>;
  readonly setWardenSettings: (settings: WardenSettings) => Effect.Effect<void, StorageError>;
  readonly getLocalAuthRecord: () => Effect.Effect<LocalAuthRecord, StorageError>;
  readonly setLocalAuthRecord: (record: LocalAuthRecord) => Effect.Effect<void, StorageError>;
  readonly getAgentSecuritySettings: () => Effect.Effect<AgentSecuritySettings, StorageError>;
  readonly setAgentSecuritySettings: (settings: AgentSecuritySettings) => Effect.Effect<void, StorageError>;
  readonly listAgents: () => Effect.Effect<AgentRecord[], StorageError>;
  readonly getAgent: (id: string) => Effect.Effect<AgentRecord | undefined, StorageError>;
  readonly getAgentByToken: (token: string) => Effect.Effect<AgentRecord | undefined, StorageError>;
  readonly addAgent: (id: string, name: string, token: string) => Effect.Effect<void, StorageError>;
  readonly revokeAgent: (id: string) => Effect.Effect<void, StorageError>;
}

export class VaultStore extends Context.Tag("VaultStore")<VaultStore, VaultStoreService>() {}

interface LocalAuthRow {
  readonly enabled: number;
  readonly pin_hash: string | null;
  readonly salt: string | null;
  readonly biometric_enabled: number;
  readonly require_on_approval: number;
  readonly require_on_launch: number;
  readonly require_on_settings: number;
  readonly auto_lock_minutes: number;
}

interface CredentialRow {
  readonly ceiling: string;
  readonly ciphertext: string;
  readonly website: string | null;
  readonly kind: string | null;
  readonly public_meta: string | null;
}

interface CredentialMetaRow {
  readonly alias: string;
  readonly ceiling: string;
  readonly website: string | null;
  readonly kind: string | null;
  readonly public_meta: string | null;
}

function toKind(raw: string | null): CredentialKind {
  return raw === CARD_KIND ? CARD_KIND : SECRET_KIND;
}

interface AliasRow {
  readonly alias: string;
}

export interface WardenSettingsRow {
  readonly provider: string;
  readonly model: string;
  readonly effort: string;
  readonly meta_api_base_url: string;
  readonly local_base_url: string;
  readonly local_api: string;
  readonly local_model: string;
}

// Rows written by earlier builds use provider "ollama" or "builtin" with the
// local tag in `model` and no local_* columns. They migrate to the
// bring-your-own endpoint at the Ollama address those builds always used.
export function wardenSettingsFromRow(row: WardenSettingsRow): WardenSettings {
  const legacyLocal = (LEGACY_LOCAL_PROVIDERS as readonly string[]).includes(row.provider);
  const provider = normalizeWardenProvider(row.provider) ?? DEFAULT_WARDEN_SETTINGS.provider;
  const localApi: WardenSettings["localApi"] = row.local_api === "openai" ? "openai" : "ollama";
  if (legacyLocal && row.local_model === "") {
    return {
      provider,
      model: DEFAULT_WARDEN_SETTINGS.model,
      effort: row.effort as WardenSettings["effort"],
      metaApiBaseUrl: row.meta_api_base_url,
      localBaseUrl: row.local_base_url !== "" ? row.local_base_url : SUGGESTED_LOCAL_BASE_URL.ollama,
      localApi,
      localModel: row.model,
    };
  }
  return {
    provider,
    model: row.model,
    effort: row.effort as WardenSettings["effort"],
    metaApiBaseUrl: row.meta_api_base_url,
    localBaseUrl: row.local_base_url,
    localApi,
    localModel: row.local_model,
  };
}

interface AuditRow {
  readonly ts: string;
  readonly agent: string;
  readonly alias: string;
  readonly scope: string;
  readonly stage: string;
  readonly detail: string;
  readonly model_id: string | null;
  readonly request_id: string | null;
  readonly risk: string | null;
  readonly recommended_scope: string | null;
  readonly decision_source: string | null;
  readonly latency_ms: number | null;
  readonly explanation: string | null;
  readonly verified: number | null;
  readonly client_pid: number | null;
  readonly client_process: string | null;
}

interface AgentRow {
  readonly id: string;
  readonly name: string;
  readonly token: string; // Legacy migration only.
  readonly token_hash: string | null;
  readonly token_prefix: string;
  readonly created_at: string;
  readonly revoked: number;
}

export function hashAgentToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function toStorageError(operation: string) {
  return (cause: unknown): StorageError =>
    new StorageError({
      message: cause instanceof Error ? cause.message : String(cause),
      operation,
    });
}

// The store never sees the master key: ciphertext reaches it already
// encrypted via crypto.ts (see KeySession in key-session.ts).
function makeStore(db: Database.Database): VaultStoreService {
  db.exec(
    `CREATE TABLE IF NOT EXISTS credentials (
       alias TEXT PRIMARY KEY,
       ceiling TEXT NOT NULL,
       ciphertext TEXT NOT NULL
     );
     CREATE TABLE IF NOT EXISTS agent_security_settings (
       id INTEGER PRIMARY KEY CHECK (id = 1),
       strict_mode INTEGER NOT NULL DEFAULT 0,
       verify_caller_process INTEGER NOT NULL DEFAULT 0
     );
     CREATE TABLE IF NOT EXISTS warden_settings (
       id INTEGER PRIMARY KEY CHECK (id = 1),
       provider TEXT NOT NULL,
       model TEXT NOT NULL,
       effort TEXT NOT NULL,
       meta_api_base_url TEXT NOT NULL
     );
     CREATE TABLE IF NOT EXISTS local_auth_settings (
        id INTEGER PRIMARY KEY,
        enabled INTEGER NOT NULL DEFAULT 0,
        pin_hash TEXT,
        salt TEXT,
        biometric_enabled INTEGER NOT NULL DEFAULT 0,
        require_on_approval INTEGER NOT NULL DEFAULT 0,
        require_on_launch INTEGER NOT NULL DEFAULT 0,
        require_on_settings INTEGER NOT NULL DEFAULT 0,
        auto_lock_minutes INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS audit (
       ts TEXT NOT NULL,
       agent TEXT NOT NULL,
       alias TEXT NOT NULL,
       scope TEXT NOT NULL,
       stage TEXT NOT NULL,
       detail TEXT NOT NULL,
       model_id TEXT,
       verified INTEGER
     );
     CREATE TABLE IF NOT EXISTS agents (
       id TEXT PRIMARY KEY,
       name TEXT NOT NULL,
       token TEXT NOT NULL UNIQUE,
       created_at TEXT NOT NULL,
       revoked INTEGER NOT NULL DEFAULT 0
     );`,
  );
  const cols = db.prepare("PRAGMA table_info(credentials)").all() as { name: string }[];
  if (!cols.some((c) => c.name === "website")) {
    db.exec("ALTER TABLE credentials ADD COLUMN website TEXT NOT NULL DEFAULT ''");
  }
  if (!cols.some((c) => c.name === "kind")) {
    db.exec("ALTER TABLE credentials ADD COLUMN kind TEXT NOT NULL DEFAULT 'secret'");
  }
  if (!cols.some((c) => c.name === "public_meta")) {
    db.exec("ALTER TABLE credentials ADD COLUMN public_meta TEXT NOT NULL DEFAULT ''");
  }
  const auditCols = db.prepare("PRAGMA table_info(audit)").all() as { name: string }[];
  const auditColumnDefs: Record<string, string> = {
    request_id: "TEXT",
    risk: "TEXT",
    recommended_scope: "TEXT",
    decision_source: "TEXT",
    latency_ms: "REAL",
    explanation: "TEXT",
    verified: "INTEGER",
    client_pid: "INTEGER",
    client_process: "TEXT",
  };
  for (const [name, def] of Object.entries(auditColumnDefs)) {
    if (!auditCols.some((c) => c.name === name)) {
      db.exec(`ALTER TABLE audit ADD COLUMN ${name} ${def}`);
    }
  }
  const insertCredential = db.prepare(
    "INSERT OR REPLACE INTO credentials (alias, ceiling, ciphertext, website, kind, public_meta) VALUES (?, ?, ?, ?, ?, ?)",
  );
  const selectCredential = db.prepare(
    "SELECT ceiling, ciphertext, website, kind, public_meta FROM credentials WHERE alias = ?",
  );
  const updateCredentialStmt = db.prepare(
    "UPDATE credentials SET ceiling = ?, ciphertext = ?, website = ? WHERE alias = ?",
  );
  const deleteCredentialStmt = db.prepare("DELETE FROM credentials WHERE alias = ?");
  const selectCredentials = db.prepare(
    "SELECT alias, ceiling, website, kind, public_meta FROM credentials ORDER BY alias ASC",
  );
  const selectAliases = db.prepare(
    "SELECT alias FROM credentials ORDER BY alias ASC",
  );
  const insertAudit = db.prepare(
    "INSERT INTO audit (ts, agent, alias, scope, stage, detail, model_id, request_id, risk, recommended_scope, decision_source, latency_ms, explanation, verified, client_pid, client_process) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
  );
  // Rebuild the legacy token table transactionally. No raw bearer is retained
  // in the logical database. Existing IDE tokens keep working until rotated.
  db.exec("CREATE TABLE IF NOT EXISTS local_migration_state (name TEXT PRIMARY KEY, cleanup_pending INTEGER NOT NULL)");
  const agentCols = db.prepare("PRAGMA table_info(agents)").all() as { name: string }[];
  if (agentCols.some((c) => c.name === "token")) {
    // A consistent SQLite snapshot precedes any destructive schema change.
    // Local backup retains the old credential data and must stay private.
    if (db.name !== ":memory:") {
      const backupDir = `${db.name}.before-agent-hash-${Date.now().toString()}-${Math.random().toString(16).slice(2)}`;
      mkdirSync(backupDir, {mode:0o700});
      if (process.platform === "win32") {
        const identity = execFileSync("whoami.exe", [], {encoding:"utf8"}).trim();
        // Restrict inheritance BEFORE writing any raw credential data.
        execFileSync("icacls.exe", [backupDir, "/inheritance:r", "/grant:r", `${identity}:(OI)(CI)(F)`, "SYSTEM:(OI)(CI)(F)"], {stdio:"pipe"});
      }
      const backup = `${backupDir}/vault.db.bak`;
      db.prepare("VACUUM INTO ?").run(backup);
      if (process.platform !== "win32") chmodSync(backup, 0o600);
    }
    db.pragma("wal_checkpoint(TRUNCATE)");
    db.exec("PRAGMA secure_delete=ON");
    db.transaction(() => {
      const rows = db.prepare("SELECT * FROM agents").all() as AgentRow[];
      db.exec("ALTER TABLE agents RENAME TO agents_legacy; CREATE TABLE agents (id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT UNIQUE, token_prefix TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)");
      const put = db.prepare("INSERT INTO agents VALUES (?, ?, ?, ?, ?, ?)");
      for (const row of rows) put.run(row.id, row.name, hashAgentToken(row.token), row.token.slice(0, 16), row.created_at, row.revoked);
      db.exec("DROP TABLE agents_legacy");
      db.exec("INSERT OR REPLACE INTO local_migration_state VALUES ('agent-hash',1)");
    })();
  }
  const pendingCleanup = db.prepare("SELECT cleanup_pending FROM local_migration_state WHERE name='agent-hash'").get() as {cleanup_pending:number} | undefined;
  if (pendingCleanup?.cleanup_pending === 1) {
    // A crash after the transaction must retry physical cleanup on startup.
    db.exec("PRAGMA secure_delete=ON; VACUUM");
    const result = db.pragma("wal_checkpoint(TRUNCATE)") as {busy:number}[];
    if (result.some(row=>row.busy !== 0)) throw new Error("agent migration cleanup is busy; close other vault processes and retry");
    db.exec("UPDATE local_migration_state SET cleanup_pending=0 WHERE name='agent-hash'");
  }
  const seedAgent = db.prepare("INSERT OR IGNORE INTO agents (id,name,token_hash,token_prefix,created_at,revoked) VALUES (?,?,NULL,'',?,1)");
  for (const [id, name] of [["cursor", "Cursor"], ["claude-code", "Claude Code"], ["vscode", "VS Code"], ["codex", "Codex"], ["opencode", "OpenCode"]]) seedAgent.run(id, name, new Date().toISOString());
  const selectAllAgents = db.prepare("SELECT * FROM agents ORDER BY id ASC");
  const selectAgentById = db.prepare("SELECT * FROM agents WHERE id = ?");
  const selectAgentByToken = db.prepare("SELECT * FROM agents WHERE token_hash = ?");
  const insertAgent = db.prepare(
    "INSERT INTO agents (id,name,token_hash,token_prefix,created_at,revoked) VALUES (?,?,?,?,?,0) ON CONFLICT(id) DO UPDATE SET name=excluded.name,token_hash=excluded.token_hash,token_prefix=excluded.token_prefix,revoked=0",
  );
  const revokeAgentStmt = db.prepare(
    "UPDATE agents SET revoked = 1 WHERE id = ?",
  );

  const upsertSecuritySettings = db.prepare(
    "INSERT INTO agent_security_settings (id, strict_mode, verify_caller_process) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET strict_mode = excluded.strict_mode, verify_caller_process = excluded.verify_caller_process"
  );
  const selectSecuritySettings = db.prepare(
    "SELECT strict_mode, verify_caller_process FROM agent_security_settings WHERE id = 1"
  );
  for (const [name, def] of [
    ["local_base_url", "TEXT NOT NULL DEFAULT ''"],
    ["local_api", "TEXT NOT NULL DEFAULT 'ollama'"],
    ["local_model", "TEXT NOT NULL DEFAULT ''"],
  ] as const) {
    try {
      db.exec(`ALTER TABLE warden_settings ADD COLUMN ${name} ${def}`);
    } catch {
      // Column already exists
    }
  }
  const upsertSettings = db.prepare(
    "INSERT INTO warden_settings (id, provider, model, effort, meta_api_base_url, local_base_url, local_api, local_model) VALUES (1, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET provider = excluded.provider, model = excluded.model, effort = excluded.effort, meta_api_base_url = excluded.meta_api_base_url, local_base_url = excluded.local_base_url, local_api = excluded.local_api, local_model = excluded.local_model",
  );
  try {
    db.exec("ALTER TABLE local_auth_settings ADD COLUMN biometric_enabled INTEGER NOT NULL DEFAULT 0");
  } catch {
    // Column already exists
  }
  try {
    db.exec("ALTER TABLE local_auth_settings ADD COLUMN require_on_settings INTEGER NOT NULL DEFAULT 0");
  } catch {
    // Column already exists
  }
  const upsertLocalAuth = db.prepare(
    "INSERT INTO local_auth_settings (id, enabled, pin_hash, salt, biometric_enabled, require_on_approval, require_on_launch, require_on_settings, auto_lock_minutes) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled, pin_hash = excluded.pin_hash, salt = excluded.salt, biometric_enabled = excluded.biometric_enabled, require_on_approval = excluded.require_on_approval, require_on_launch = excluded.require_on_launch, require_on_settings = excluded.require_on_settings, auto_lock_minutes = excluded.auto_lock_minutes",
  );
  const selectLocalAuth = db.prepare(
    "SELECT enabled, pin_hash, salt, biometric_enabled, require_on_approval, require_on_launch, require_on_settings, auto_lock_minutes FROM local_auth_settings WHERE id = 1",
  );
  const selectSettings = db.prepare(
    "SELECT provider, model, effort, meta_api_base_url, local_base_url, local_api, local_model FROM warden_settings WHERE id = 1",
  );
  const selectAudit = db.prepare(
    "SELECT ts, agent, alias, scope, stage, detail, model_id, request_id, risk, recommended_scope, decision_source, latency_ms, explanation, verified, client_pid, client_process FROM audit ORDER BY rowid ASC",
  );

  return {
    addCredential: (alias, scopeCeiling, ciphertext, website, kind, publicMeta) =>
      Effect.try({
        try: () => {
          insertCredential.run(alias, scopeCeiling, ciphertext, website ?? "", kind ?? SECRET_KIND, publicMeta ?? "");
        },
        catch: toStorageError("addCredential"),
      }),
    updateCredential: (alias, scopeCeiling, ciphertext, website) =>
      Effect.try({
        try: () => {
          updateCredentialStmt.run(scopeCeiling, ciphertext, website, alias);
        },
        catch: toStorageError("updateCredential"),
      }),
    deleteCredential: (alias) =>
      Effect.try({
        try: () => {
          deleteCredentialStmt.run(alias);
        },
        catch: toStorageError("deleteCredential"),
      }),
    getCredential: (alias) =>
      Effect.try({
        try: () => {
          const row = selectCredential.get(alias) as CredentialRow | undefined;
          return row === undefined
            ? undefined
            : { scopeCeiling: row.ceiling, ciphertext: row.ciphertext, website: row.website ?? "", kind: toKind(row.kind), publicMeta: row.public_meta ?? "" };
        },
        catch: toStorageError("getCredential"),
      }),
    listCredentials: () =>
      Effect.try({
        try: () => {
          const rows = selectCredentials.all() as CredentialMetaRow[];
          return rows.map((row) => ({ alias: row.alias, scopeCeiling: row.ceiling, website: row.website ?? "", kind: toKind(row.kind), publicMeta: row.public_meta ?? "" }));
        },
        catch: toStorageError("listCredentials"),
      }),
    listCredentialAliases: () =>
      Effect.try({
        try: () => {
          const rows = selectAliases.all() as AliasRow[];
          return rows.map((row) => row.alias);
        },
        catch: toStorageError("listCredentialAliases"),
      }),
    appendAudit: (e) =>
      Effect.try({
        try: () => {
          insertAudit.run(e.ts, e.agentId, e.alias, e.scope, e.stage, e.detail, e.modelId ?? null, e.requestId ?? null, e.risk ?? null, e.recommendedScope ?? null, e.decisionSource ?? null, e.latencyMs ?? null, e.explanation ?? null, (e.verified === undefined ? null : e.verified ? 1 : 0), e.clientPid ?? null, e.clientProcess ?? null);
        },
        catch: toStorageError("appendAudit"),
      }),
    listAudit: () =>
      Effect.try({
        try: () => {
          const rows = selectAudit.all() as AuditRow[];
          return rows.map((row): AuditEvent => {
            const base: AuditEvent = {
              ts: row.ts,
              agentId: row.agent,
              alias: row.alias,
              scope: row.scope,
              stage: row.stage as AuditEvent["stage"],
              detail: row.detail,
            };
            let event: AuditEvent = base;
            if (row.model_id !== null) event = { ...event, modelId: row.model_id };
            if (row.request_id !== null) event = { ...event, requestId: row.request_id };
            if (row.risk !== null) event = { ...event, risk: row.risk as Risk };
            if (row.recommended_scope !== null) event = { ...event, recommendedScope: row.recommended_scope };
            if (row.decision_source !== null) event = { ...event, decisionSource: row.decision_source as DecisionSource };
            if (row.latency_ms !== null) event = { ...event, latencyMs: row.latency_ms };
            if (row.explanation !== null) event = { ...event, explanation: row.explanation };
            if (row.verified !== null) event = { ...event, verified: row.verified === 1 };
            if (row.client_pid !== null) event = { ...event, clientPid: row.client_pid };
            if (row.client_process !== null) event = { ...event, clientProcess: row.client_process };
            return event;
          });
        },
        catch: toStorageError("listAudit"),
      }),

    getAgentSecuritySettings: () =>
      Effect.try({
        try: () => {
          const row = selectSecuritySettings.get() as { strict_mode: number; verify_caller_process: number } | undefined;
          if (row === undefined) return { ...DEFAULT_AGENT_SECURITY_SETTINGS };
          return {
            strictMode: Boolean(row.strict_mode),
            verifyCallerProcess: Boolean(row.verify_caller_process),
          };
        },
        catch: toStorageError("getAgentSecuritySettings"),
      }),
    setAgentSecuritySettings: (settings) =>
      Effect.try({
        try: () => {
          upsertSecuritySettings.run(settings.strictMode ? 1 : 0, settings.verifyCallerProcess ? 1 : 0);
        },
        catch: toStorageError("setAgentSecuritySettings"),
      }),
    getWardenSettings: () =>
      Effect.try({
        try: () => {
          const row = selectSettings.get() as WardenSettingsRow | undefined;
          if (row === undefined) {
            return defaultWardenSettings();
          }
          return wardenSettingsFromRow(row);
        },
        catch: toStorageError("getWardenSettings"),
      }),
        getLocalAuthRecord: () =>
      Effect.try({
        try: () => {
          const row = selectLocalAuth.get() as LocalAuthRow | undefined;
          if (row === undefined) {
            return { ...DEFAULT_LOCAL_AUTH_RECORD };
          }
          return {
            enabled: Boolean(row.enabled),
            pinHash: row.pin_hash,
            salt: row.salt,
            biometricEnabled: Boolean(row.biometric_enabled),
            requireOnApproval: Boolean(row.require_on_approval),
            requireOnLaunch: Boolean(row.require_on_launch),
            requireOnSettings: Boolean(row.require_on_settings),
            autoLockMinutes: row.auto_lock_minutes,
          };
        },
        catch: toStorageError("getLocalAuthRecord"),
      }),
    setLocalAuthRecord: (record) =>
      Effect.try({
        try: () => {
          upsertLocalAuth.run(
            record.enabled ? 1 : 0,
            record.pinHash,
            record.salt,
            record.biometricEnabled ? 1 : 0,
            record.requireOnApproval ? 1 : 0,
            record.requireOnLaunch ? 1 : 0,
            record.requireOnSettings ? 1 : 0,
            record.autoLockMinutes,
          );
        },
        catch: toStorageError("setLocalAuthRecord"),
      }),
    setWardenSettings: (settings) =>
      Effect.try({
        try: () => {
          upsertSettings.run(
            settings.provider,
            settings.model,
            settings.effort,
            settings.metaApiBaseUrl,
            settings.localBaseUrl,
            settings.localApi,
            settings.localModel,
          );
        },
        catch: toStorageError("setWardenSettings"),
      }),
    listAgents: () =>
      Effect.try({
        try: () => {
          const rows = selectAllAgents.all() as AgentRow[];
          return rows.map((r): AgentRecord => ({
            id: r.id,
            name: r.name,
            token: "",
            tokenPrefix: r.token_prefix,
            createdAt: r.created_at,
            revoked: r.revoked === 1,
          }));
        },
        catch: toStorageError("listAgents"),
      }),
    getAgent: (id) =>
      Effect.try({
        try: () => {
          const row = selectAgentById.get(id) as AgentRow | undefined;
          return row === undefined
            ? undefined
            : {
                id: row.id,
                name: row.name,
                token: "",
                tokenPrefix: row.token_prefix,
                createdAt: row.created_at,
                revoked: row.revoked === 1,
              };
        },
        catch: toStorageError("getAgent"),
      }),
    getAgentByToken: (token) =>
      Effect.try({
        try: () => {
          const row = selectAgentByToken.get(hashAgentToken(token)) as AgentRow | undefined;
          return row === undefined || row.token_hash === null || !timingSafeEqual(Buffer.from(row.token_hash), Buffer.from(hashAgentToken(token)))
            ? undefined
            : { id: row.id, name: row.name, token: "", tokenPrefix: row.token_prefix, createdAt: row.created_at, revoked: row.revoked === 1 };
        },
        catch: toStorageError("getAgentByToken"),
      }),
    addAgent: (id, name, token) =>
      Effect.try({
        try: () => {
          insertAgent.run(id, name, hashAgentToken(token), token.slice(0, 16), new Date().toISOString());
        },
        catch: toStorageError("addAgent"),
      }),
    revokeAgent: (id) =>
      Effect.try({
        try: () => {
          revokeAgentStmt.run(id);
        },
        catch: toStorageError("revokeAgent"),
      }),
  };
}

// Closes the database when the layer's scope ends. For one-shot callers
// (the CLI): leaving vault.db open makes Windows refuse to delete or move
// it. Long-lived callers that keep the service past the scope use
// VaultStoreLive, which stays open for the life of the process.
export const VaultStoreScoped = (dbPath: string): Layer.Layer<VaultStore> =>
  Layer.scoped(
    VaultStore,
    Effect.map(
      Effect.acquireRelease(
        Effect.sync(() => new Database(dbPath)),
        (db) => Effect.sync(() => db.close()),
      ),
      makeStore,
    ),
  );

// The optional key argument is accepted for older call sites and ignored.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function VaultStoreLive(dbPath: string, _legacyMasterKey?: Buffer): Layer.Layer<VaultStore> {
  return Layer.sync(VaultStore, () => makeStore(new Database(dbPath)));
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function VaultStoreTest(_legacyMasterKey?: Buffer): Layer.Layer<VaultStore> {
  return Layer.sync(VaultStore, () => makeStore(new Database(":memory:")));
}
