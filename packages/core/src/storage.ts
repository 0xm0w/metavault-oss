import Database from "better-sqlite3";
import { Context, Effect, Layer } from "effect";
import { StorageError } from "./errors.js";
import { DEFAULT_LOCAL_AUTH_RECORD, DEFAULT_WARDEN_SETTINGS, type LocalAuthRecord, type WardenSettings } from "./settings.js";
import type { AuditEvent, DecisionSource, Risk } from "./types.js";

export interface CredentialRecord {
  readonly scopeCeiling: string;
  readonly ciphertext: string;
  readonly website: string;
}

export interface CredentialMeta {
  readonly alias: string;
  readonly scopeCeiling: string;
  readonly website: string;
}

export interface VaultStoreService {
  readonly addCredential: (
    alias: string,
    scopeCeiling: string,
    ciphertext: string,
    website?: string,
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
}

export class VaultStore extends Context.Tag("VaultStore")<VaultStore, VaultStoreService>() {}

interface LocalAuthRow {
  readonly enabled: number;
  readonly pin_hash: string | null;
  readonly salt: string | null;
  readonly require_on_approval: number;
  readonly require_on_launch: number;
  readonly auto_lock_minutes: number;
}

interface CredentialRow {
  readonly ceiling: string;
  readonly ciphertext: string;
  readonly website: string | null;
}

interface CredentialMetaRow {
  readonly alias: string;
  readonly ceiling: string;
  readonly website: string | null;
}

interface AliasRow {
  readonly alias: string;
}

interface WardenSettingsRow {
  readonly provider: string;
  readonly model: string;
  readonly effort: string;
  readonly meta_api_base_url: string;
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
}

function toStorageError(operation: string) {
  return (cause: unknown): StorageError =>
    new StorageError({
      message: cause instanceof Error ? cause.message : String(cause),
      operation,
    });
}

// masterKey is part of the layer contract (the daemon supplies it from the
// keychain); ciphertext reaches the store already encrypted via crypto.ts.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function makeStore(dbPath: string, masterKey: Buffer): VaultStoreService {
  const db = new Database(dbPath);
  db.exec(
    `CREATE TABLE IF NOT EXISTS credentials (
       alias TEXT PRIMARY KEY,
       ceiling TEXT NOT NULL,
       ciphertext TEXT NOT NULL
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
        require_on_approval INTEGER NOT NULL DEFAULT 1,
        require_on_launch INTEGER NOT NULL DEFAULT 0,
        auto_lock_minutes INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS audit (
       ts TEXT NOT NULL,
       agent TEXT NOT NULL,
       alias TEXT NOT NULL,
       scope TEXT NOT NULL,
       stage TEXT NOT NULL,
       detail TEXT NOT NULL,
       model_id TEXT
     );`,
  );
  const cols = db.prepare("PRAGMA table_info(credentials)").all() as { name: string }[];
  if (!cols.some((c) => c.name === "website")) {
    db.exec("ALTER TABLE credentials ADD COLUMN website TEXT NOT NULL DEFAULT ''");
  }
  const auditCols = db.prepare("PRAGMA table_info(audit)").all() as { name: string }[];
  const auditColumnDefs: Record<string, string> = {
    request_id: "TEXT",
    risk: "TEXT",
    recommended_scope: "TEXT",
    decision_source: "TEXT",
    latency_ms: "REAL",
    explanation: "TEXT",
  };
  for (const [name, def] of Object.entries(auditColumnDefs)) {
    if (!auditCols.some((c) => c.name === name)) {
      db.exec(`ALTER TABLE audit ADD COLUMN ${name} ${def}`);
    }
  }
  const insertCredential = db.prepare(
    "INSERT OR REPLACE INTO credentials (alias, ceiling, ciphertext, website) VALUES (?, ?, ?, ?)",
  );
  const selectCredential = db.prepare(
    "SELECT ceiling, ciphertext, website FROM credentials WHERE alias = ?",
  );
  const updateCredentialStmt = db.prepare(
    "UPDATE credentials SET ceiling = ?, ciphertext = ?, website = ? WHERE alias = ?",
  );
  const deleteCredentialStmt = db.prepare("DELETE FROM credentials WHERE alias = ?");
  const selectCredentials = db.prepare(
    "SELECT alias, ceiling, website FROM credentials ORDER BY alias ASC",
  );
  const selectAliases = db.prepare(
    "SELECT alias FROM credentials ORDER BY alias ASC",
  );
  const insertAudit = db.prepare(
    "INSERT INTO audit (ts, agent, alias, scope, stage, detail, model_id, request_id, risk, recommended_scope, decision_source, latency_ms, explanation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
  );
  const upsertSettings = db.prepare(
    "INSERT INTO warden_settings (id, provider, model, effort, meta_api_base_url) VALUES (1, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET provider = excluded.provider, model = excluded.model, effort = excluded.effort, meta_api_base_url = excluded.meta_api_base_url",
  );
    const upsertLocalAuth = db.prepare(
    "INSERT INTO local_auth_settings (id, enabled, pin_hash, salt, require_on_approval, require_on_launch, auto_lock_minutes) VALUES (1, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled, pin_hash = excluded.pin_hash, salt = excluded.salt, require_on_approval = excluded.require_on_approval, require_on_launch = excluded.require_on_launch, auto_lock_minutes = excluded.auto_lock_minutes",
  );
  const selectLocalAuth = db.prepare(
    "SELECT enabled, pin_hash, salt, require_on_approval, require_on_launch, auto_lock_minutes FROM local_auth_settings WHERE id = 1",
  );
  const selectSettings = db.prepare(
    "SELECT provider, model, effort, meta_api_base_url FROM warden_settings WHERE id = 1",
  );
  const selectAudit = db.prepare(
    "SELECT ts, agent, alias, scope, stage, detail, model_id, request_id, risk, recommended_scope, decision_source, latency_ms, explanation FROM audit ORDER BY rowid ASC",
  );

  return {
    addCredential: (alias, scopeCeiling, ciphertext, website) =>
      Effect.try({
        try: () => {
          insertCredential.run(alias, scopeCeiling, ciphertext, website ?? "");
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
            : { scopeCeiling: row.ceiling, ciphertext: row.ciphertext, website: row.website ?? "" };
        },
        catch: toStorageError("getCredential"),
      }),
    listCredentials: () =>
      Effect.try({
        try: () => {
          const rows = selectCredentials.all() as CredentialMetaRow[];
          return rows.map((row) => ({ alias: row.alias, scopeCeiling: row.ceiling, website: row.website ?? "" }));
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
          insertAudit.run(e.ts, e.agentId, e.alias, e.scope, e.stage, e.detail, e.modelId ?? null, e.requestId ?? null, e.risk ?? null, e.recommendedScope ?? null, e.decisionSource ?? null, e.latencyMs ?? null, e.explanation ?? null);
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
            return event;
          });
        },
        catch: toStorageError("listAudit"),
      }),
    getWardenSettings: () =>
      Effect.try({
        try: () => {
          const row = selectSettings.get() as WardenSettingsRow | undefined;
          if (row === undefined) {
            return { ...DEFAULT_WARDEN_SETTINGS };
          }
          return {
            provider: row.provider as WardenSettings["provider"],
            model: row.model,
            effort: row.effort as WardenSettings["effort"],
            metaApiBaseUrl: row.meta_api_base_url,
          };
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
            requireOnApproval: Boolean(row.require_on_approval),
            requireOnLaunch: Boolean(row.require_on_launch),
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
            record.requireOnApproval ? 1 : 0,
            record.requireOnLaunch ? 1 : 0,
            record.autoLockMinutes,
          );
        },
        catch: toStorageError("setLocalAuthRecord"),
      }),
    setWardenSettings: (settings) =>
      Effect.try({
        try: () => {
          upsertSettings.run(settings.provider, settings.model, settings.effort, settings.metaApiBaseUrl);
        },
        catch: toStorageError("setWardenSettings"),
      }),
  };
}

export function VaultStoreLive(dbPath: string, masterKey: Buffer): Layer.Layer<VaultStore> {
  return Layer.sync(VaultStore, () => makeStore(dbPath, masterKey));
}

export function VaultStoreTest(masterKey: Buffer): Layer.Layer<VaultStore> {
  return Layer.sync(VaultStore, () => makeStore(":memory:", masterKey));
}
