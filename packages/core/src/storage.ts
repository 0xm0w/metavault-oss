import Database from "better-sqlite3";
import { Context, Effect, Layer } from "effect";
import { StorageError } from "./errors.js";
import type { AuditEvent } from "./types.js";

export interface CredentialRecord {
  readonly scopeCeiling: string;
  readonly ciphertext: string;
}

export interface VaultStoreService {
  readonly addCredential: (
    alias: string,
    scopeCeiling: string,
    ciphertext: string,
  ) => Effect.Effect<void, StorageError>;
  readonly getCredential: (
    alias: string,
  ) => Effect.Effect<CredentialRecord | undefined, StorageError>;
  readonly listCredentialAliases: () => Effect.Effect<string[], StorageError>;
  readonly appendAudit: (e: AuditEvent) => Effect.Effect<void, StorageError>;
  readonly listAudit: () => Effect.Effect<AuditEvent[], StorageError>;
}

export class VaultStore extends Context.Tag("VaultStore")<VaultStore, VaultStoreService>() {}

interface CredentialRow {
  readonly ceiling: string;
  readonly ciphertext: string;
}

interface AliasRow {
  readonly alias: string;
}

interface AuditRow {
  readonly ts: string;
  readonly agent: string;
  readonly alias: string;
  readonly scope: string;
  readonly stage: string;
  readonly detail: string;
  readonly model_id: string | null;
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
  const insertCredential = db.prepare(
    "INSERT OR REPLACE INTO credentials (alias, ceiling, ciphertext) VALUES (?, ?, ?)",
  );
  const selectCredential = db.prepare(
    "SELECT ceiling, ciphertext FROM credentials WHERE alias = ?",
  );
  const selectAliases = db.prepare(
    "SELECT alias FROM credentials ORDER BY alias ASC",
  );
  const insertAudit = db.prepare(
    "INSERT INTO audit (ts, agent, alias, scope, stage, detail, model_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
  );
  const selectAudit = db.prepare(
    "SELECT ts, agent, alias, scope, stage, detail, model_id FROM audit ORDER BY rowid ASC",
  );

  return {
    addCredential: (alias, scopeCeiling, ciphertext) =>
      Effect.try({
        try: () => {
          insertCredential.run(alias, scopeCeiling, ciphertext);
        },
        catch: toStorageError("addCredential"),
      }),
    getCredential: (alias) =>
      Effect.try({
        try: () => {
          const row = selectCredential.get(alias) as CredentialRow | undefined;
          return row === undefined
            ? undefined
            : { scopeCeiling: row.ceiling, ciphertext: row.ciphertext };
        },
        catch: toStorageError("getCredential"),
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
          insertAudit.run(e.ts, e.agentId, e.alias, e.scope, e.stage, e.detail, e.modelId ?? null);
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
            return row.model_id === null ? base : { ...base, modelId: row.model_id };
          });
        },
        catch: toStorageError("listAudit"),
      }),
  };
}

export function VaultStoreLive(dbPath: string, masterKey: Buffer): Layer.Layer<VaultStore> {
  return Layer.sync(VaultStore, () => makeStore(dbPath, masterKey));
}

export function VaultStoreTest(masterKey: Buffer): Layer.Layer<VaultStore> {
  return Layer.sync(VaultStore, () => makeStore(":memory:", masterKey));
}
