import Database from "better-sqlite3";
import { Context, Effect, Layer } from "effect";
import { StorageError } from "./errors.js";
export class VaultStore extends Context.Tag("VaultStore")() {
}
function toStorageError(operation) {
    return (cause) => new StorageError({
        message: cause instanceof Error ? cause.message : String(cause),
        operation,
    });
}
// masterKey is part of the layer contract (the daemon supplies it from the
// keychain); ciphertext reaches the store already encrypted via crypto.ts.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function makeStore(dbPath, masterKey) {
    const db = new Database(dbPath);
    db.exec(`CREATE TABLE IF NOT EXISTS credentials (
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
     );`);
    const cols = db.prepare("PRAGMA table_info(credentials)").all();
    if (!cols.some((c) => c.name === "website")) {
        db.exec("ALTER TABLE credentials ADD COLUMN website TEXT NOT NULL DEFAULT ''");
    }
    const insertCredential = db.prepare("INSERT OR REPLACE INTO credentials (alias, ceiling, ciphertext, website) VALUES (?, ?, ?, ?)");
    const selectCredential = db.prepare("SELECT ceiling, ciphertext, website FROM credentials WHERE alias = ?");
    const updateCredentialStmt = db.prepare("UPDATE credentials SET ceiling = ?, ciphertext = ?, website = ? WHERE alias = ?");
    const deleteCredentialStmt = db.prepare("DELETE FROM credentials WHERE alias = ?");
    const selectCredentials = db.prepare("SELECT alias, ceiling, website FROM credentials ORDER BY alias ASC");
    const selectAliases = db.prepare("SELECT alias FROM credentials ORDER BY alias ASC");
    const insertAudit = db.prepare("INSERT INTO audit (ts, agent, alias, scope, stage, detail, model_id) VALUES (?, ?, ?, ?, ?, ?, ?)");
    const selectAudit = db.prepare("SELECT ts, agent, alias, scope, stage, detail, model_id FROM audit ORDER BY rowid ASC");
    return {
        addCredential: (alias, scopeCeiling, ciphertext, website) => Effect.try({
            try: () => {
                insertCredential.run(alias, scopeCeiling, ciphertext, website ?? "");
            },
            catch: toStorageError("addCredential"),
        }),
        updateCredential: (alias, scopeCeiling, ciphertext, website) => Effect.try({
            try: () => {
                updateCredentialStmt.run(scopeCeiling, ciphertext, website, alias);
            },
            catch: toStorageError("updateCredential"),
        }),
        deleteCredential: (alias) => Effect.try({
            try: () => {
                deleteCredentialStmt.run(alias);
            },
            catch: toStorageError("deleteCredential"),
        }),
        getCredential: (alias) => Effect.try({
            try: () => {
                const row = selectCredential.get(alias);
                return row === undefined
                    ? undefined
                    : { scopeCeiling: row.ceiling, ciphertext: row.ciphertext, website: row.website ?? "" };
            },
            catch: toStorageError("getCredential"),
        }),
        listCredentials: () => Effect.try({
            try: () => {
                const rows = selectCredentials.all();
                return rows.map((row) => ({ alias: row.alias, scopeCeiling: row.ceiling, website: row.website ?? "" }));
            },
            catch: toStorageError("listCredentials"),
        }),
        listCredentialAliases: () => Effect.try({
            try: () => {
                const rows = selectAliases.all();
                return rows.map((row) => row.alias);
            },
            catch: toStorageError("listCredentialAliases"),
        }),
        appendAudit: (e) => Effect.try({
            try: () => {
                insertAudit.run(e.ts, e.agentId, e.alias, e.scope, e.stage, e.detail, e.modelId ?? null);
            },
            catch: toStorageError("appendAudit"),
        }),
        listAudit: () => Effect.try({
            try: () => {
                const rows = selectAudit.all();
                return rows.map((row) => {
                    const base = {
                        ts: row.ts,
                        agentId: row.agent,
                        alias: row.alias,
                        scope: row.scope,
                        stage: row.stage,
                        detail: row.detail,
                    };
                    return row.model_id === null ? base : { ...base, modelId: row.model_id };
                });
            },
            catch: toStorageError("listAudit"),
        }),
    };
}
export function VaultStoreLive(dbPath, masterKey) {
    return Layer.sync(VaultStore, () => makeStore(dbPath, masterKey));
}
export function VaultStoreTest(masterKey) {
    return Layer.sync(VaultStore, () => makeStore(":memory:", masterKey));
}
