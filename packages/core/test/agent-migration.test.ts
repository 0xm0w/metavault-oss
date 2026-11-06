import { execFileSync } from "node:child_process";
import { statSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { Effect } from "effect";
import { describe, it, expect, vi } from "vitest";
import { VaultStore, VaultStoreScoped, hashAgentToken } from "../src/storage.js";

describe("agent token hash migration", () => {
  it("preserves existing token verification and revoked state without retaining raw tokens, idempotently", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mv-agents-")); const dbPath = join(dir, "vault.db");
    const token = "ov_agent_legacy_aabbccddeeff00112233445566778899";
    writeFileSync(join(dir,"metavault.key.json"), "synthetic wrapped-key snapshot");
    writeFileSync(join(dir,"metavault.token"), "synthetic-daemon-token");
    const db = new Database(dbPath);
    db.exec("CREATE TABLE agents (id TEXT PRIMARY KEY,name TEXT NOT NULL,token TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0)");
    db.prepare("INSERT INTO agents VALUES (?,?,?,?,?)").run("legacy", "Legacy", token, "2026-01-01", 1); db.close();
    try {
      for (let run = 0; run < 2; run++) await Effect.runPromise(Effect.gen(function* () {
        const store = yield* VaultStore;
        const agent = yield* store.getAgentByToken(token);
        expect(agent?.id).toBe("legacy"); expect(agent?.revoked).toBe(true); expect(agent?.token).toBe("");
        expect(yield* store.getAgentByToken("forged")).toBeUndefined();
        expect(JSON.stringify(yield* store.listAgents())).not.toContain(token);
      }).pipe(Effect.provide(VaultStoreScoped(dbPath))));
      const backups = readdirSync(dir).filter(name => name.includes("before-agent-hash"));
      expect(backups).toHaveLength(0);
      expect(readFileSync(join(dir, "metavault.token"), "utf8")).toBe("synthetic-daemon-token");
      const checked = new Database(dbPath);
      expect(checked.prepare("PRAGMA table_info(agents)").all()).not.toContainEqual(expect.objectContaining({ name: "token" }));
      expect(checked.prepare("SELECT token_hash FROM agents WHERE id='legacy'").get()).toEqual({token_hash: hashAgentToken(token)});
      checked.close();
      expect(readFileSync(dbPath).includes(Buffer.from(token))).toBe(false);
      for (const name of readdirSync(dir).filter(name=>!name.includes("before-agent-hash"))) {
        expect(readFileSync(join(dir,name)).includes(Buffer.from(token))).toBe(false);
      }
    } finally { rmSync(dir, {recursive:true,force:true}); }
  });
});

it("rolls back an interrupted table rebuild and can retry from intact legacy credentials", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mv-agent-failure-")); const dbPath = join(dir,"vault.db");
  const db = new Database(dbPath);
  db.pragma("journal_mode=WAL");
  db.exec("CREATE TABLE agents (id TEXT PRIMARY KEY,name TEXT NOT NULL,token TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0)");
  db.prepare("INSERT INTO agents VALUES (?,?,?,?,0)").run("legacy","Legacy","legacy-failure-token","2026-01-01"); db.close();
  // Preserve the native method and invoke it with the explicit database receiver.
  // eslint-disable-next-line @typescript-eslint/unbound-method
  const original = Database.prototype.exec;
  const fail = vi.spyOn(Database.prototype,"exec").mockImplementation(function(this: Database.Database, sql:string) {
    if (sql === "DROP TABLE agents_legacy") throw new Error("simulated interrupted rebuild");
    return original.call(this,sql);
  });
  try {
    const attempt = await Effect.runPromiseExit(Effect.gen(function* () { yield* VaultStore; }).pipe(Effect.provide(VaultStoreScoped(dbPath))));
    expect(attempt._tag).toBe("Failure"); fail.mockRestore();
    const inspect = new Database(dbPath);
    expect(inspect.prepare("SELECT token FROM agents WHERE id='legacy'").get()).toEqual({token:"legacy-failure-token"}); inspect.close();
    await Effect.runPromise(Effect.gen(function* () {const store=yield* VaultStore; expect((yield* store.getAgentByToken("legacy-failure-token"))?.id).toBe("legacy");}).pipe(Effect.provide(VaultStoreScoped(dbPath))));
  } finally {fail.mockRestore();rmSync(dir,{recursive:true,force:true});}
});

it("retries post-commit cleanup after a simulated interruption without losing token verification", async () => {
  const dir=mkdtempSync(join(tmpdir(),"mv-agent-cleanup-"));const dbPath=join(dir,"vault.db");
  const db=new Database(dbPath);db.exec("CREATE TABLE agents (id TEXT PRIMARY KEY,name TEXT NOT NULL,token TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0)");
  db.prepare("INSERT INTO agents VALUES (?,?,?,?,0)").run("legacy","Legacy","cleanup-test-token","2026-01-01");db.close();
  // eslint-disable-next-line @typescript-eslint/unbound-method
  const original=Database.prototype.exec;
  const fail=vi.spyOn(Database.prototype,"exec").mockImplementation(function(this:Database.Database,sql:string){if(sql === "PRAGMA secure_delete=ON; VACUUM")throw new Error("interrupted cleanup");return original.call(this,sql);});
  try {
    const attempt=await Effect.runPromiseExit(Effect.gen(function*(){yield* VaultStore;}).pipe(Effect.provide(VaultStoreScoped(dbPath))));expect(attempt._tag).toBe("Failure");fail.mockRestore();
    const inspect=new Database(dbPath);expect(inspect.prepare("SELECT cleanup_pending FROM local_migration_state WHERE name='agent-hash'").get()).toEqual({cleanup_pending:1});inspect.close();
    await Effect.runPromise(Effect.gen(function*(){const store=yield* VaultStore;expect((yield* store.getAgentByToken("cleanup-test-token"))?.id).toBe("legacy");}).pipe(Effect.provide(VaultStoreScoped(dbPath))));
    const complete=new Database(dbPath);expect(complete.prepare("SELECT cleanup_pending FROM local_migration_state WHERE name='agent-hash'").get()).toEqual({cleanup_pending:0});complete.close();
  } finally {fail.mockRestore();rmSync(dir,{recursive:true,force:true});}
});
