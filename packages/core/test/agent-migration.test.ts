import { execFileSync } from "node:child_process";
import { statSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { Effect } from "effect";
import { describe, it, expect } from "vitest";
import { VaultStore, VaultStoreScoped, hashAgentToken } from "../src/storage.js";

describe("agent token hash migration", () => {
  it("preserves existing token verification and revoked state without retaining raw tokens, idempotently", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mv-agents-")); const dbPath = join(dir, "vault.db");
    const token = "ov_agent_legacy_aabbccddeeff00112233445566778899";
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
      expect(backups).toHaveLength(1);
      const backupDirectory = join(dir, backups[0] ?? "");
      const backupPath = join(backupDirectory,"vault.db.bak");
      if (process.platform === "win32") {
        const acl = execFileSync("icacls.exe", [backupPath], {encoding:"utf8"});
        expect(acl).not.toMatch(/BUILTIN\\Users|Everyone|Authenticated Users/i);
        const directoryAcl = execFileSync("icacls.exe", [backupDirectory], {encoding:"utf8"});
        expect(directoryAcl).not.toMatch(/BUILTIN\\Users|Everyone|Authenticated Users|\(I\)/i);
        expect(acl).toMatch(/SYSTEM/);
      } else { expect(statSync(backupPath).mode & 0o777).toBe(0o600); expect(statSync(backupDirectory).mode & 0o777).toBe(0o700); }
      const backup = new Database(backupPath);
      expect(backup.prepare("SELECT token FROM agents WHERE id='legacy'").get()).toEqual({token}); backup.close();
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
