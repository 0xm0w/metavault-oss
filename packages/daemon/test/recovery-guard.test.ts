import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it, vi } from "vitest";
vi.mock("../../core/src/keychain.js", () => ({ retrieveMasterKey: () => null }));
import { assertFirstRunDatabaseEmpty, resolveDaemonKeySession } from "../src/server.js";

const dirs: string[] = [];
function path(): string { const dir=mkdtempSync(join(tmpdir(),"mv-recovery-")); dirs.push(dir); return join(dir,"vault.db"); }
afterEach(()=>{vi.unstubAllEnvs();for(const dir of dirs.splice(0))rmSync(dir,{recursive:true,force:true});});
describe("missing-key first-run recovery guard",()=>{
  it("allows an absent database without creating it",()=>{const p=path(); expect(()=> { assertFirstRunDatabaseEmpty(p); }).not.toThrow();});
  it("allows initialized schema with no credentials after restart before setup",()=>{const p=path();const db=new Database(p);db.exec("CREATE TABLE credentials (alias TEXT, ciphertext TEXT)");db.close();expect(()=> { assertFirstRunDatabaseEmpty(p); }).not.toThrow();});
  it("refuses encrypted records without modifying the DB or creating a key",()=>{const p=path();const db=new Database(p);db.exec("CREATE TABLE credentials (alias TEXT, ciphertext TEXT); INSERT INTO credentials VALUES ('dummy','synthetic encrypted record')");db.close();const before=readFileSync(p);expect(()=> { assertFirstRunDatabaseEmpty(p); }).toThrow(/Vault recovery required/);expect(readFileSync(p).equals(before)).toBe(true);});
  it("resolver refuses first-run fallback for existing records when all keys are missing",()=>{
    vi.stubEnv("METAVAULT_MASTER_KEY", "");
    const p=path();const db=new Database(p);db.exec("CREATE TABLE credentials (alias TEXT, ciphertext TEXT); INSERT INTO credentials VALUES ('dummy','synthetic')");db.close();
    expect(()=>resolveDaemonKeySession(p,()=>{},true)).toThrow(/Vault recovery required/);
  });
  it("fails closed for unknown schema and corrupt database",()=>{const p=path();const db=new Database(p);db.exec("CREATE TABLE unexpected (id TEXT)");db.close();expect(()=> { assertFirstRunDatabaseEmpty(p); }).toThrow(/Vault recovery required/);writeFileSync(p,"not a database");const before=readFileSync(p);expect(()=> { assertFirstRunDatabaseEmpty(p); }).toThrow(/Vault recovery required/);expect(readFileSync(p).equals(before)).toBe(true);});
});
