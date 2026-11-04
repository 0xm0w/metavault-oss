import { mkdtempSync, readFileSync, rmSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it, vi } from "vitest";
vi.mock("../../core/src/keychain.js", () => ({ retrieveMasterKey: () => null }));
import { encryptSecret } from "../../core/src/crypto.js";
import { wrapMasterKey, writeWrappedKeyFile, wrappedKeyFilePath } from "../../core/src/keywrap.js";
import { assertDatabaseKeyMatches, resolveDaemonKeySession } from "../src/server.js";
const dirs: string[]=[];
const key=Buffer.alloc(32,7), other=Buffer.alloc(32,9), pass="synthetic restore password";
const fast={params:{N:2**12,r:8,p:1},allowWeakParams:true} as const;
function fixture(): string {const dir=mkdtempSync(join(tmpdir(),"mv-identity-"));dirs.push(dir);const p=join(dir,"vault.db");const db=new Database(p);db.exec("CREATE TABLE credentials (alias TEXT, ciphertext TEXT)");const put=db.prepare("INSERT INTO credentials VALUES (?,?)");put.run("first",encryptSecret(key,"synthetic-one"));put.run("second",encryptSecret(key,"synthetic-two"));db.close();return p;}
afterEach(()=>{vi.unstubAllEnvs();for(const d of dirs.splice(0))rmSync(d,{recursive:true,force:true});});
describe("database/key identity and matching restore",()=>{
 it("authenticates every record read-only and rejects mixed keys or damaged records",()=>{const p=fixture();const before=readFileSync(p);expect(()=> { assertDatabaseKeyMatches(p,key); }).not.toThrow();expect(()=> { assertDatabaseKeyMatches(p,other); }).toThrow(/recovery required/);expect(readFileSync(p).equals(before)).toBe(true);const db=new Database(p);db.prepare("UPDATE credentials SET ciphertext=? WHERE alias='second'").run(encryptSecret(other,"other"));db.close();const mixed=readFileSync(p);expect(()=> { assertDatabaseKeyMatches(p,key); }).toThrow(/recovery required/);expect(readFileSync(p).equals(mixed)).toBe(true);});
 it("keeps readable unrelated wrapped key locked without changing DB/key bytes",async()=>{const p=fixture();writeWrappedKeyFile(wrappedKeyFilePath(p),await wrapMasterKey(other,pass,fast));const dbBefore=readFileSync(p),keyBefore=readFileSync(wrappedKeyFilePath(p));const s=resolveDaemonKeySession(p,()=>{},true);expect(s.status().fingerprint).toBeNull();expect(await s.unlock(pass)).toBe("key-mismatch");expect(s.isLocked()).toBe(true);expect(s.status().fingerprint).toBeNull();expect(readFileSync(p).equals(dbBefore)).toBe(true);expect(readFileSync(wrappedKeyFilePath(p)).equals(keyBefore)).toBe(true);s.dispose();});
 it("matching stopped DB/key copies restore, retain identity and clear it on relock",async()=>{const p=fixture();writeWrappedKeyFile(wrappedKeyFilePath(p),await wrapMasterKey(key,pass,fast));const dir=mkdtempSync(join(tmpdir(),"mv-restored-"));dirs.push(dir);const restored=join(dir,"vault.db");copyFileSync(p,restored);copyFileSync(wrappedKeyFilePath(p),wrappedKeyFilePath(restored));const s=resolveDaemonKeySession(restored,()=>{},true);expect(await s.unlock(pass)).toBe("unlocked");const fingerprint=createHash("sha256").update(key).digest("hex").slice(0,24);expect(s.status().fingerprint).toBe(fingerprint);expect(s.key().equals(key)).toBe(true);s.lock();expect(s.status().fingerprint).toBeNull();expect(await s.unlock(pass)).toBe("unlocked");expect(s.status().fingerprint).toBe(fingerprint);s.dispose();});
 it("refuses unrelated legacy environment key before serving and leaves original buffer alone",()=>{const p=fixture();vi.stubEnv("METAVAULT_MASTER_KEY",other.toString("base64"));vi.stubEnv("METAVAULT_ALLOW_ENV_MASTER_KEY","1");expect(()=>resolveDaemonKeySession(p,()=>{},true)).toThrow(/recovery required/);expect(other.equals(Buffer.alloc(32,9))).toBe(true);});
 it("fails closed for unknown DB schema",()=>{const p=fixture();const db=new Database(p);db.exec("DROP TABLE credentials");db.close();expect(()=> { assertDatabaseKeyMatches(p,key); }).toThrow(/recovery required/);});
});
