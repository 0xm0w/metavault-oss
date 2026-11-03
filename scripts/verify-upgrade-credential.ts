// Synthetic CI fixture only. Never prints key, password or credential contents.
import { readFileSync } from "node:fs";
import Database from "better-sqlite3";
import { unwrapMasterKey } from "../packages/core/src/keywrap.js";
import { decryptSecret } from "../packages/core/src/crypto.js";
async function main(): Promise<void> {
  const db = new Database(process.env["MV_UPGRADE_DB"] ?? "", {readonly:true,fileMustExist:true});
  const wrapped = JSON.parse(readFileSync(process.env["MV_UPGRADE_KEY"] ?? "", "utf8"));
  const key = await unwrapMasterKey(wrapped, process.env["MV_UPGRADE_PASSWORD"] ?? "");
  try {
    const row = db.prepare("SELECT ciphertext FROM credentials WHERE alias=?").get("previous-release-dummy") as {ciphertext:string} | undefined;
    if (!row || decryptSecret(key,row.ciphertext) !== process.env["MV_UPGRADE_EXPECTED"]) throw new Error("Published upgrade synthetic decryption failed");
    process.stdout.write("PASS published-release credential decrypts with original key after candidate upgrade\n");
  } finally {key.fill(0);db.close();}
}
void main().catch(()=>{process.stderr.write("Synthetic upgrade decrypt verification failed\n");process.exitCode=1;});
