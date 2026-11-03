import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { startVaultDaemon } from "../dist/packages/daemon/src/server.js";

const port = Number(process.env.METAVAULT_PORT || process.env.METAVAULT_PORT || 7077);
const keyFile = "metavault.key";

let masterKey;
const masterKeyEnv = process.env.METAVAULT_MASTER_KEY || process.env.METAVAULT_MASTER_KEY;
if (masterKeyEnv) {
  masterKey = Buffer.from(masterKeyEnv, "base64");
} else if (existsSync(keyFile)) {
  masterKey = Buffer.from(readFileSync(keyFile, "utf8").trim(), "base64");
} else {
  const generated = randomBytes(32);
  writeFileSync(keyFile, generated.toString("base64"), "utf8");
  masterKey = generated;
}

process.on("uncaughtException", (err) => console.error("Uncaught exception:", err));
process.on("unhandledRejection", (err) => console.error("Unhandled rejection:", err));

await startVaultDaemon({
  port,
  masterKey,
});

console.log(`[vaultd] listening on http://127.0.0.1:${port}`);
setInterval(() => {}, 60000);
