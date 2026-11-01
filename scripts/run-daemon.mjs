import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { startVaultDaemon } from "../dist/packages/daemon/src/server.js";

const port = Number(process.env.OPENVAULT_PORT || 7077);
const keyFile = "openvault.key";

let masterKey;
if (process.env.OPENVAULT_MASTER_KEY) {
  masterKey = Buffer.from(process.env.OPENVAULT_MASTER_KEY, "base64");
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
