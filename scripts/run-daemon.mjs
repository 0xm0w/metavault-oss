import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { startVaultDaemon } from "../dist/packages/daemon/src/server.js";

const port = Number(process.env.METAVAULT_PORT || 7077);

// Default: the daemon resolves its own key. A passphrase-wrapped key
// (metavault.key.json, created by `metavault init` or `metavault key
// protect`) starts LOCKED; unlock with `metavault unlock`. An env key is
// honoured only with METAVAULT_ALLOW_ENV_MASTER_KEY=1.
//
// METAVAULT_DEV_PLAINTEXT_KEY=1 restores the old throwaway dev behaviour
// (an UNWRAPPED key in ./metavault.key). Never use it with real secrets:
// any process running as you can read that file.
let masterKey;
if (process.env.METAVAULT_DEV_PLAINTEXT_KEY === "1") {
  const keyFile = "metavault.key";
  console.warn("[vaultd] DEV ONLY: using an unwrapped master key file (./metavault.key)");
  if (existsSync(keyFile)) {
    masterKey = Buffer.from(readFileSync(keyFile, "utf8").trim(), "base64");
  } else {
    masterKey = randomBytes(32);
    writeFileSync(keyFile, masterKey.toString("base64"), { encoding: "utf8", mode: 0o600 });
  }
}

process.on("uncaughtException", (err) => console.error("Uncaught exception:", err));
process.on("unhandledRejection", (err) => console.error("Unhandled rejection:", err));

await startVaultDaemon(masterKey === undefined ? { port } : { port, masterKey });

console.log(`[vaultd] listening on http://127.0.0.1:${port}`);
setInterval(() => {}, 60000);
