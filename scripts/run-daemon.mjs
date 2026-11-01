import { randomBytes } from "node:crypto";
import { startVaultDaemon } from "../dist/packages/daemon/src/server.js";

const port = Number(process.env.OPENVAULT_PORT || 7078);
const masterKey = process.env.OPENVAULT_MASTER_KEY
  ? Buffer.from(process.env.OPENVAULT_MASTER_KEY, "base64")
  : randomBytes(32);

process.on("uncaughtException", (err) => console.error("Uncaught exception:", err));
process.on("unhandledRejection", (err) => console.error("Unhandled rejection:", err));

await startVaultDaemon({
  port,
  masterKey,
});

console.log(`[vaultd] listening on http://127.0.0.1:${port}`);
setInterval(() => {}, 60000);
