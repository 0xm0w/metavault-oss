// Two-host MCP gate: boots vaultd (mock upstream, live marshal), then
// connects TWO independent MCP stdio processes — configured the way two
// different IDE hosts (VS Code, Claude Code) would be — and verifies
// both can list aliases and request a capability without ever seeing
// the secret. Protocol-level equivalent of the two-IDE check.
// Usage: node scripts/check-mcp-hosts.mjs  (after the dist build)
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { Effect } from "effect";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { startVaultDaemon } from "../dist/packages/daemon/src/server.js";
import { VaultStore, VaultStoreLive } from "../dist/packages/core/src/storage.js";
import { encryptSecret } from "../dist/packages/core/src/crypto.js";

const SECRET = "sk-test-MCPHOST-0000000000000000";
const dir = mkdtempSync(join(tmpdir(), "metavault-mcp-"));
const dbPath = join(dir, "vault.db");
const masterKey = randomBytes(32);

const upstream = createServer((req, res) => {
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ data: [] }));
});
await new Promise((r) => upstream.listen(0, "127.0.0.1", r));

await Effect.runPromise(
  Effect.gen(function* () {
    const store = yield* VaultStore;
    yield* store.addCredential("stripe", "charges.read", encryptSecret(masterKey, SECRET));
  }).pipe(Effect.provide(VaultStoreLive(dbPath, masterKey))),
);

const daemon = await startVaultDaemon({
  port: 0, dbPath, masterKey,
  connectorPresets: { stripe: `http://127.0.0.1:${upstream.address().port}/v1/charges` },
});
const daemonUrl = `http://127.0.0.1:${daemon.address().port}`;

const EXPECTED_TOOLS = ["enrollment_status", "grant_status", "list_aliases", "register_agent", "registration_status", "request_capability", "request_enrollment", "revoke"];

let failures = 0;
for (const host of ["vscode", "claude-code"]) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["dist/packages/mcp/src/server.js"],
    env: { ...process.env, METAVAULT_DAEMON_URL: daemonUrl, METAVAULT_AGENT_ID: host, METAVAULT_IDE: host },
  });
  const client = new Client({ name: `metavault-check-${host}`, version: "0.0.0" });
  const t = performance.now();
  await client.connect(transport);
  const listed = await client.listTools();
  const toolNames = listed.tools.map((tool) => tool.name).sort();
  const okTools = JSON.stringify(toolNames) === JSON.stringify(EXPECTED_TOOLS);
  const aliases = await client.callTool({ name: "list_aliases", arguments: {} });
  const aliasesText = JSON.stringify(aliases);
  const okAliases = aliasesText.includes("stripe") && !aliasesText.includes(SECRET);
  const result = await client.callTool({
    name: "request_capability",
    arguments: { alias: "stripe", scope: "charges.read", reason: "two-host gate check" },
  });
  const resultText = JSON.stringify(result);
  const okResult = !resultText.includes(SECRET) && (resultText.includes("executed") || resultText.includes("awaiting-approval"));
  console.log(`${okAliases && okResult && okTools ? "PASS" : "FAIL"}  host=${host.padEnd(11)} tools=${okTools} list_aliases=${okAliases} request=${okResult} (${Math.round(performance.now() - t)} ms)`);
  if (!(okAliases && okResult && okTools)) failures++;
  await client.close();
}

daemon.close();
upstream.close();
try {
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
} catch {
  console.log(`note: temp dir cleanup deferred by OS: ${dir}`);
}
console.log(`\nMCP TWO-HOST ${failures === 0 ? "PASS" : "FAIL"}`);
process.exit(failures === 0 ? 0 : 1);
