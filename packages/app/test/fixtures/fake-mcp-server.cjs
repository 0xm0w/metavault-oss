// Minimal newline-delimited JSON-RPC MCP stand-in for mcp-selfcheck tests.
// Modes via argv[2]: "ok" (default), "silent" (never answers), "exit" (dies),
// "badtools" (wrong tool set).
const mode = process.argv[2] ?? "ok";
if (mode === "exit") process.exit(1);
const TOOLS_OK = ["enrollment_status","grant_status","list_aliases","register_agent","registration_status","request_capability","request_enrollment","revoke"];
// eslint-disable-next-line @typescript-eslint/no-require-imports -- .cjs fixture, not compiled
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.method === "initialize") {
    if (mode !== "silent") {
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-03-26", capabilities: {}, serverInfo: { name: "fake-metavault", version: "0.0.0-test" } } }) + "\n");
    }
  } else if (msg.method === "tools/list") {
    if (mode !== "silent") {
      const tools = (mode === "badtools" ? ["list_aliases"] : TOOLS_OK).map((name) => ({ name, inputSchema: { type: "object" } }));
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { tools } }) + "\n");
    }
  }
});
