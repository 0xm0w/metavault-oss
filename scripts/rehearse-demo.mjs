// Demo rehearsal (verification gate): boots the real vaultd against a
// local mock upstream with the REAL Ollama marshal (llama3.2:3b), then
// runs the 3-minute demo flow end to end with timings and assertions.
// Requires: `npx tsc -p tsconfig.json --outDir dist` and Ollama running.
// Usage: node scripts/rehearse-demo.mjs
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { Effect } from "effect";
import { startVaultDaemon } from "../dist/packages/daemon/src/server.js";
import { VaultStore, VaultStoreLive } from "../dist/packages/core/src/storage.js";
import { encryptSecret } from "../dist/packages/core/src/crypto.js";

const SECRET = "sk-test-REHEARSE-0000000000000000";
const rows = [];
let failures = 0;
function step(name, ms, ok, detail) {
  rows.push({ name, ms: Math.round(ms), ok, detail });
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name.padEnd(38)} ${String(Math.round(ms)).padStart(6)} ms  ${detail}`);
}
const now = () => performance.now();

const dir = mkdtempSync(join(tmpdir(), "openvault-rehearse-"));
const dbPath = join(dir, "vault.db");
const masterKey = randomBytes(32);

// Mock upstream (stands in for api.stripe.com): records the injected header.
let seenAuth = null;
const upstream = createServer((req, res) => {
  seenAuth = req.headers.authorization ?? null;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ data: [{ id: "ch_1", amount: 1200 }, { id: "ch_2", amount: 3400 }] }));
});
await new Promise((r) => upstream.listen(0, "127.0.0.1", r));
const upstreamUrl = `http://127.0.0.1:${upstream.address().port}/v1/charges`;

// Seed one credential (ciphertext only in the DB).
await Effect.runPromise(
  Effect.gen(function* () {
    const store = yield* VaultStore;
    yield* store.addCredential("stripe", "charges.read", encryptSecret(masterKey, SECRET));
  }).pipe(Effect.provide(VaultStoreLive(dbPath, masterKey))),
);

const daemon = await startVaultDaemon({
  port: 0,
  dbPath,
  masterKey,
  connectorPresets: { stripe: upstreamUrl },
});
const base = `http://127.0.0.1:${daemon.address().port}`;
const token = readFileSync(join(dir, "openvault.token"), "utf8").trim();
const post = async (path, body, headers = {}) => {
  const t = now();
  const res = await fetch(base + path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, text, json: JSON.parse(text), ms: now() - t };
};
const req = (scope, reason) => ({
  agentId: "cursor", ide: "Cursor", tool: "http", alias: "stripe", requestedScope: scope, reason,
});

// 1. Agent requests a read; marshal (live llama3.2:3b) vets it.
const r1 = await post("/request", req("charges.read", "List the last 5 failed charges"));
step("request charges.read (live marshal)", r1.ms, r1.json.status === "awaiting-approval" || r1.json.status === "executed", `daemon said: ${r1.json.status}`);
if (r1.text.includes(SECRET)) { step("secret absent from /request response", 0, false, "SECRET LEAKED"); }

// 2. Self-approval without the daemon token must fail. Use a bogus
// grantId so this check runs even when step 1 auto-executed (no grantId).
const bad = await post("/approve", { grantId: "bogus-grant-id" });
step("approve without token -> 401", bad.ms, bad.status === 401, `HTTP ${bad.status}`);

// 3. Human approves with token; secret injected upstream, never returned.
// Only when step 1 left a pending grant - a low-risk read may instead
// have auto-executed, in which case the upstream/secret checks apply to r1.
let grantId = r1.json.grantId;
if (grantId) {
  const ok = await post("/approve", { grantId }, { "x-openvault-token": token });
  step("approve with token -> executed", ok.ms, ok.json.status === "executed", `result keys: ${Object.keys(ok.json.result ?? {}).join(",")}`);
  step("upstream received Bearer secret", 0, seenAuth === `Bearer ${SECRET}`, seenAuth ? "Authorization header injected in-daemon" : "no header seen");
  step("secret absent from approve result", 0, !ok.text.includes(SECRET), "result contains tool output only");
} else if (r1.json.status === "executed") {
  step("upstream received Bearer secret", 0, seenAuth === `Bearer ${SECRET}`, seenAuth ? "Authorization header injected in-daemon" : "no header seen");
  step("secret absent from request result", 0, !r1.text.includes(SECRET), "result contains tool output only");
}

// 4. A write request above a read ceiling is denied outright - no grant,
// no approval path, no execution of a downgraded read either.
const r2 = await post("/request", req("charges.write", "Refund charge ch_1"));
step("write request denied, never executes", r2.ms, r2.json.status === "denied" && !r2.json.grantId, `daemon said: ${r2.json.status}`);

// 5. Revoke the agent; its next request is denied.
const rv = await post("/revoke", { target: "cursor" });
const r3 = await post("/request", req("charges.read", "List charges again"));
step("after revoke, next request denied", r3.ms, r3.json.status === "denied", `revoke HTTP ${rv.status}, request: ${r3.json.status}`);

// 6. Audit log records the whole flow and contains no secret.
const auditRes = await fetch(base + "/audit");
const auditText = await auditRes.text();
const audit = JSON.parse(auditText);
const events = Array.isArray(audit.events) ? audit.events : [];
step("audit log complete, secret-free", 0, events.length >= 5 && !auditText.includes(SECRET), `${events.length} events, stages: ${[...new Set(events.map((e) => e.stage))].join(",")}`);

console.log(`\nREHEARSAL ${failures === 0 ? "PASS" : "FAIL"} (${rows.length} checks, ${failures} failures)`);
daemon.closeAllConnections();
upstream.closeAllConnections();
await Promise.all([
  new Promise((r) => daemon.close(r)),
  new Promise((r) => upstream.close(r)),
]);
try {
  rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
} catch {
  // The in-process vault DB is still open on Windows; the OS temp
  // cleaner reclaims the rehearsal dir after exit. Not a check failure.
}
await new Promise((r) => setTimeout(r, 250));
process.exit(failures === 0 ? 0 : 1);
