// E2E QA harness (policy-only warden, no local AI) for metavault-oss.
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { Effect } from "effect";
import { startVaultDaemon } from "../dist/packages/daemon/src/server.js";
import { VaultStore, VaultStoreLive } from "../dist/packages/core/src/storage.js";
import { encryptSecret } from "../dist/packages/core/src/crypto.js";

const SECRET = "sk-test-E2E-QA-1111111111111111";
const results = [];
const step = (name, ok, detail="") => { results.push({name, ok, detail}); console.log(`${ok?"PASS":"FAIL"}  ${name}  ${detail}`); };

// mock upstream
let seenAuth = null;
const upstream = createServer((req,res)=>{ seenAuth = req.headers.authorization ?? null; res.setHeader("content-type","application/json"); res.end(JSON.stringify({data:[{id:"ch_1",amount:1200}]})); });
await new Promise(r=>upstream.listen(0,"127.0.0.1",r));
const upstreamUrl = `http://127.0.0.1:${upstream.address().port}/v1/charges`;

const dir = mkdtempSync(join(tmpdir(),"metavault-e2e-"));
const dbPath = join(dir,"metavault.db");
const masterKey = randomBytes(32);

// env check: only METAVAULT_* is read (the legacy prefix was dropped; see CHANGELOG)
process.env["METAVAULT_MASTER_KEY"] = masterKey.toString("base64");
const { metavaultEnv } = await import("../dist/packages/core/src/env.js");
step("env: METAVAULT_MASTER_KEY resolves", metavaultEnv("MASTER_KEY") === process.env["METAVAULT_MASTER_KEY"]);
delete process.env["METAVAULT_MASTER_KEY"];

// seed credential
await Effect.runPromise(Effect.gen(function*(){ const s = yield* VaultStore; yield* s.addCredential("stripe","charges.read",encryptSecret(masterKey,SECRET), "stripe.com"); }).pipe(Effect.provide(VaultStoreLive(dbPath, masterKey))));

const daemon = await startVaultDaemon({ port: 0, dbPath, masterKey, connectorPresets: { stripe: upstreamUrl } });
const base = `http://127.0.0.1:${daemon.address().port}`;
const token = readFileSync(join(dir,"metavault.token"),"utf8").trim();
writeFileSync("/tmp/mvqa/daemon-info.json", JSON.stringify({ base, token, dbPath, dir }));
const call = async (method, path, body, headers={}) => { const res = await fetch(base+path,{method,headers:{"content-type":"application/json",...headers},body:body?JSON.stringify(body):undefined}); const text = await res.text(); let json=null; try{json=JSON.parse(text)}catch{} return {status:res.status,text,json}; };

// 1. policy-only: set warden provider none (no local AI)
const s0 = await call("PATCH","/settings/warden",{provider:"none"},{"x-metavault-token":token});
step("settings: warden provider none (policy-only)", s0.status===200, s0.text.slice(0,80));

// 2. capability request: write scope requires human; read within ceiling
const reqBody = { agentId:"cursor", ide:"Cursor", tool:"http", alias:"stripe", requestedScope:"charges.read", reason:"List recent charges for QA" };
const r1 = await call("POST","/request",reqBody);
step("request charges.read -> awaiting-approval", r1.json?.status==="awaiting-approval", `got ${r1.json?.status}`);
step("no secret in /request response", !r1.text.includes(SECRET));
const grantId = r1.json?.grantId;

// 3. approve without token -> 401
const bad = await call("POST","/approve",{grantId});
step("approve without token -> 401", bad.status===401, `HTTP ${bad.status}`);

// 4. approve with token -> executed; upstream saw secret; response has none
const ok = await call("POST","/approve",{grantId},{"x-metavault-token":token});
step("approve with token -> executed", ok.json?.status==="executed", ok.text.slice(0,100));
step("secret injected upstream in-daemon", seenAuth === `Bearer ${SECRET}`);
step("no secret in /approve response", !ok.text.includes(SECRET));

// 5. write scope denied by policy ceiling
const r2 = await call("POST","/request",{...reqBody, requestedScope:"charges.write", reason:"refund a charge"});
step("charges.write handled (denied or requires approval, never auto-executed)", ["denied","awaiting-approval"].includes(r2.json?.status), `got ${r2.json?.status}`);

// 6. unknown alias denied
const r3 = await call("POST","/request",{...reqBody, alias:"nonexistent"});
step("unknown alias denied", r3.json?.status==="denied", `got ${r3.json?.status}`);

// 7. enrollment deeplink flow
const e1 = await call("POST","/enrollments",{alias:"openai",scope:"responses.read",website:"openai.com",agentId:"cursor",ide:"Cursor"});
const deeplink = e1.json?.deeplink ?? "";
step("enrollment returns metavault:// deeplink", deeplink.startsWith("metavault://add?"), deeplink.slice(0,60));
const enrId = e1.json?.enrollmentId;
const e2 = await call("POST","/credentials",{alias:"openai",scope:"responses.read",secret:"sk-test-OPENAI-2222",website:"openai.com",enrollmentId:enrId},{"x-metavault-token":token});
step("credential added via enrollment", [200,201].includes(e2.status), `HTTP ${e2.status}`);
const e3 = await call("GET",`/enrollments/${enrId}`);
step("enrollment_status completed", e3.json?.status==="completed", `got ${e3.json?.status}`);

// 8. aliases / audit / policies
const al = await call("GET","/aliases",null,{"x-metavault-token":token});
step("aliases lists stripe+openai, no secrets", al.status===200 && al.text.includes("stripe") && al.text.includes("openai") && !al.text.includes(SECRET));
const au = await call("GET","/audit",null,{"x-metavault-token":token});
step("audit recorded the flow, no secrets", au.status===200 && au.text.includes("charges.read") && !au.text.includes(SECRET));
const pol = await call("GET","/policies",null,{"x-metavault-token":token});
step("policies endpoint ok", pol.status===200);

// 9. credential update (rotate secret) via PATCH
const up = await call("PATCH","/credentials/stripe",{secret:"sk-test-ROTATED-3333"},{"x-metavault-token":token});
step("PATCH credential secret rotation", up.status===200, `HTTP ${up.status}`);

// 10. pending endpoint + settings read
const pend = await call("GET","/pending",null,{"x-metavault-token":token});
step("pending endpoint ok", pend.status===200);
const warden = await call("GET","/settings/warden",null,{"x-metavault-token":token});
step("warden settings readback provider=none", warden.json?.provider==="none", JSON.stringify(warden.json).slice(0,80));

const failed = results.filter(r=>!r.ok).length;
console.log(`\nE2E SUMMARY: ${results.length-failed}/${results.length} passed`);
process.exit(failed?1:0);
