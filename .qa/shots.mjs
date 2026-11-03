import { createServer } from "node:http";
import { readFileSync, mkdirSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, extname } from "node:path";
import { randomBytes } from "node:crypto";
import { Effect } from "effect";
import puppeteer from "puppeteer-core";
import { startVaultDaemon } from "../dist/packages/daemon/src/server.js";
import { VaultStore, VaultStoreLive } from "../dist/packages/core/src/storage.js";
import { encryptSecret } from "../dist/packages/core/src/crypto.js";

const HARNESS = "/tmp/mvqa/harness";
const SHOTS = "/tmp/mvqa/shots"; mkdirSync(SHOTS, { recursive: true });
const MIME = { ".html":"text/html", ".js":"text/javascript", ".css":"text/css", ".svg":"image/svg+xml", ".png":"image/png", ".ico":"image/x-icon" };

// --- daemon setup (policy-only, seeded) ---
const dir = mkdtempSync(join(tmpdir(), "metavault-shots-"));
const dbPath = join(dir, "metavault.db");
const masterKey = randomBytes(32);
const seed = (alias, scope, secret, website) => Effect.runPromise(Effect.gen(function*(){ const s = yield* VaultStore; yield* s.addCredential(alias, scope, encryptSecret(masterKey, secret), website); }).pipe(Effect.provide(VaultStoreLive(dbPath, masterKey))));
await seed("stripe", "charges.read", "sk-test-DEMO-aaaa1111", "stripe.com");
await seed("openai", "responses.read", "sk-test-DEMO-bbbb2222", "openai.com");
await seed("cloudflare", "dns.read", "cf-test-DEMO-cccc3333", "cloudflare.com");
const daemon = await startVaultDaemon({ port: 0, dbPath, masterKey });
const base = `http://127.0.0.1:${daemon.address().port}`;
const token = readFileSync(join(dir, "metavault.token"), "utf8").trim();
const dcall = (method, path, body, auth=true) => fetch(base+path, { method, headers: { "content-type":"application/json", ...(auth?{"x-metavault-token":token}:{}) }, body: body?JSON.stringify(body):undefined }).then(r=>r.json());
await dcall("PATCH","/settings/warden",{provider:"none"});
// one executed flow for audit history
const r1 = await dcall("POST","/request",{agentId:"cursor",ide:"Cursor",tool:"http",alias:"stripe",requestedScope:"charges.read",reason:"List recent charges for the weekly report"});
await dcall("POST","/approve",{grantId:r1.grantId});
// one pending approval for the Approvals view
const r2 = await dcall("POST","/request",{agentId:"claude-code",ide:"Claude Code",tool:"http",alias:"openai",requestedScope:"responses.read",reason:"Summarize the latest support tickets with the saved OpenAI credential"});
console.log("pending grant:", r2.status, r2.grantId);

// --- static + proxy server ---
const server = createServer(async (req, res) => {
  const u = new URL(req.url, "http://x");
  if (u.pathname.startsWith("/daemon/")) {
    const path = u.pathname.slice(7);
    const chunks = []; for await (const c of req) chunks.push(c);
    const r = await fetch(base+path, { method: req.method, headers: { "content-type":"application/json", "x-metavault-token": token }, body: chunks.length?Buffer.concat(chunks):undefined });
    const text = await r.text();
    res.writeHead(r.status, { "content-type": r.headers.get("content-type") ?? "application/json" });
    res.end(text); return;
  }
  const fp = join(HARNESS, u.pathname === "/" ? "index.html" : u.pathname);
  try { const data = readFileSync(fp); res.writeHead(200, { "content-type": MIME[extname(fp)] ?? "application/octet-stream" }); res.end(data); }
  catch { res.writeHead(404); res.end("nf"); }
});
await new Promise(r => server.listen(8877, "127.0.0.1", r));

// --- browser ---
const browser = await puppeteer.launch({ executablePath: "/usr/bin/google-chrome", headless: "new", args: ["--no-sandbox","--disable-dev-shm-usage","--force-device-scale-factor=2","--hide-scrollbars"] });
const page = await browser.newPage();
await page.setViewport({ width: 980, height: 720, deviceScaleFactor: 2 });
page.on("pageerror", e => console.log("PAGEERROR:", e.message));
const shot = (name) => page.screenshot({ path: join(SHOTS, name) });
const clickText = (sel, text) => page.evaluate((sel, text) => {
  const els = [...document.querySelectorAll(sel)];
  const el = els.find(e => e.textContent.trim().toLowerCase().includes(text.toLowerCase()));
  if (!el) return false; el.click(); return true;
}, sel, text);
const settle = () => new Promise(r => setTimeout(r, 700));

await page.goto("http://127.0.0.1:8877/index.html", { waitUntil: "networkidle0" });
await settle();
await shot("01-vault-list.png");

// add credential modal
console.log("add btn:", await clickText("button", "Add credential"));
await settle(); await shot("02-vault-add-modal.png");
await clickText("button", "Cancel"); await settle();

// detail modal (the Value label fix)
console.log("card:", await clickText(".vault-card, tr, button", "stripe"));
await settle(); await shot("03-vault-detail-value.png");
await clickText("button", "Cancel"); await settle();

// enrollment deeplink prefill
await page.evaluate(() => window.__fireDeeplink({ alias: "openai", scope: "responses.read", website: "openai.com", enrollmentId: "enr_demo123" }));
await settle(); await shot("04-enroll-flow.png");
await clickText("button", "Cancel"); await settle();

// approvals view
console.log("approvals nav:", await clickText(".sidebar-nav button, nav button, button", "Approval"));
await settle(); await shot("05-approval-dialog.png");

// audit view + expand
console.log("audit nav:", await clickText(".sidebar-nav button, nav button, button", "Audit"));
await settle();
await clickText("tr, button, .audit-row", "charges.read");
await settle(); await shot("06-audit-verdict.png");

// settings view
console.log("settings nav:", await clickText(".sidebar-nav button, nav button, button", "Settings"));
await settle(); await shot("07-settings.png");

await browser.close();
console.log("done");
process.exit(0);
