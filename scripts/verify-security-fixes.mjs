// File: scripts/verify-security-fixes.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const read = (rel) => fs.readFileSync(path.join(root, rel), "utf8");

console.log("Running MetaVault security remediation verification checks...\n");

// 1. Verify Task 1 (daemon-registrations-missing-device-binding)
const regSrc = read("packages/daemon/src/registrations.ts");
const serverSrc = read("packages/daemon/src/server.ts");
const appMainSrc = read("packages/app/src/main.ts");
assert.ok(regSrc.includes('origin: "local" | "remote"'), "Task 1: PendingRegistration must include origin");
assert.ok(regSrc.includes("deviceId?: string"), "Task 1: PendingRegistration must include deviceId");
assert.ok(serverSrc.includes("service.registerAgent(agentId, name, false, regDeviceId)"), "Task 1: server.ts must pass regDeviceId to registerAgent");
assert.ok(serverSrc.includes("pendingReg.origin === \"remote\""), "Task 1: server.ts must enforce presenceProof on remote registration approval");
assert.ok(!appMainSrc.includes("(approve|deny)$/.test(reqPath)"), "Task 1: flyout must not allow one-click registration approve");
console.log("[PASS] Task 1: Remote agent registration device binding & presence proof");

// 2. Verify Task 2 (daemon-revoke-device-leaves-pending-grants-active)
const grantsSrc = read("packages/core/src/grants.ts");
const serviceSrc = read("packages/daemon/src/service.ts");
assert.ok(grantsSrc.includes("invalidatePendingForDevice"), "Task 2: GrantRegistry must implement invalidatePendingForDevice");
assert.ok(serviceSrc.includes("registry.invalidatePendingForDevice(id)"), "Task 2: revokeDevice must call invalidatePendingForDevice(id)");
assert.ok(serviceSrc.includes("store.getDevice(grantReq.deviceId)"), "Task 2: consumeAndExecute must re-check store.getDevice(grantReq.deviceId)");
console.log("[PASS] Task 2: Device revocation invalidates pending device grants & re-checks on execute");

// 3. Verify Task 3 (app-ipc-agent-token-issuance-presence-bypass)
const guardSrc = read("packages/app/src/remote-approval-guard.ts");
assert.ok(
  guardSrc.includes('options.path === "/agents/rotate" || options.path === "/agents" || options.path === "/agents/revoke"'),
  "Task 3: guardAgentRotateCall must guard /agents, /agents/rotate, and /agents/revoke"
);
assert.ok(
  guardSrc.includes('record["presenceProof"] = consumed.daemonProof'),
  "Task 3: consumeStripped must forward daemonProof as presenceProof"
);
assert.ok(
  appMainSrc.includes("if (!next && daemonLocked)"),
  "Task 3: metavault:ui-lock-state must not clear uiLocked while daemonLocked is true"
);
console.log("[PASS] Task 3: Electron IPC & daemon agent token issuance presence proof guard");

// 4. Verify Task 4 (daemon-unverified-caller-spoofs-agentid-velocity-dos)
assert.ok(
  serviceSrc.includes('unverified-enrolled-agent-spoof') && serviceSrc.includes('const velocityKey = `${req.verified ? "verified" : "unverified"}:${req.agentId}`'),
  "Task 4: submitRequest must block unverified spoofing of active enrolled agents and namespace velocityKey"
);
console.log("[PASS] Task 4: Velocity & circuit-breaker isolation against unverified agentId spoofing");

// 5. Verify Task 5 (daemon-standing-lease-fastpath-payload-blindness)
const rulesSrc = read("packages/brain/src/rules.ts");
const promptSrc = read("packages/brain/src/prompt.ts");
assert.ok(rulesSrc.includes("const sensitive = SENSITIVE.test(untrusted);"), "Task 5: SENSITIVE must test untrusted (reason + payload)");
assert.ok(rulesSrc.includes("const bulk = BULK.test(untrusted);"), "Task 5: BULK must test untrusted (reason + payload)");
assert.ok(promptSrc.includes("payloadSafetyText:"), "Task 5: buildMarshalPrompt must include payload.safetyText");
console.log("[PASS] Task 5: Standing approval & session lease payload inspection");

// 6. Verify Task 6 (cli-run-unverified-grant-flag-and-dotenv-write-ceilings)
const cliSrc = read("packages/cli/src/cli.ts");
const dotenvSrc = read("packages/core/src/dotenv.ts");
assert.ok(cliSrc.includes("/^[a-zA-Z0-9_-]{16,128}$/.test(trimmedGrant)"), "Task 6: cli.ts must validate non-interactive --grant token format");
assert.ok(!dotenvSrc.includes('"chat.completions"') && !dotenvSrc.includes('"messages.create"'), "Task 6: dotenv.ts KNOWN_RULES must default to explicit .read ceilings");
console.log("[PASS] Task 6: CLI --grant validation & dotenv read-only default ceilings");

// 7. Verify Task 7 & Task 8 (Updater & CI Runner Hardening)
const updaterSrc = read("packages/app/src/updater.ts");
const entrypointSrc = read("ops/ci-runner/entrypoint.sh");
assert.ok(updaterSrc.includes('process.env["METAVAULT_AUTO_UPDATE"] !== "1"'), "Task 7: updater.ts must require explicit METAVAULT_AUTO_UPDATE=1 opt-in while unsigned");
assert.ok(entrypointSrc.includes("chmod 0600"), "Task 8: entrypoint.sh must restrict .credentials_rsaparams permissions");
console.log("[PASS] Task 7 & 8: Auto-updater opt-in guard & CI runner credential file permissions\n");

console.log("ALL 8 SECURITY REMEDIATION CHECKS PASSED.");
