import { randomBytes, randomUUID } from "node:crypto";
import { Clock, Context, Duration, Effect, Exit, Fiber, Layer, Ref } from "effect";
import { Brain, DEFAULT_MARSHAL_MODEL } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { decryptSecret, encryptSecret } from "../../core/src/crypto.js";
import { GrantExpired, PolicyDenied, StorageError, } from "../../core/src/errors.js";
import { createGrant, makeGrantRegistry } from "../../core/src/grants.js";
import { evaluatePolicy, isWriteScope } from "../../core/src/policy.js";
import { VaultStore } from "../../core/src/storage.js";
export class VaultService extends Context.Tag("VaultService")() {
}
export const DEFAULT_ENROLLMENT_TTL_MS = 600_000;
export const ENROLLMENT_REASON_MAX_LENGTH = 256;
const DEFAULT_GRANT_TTL_MS = 60_000;
const DEFAULT_RATE_LIMIT_PER_HOUR = 20;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;
function resolveMasterKey(options) {
    if (options.masterKey !== undefined) {
        if (options.masterKey.length !== 32) {
            throw new Error("masterKey must be 32 bytes");
        }
        return options.masterKey;
    }
    const fromEnv = process.env["OPENVAULT_MASTER_KEY"];
    if (fromEnv !== undefined && fromEnv !== "") {
        const decoded = Buffer.from(fromEnv, "base64");
        if (decoded.length !== 32) {
            throw new Error("OPENVAULT_MASTER_KEY must be base64-encoded 32 bytes");
        }
        return decoded;
    }
    return randomBytes(32);
}
export function makeVaultServiceLive(options = {}) {
    const grantTtlMs = options.grantTtlMs ?? DEFAULT_GRANT_TTL_MS;
    const rateLimitPerHour = options.rateLimitPerHour ?? DEFAULT_RATE_LIMIT_PER_HOUR;
    const initialStandingApprovals = options.standingApprovals ?? [];
    const modelId = options.modelId ?? DEFAULT_MARSHAL_MODEL;
    const enrollmentTtlMs = options.enrollmentTtlMs ?? DEFAULT_ENROLLMENT_TTL_MS;
    return Layer.effect(VaultService, Effect.gen(function* () {
        const store = yield* VaultStore;
        const brain = yield* Brain;
        const connector = yield* Connector;
        const masterKey = yield* Effect.sync(() => resolveMasterKey(options));
        const registry = yield* makeGrantRegistry();
        const sleepers = yield* Ref.make(new Map());
        const aliases = yield* Ref.make(new Set());
        // Standing approvals start from config and grow at runtime when the
        // human picks "Always allow" for a read-only low-risk grant.
        const standing = yield* Ref.make([
            ...initialStandingApprovals,
        ]);
        // Marshal decision per pending grant, kept so the app can show the
        // assessment (and so approve-always can re-check it server-side).
        const decisions = yield* Ref.make(new Map());
        const enrollments = yield* Ref.make(new Map());
        const purgeExpiredEnrollments = (now, keepId) => Ref.update(enrollments, (map) => {
            const next = new Map(map);
            for (const [id, record] of next) {
                if (id !== keepId && record.status === "pending" && record.expiresAtMs <= now) {
                    next.delete(id);
                }
            }
            return next;
        });
        const forgetDecision = (grantId) => Ref.update(decisions, (map) => {
            const next = new Map(map);
            next.delete(grantId);
            return next;
        });
        const audit = (agentId, alias, scope, stage, detail, withModel) => Effect.flatMap(Clock.currentTimeMillis, (now) => {
            const base = {
                ts: new Date(now).toISOString(),
                agentId,
                alias,
                scope,
                stage,
                detail,
            };
            const event = withModel ? { ...base, modelId } : base;
            return store.appendAudit(event);
        });
        const interruptSleeper = (grantId) => Effect.flatMap(Ref.modify(sleepers, (map) => {
            const fiber = map.get(grantId);
            const next = new Map(map);
            next.delete(grantId);
            return [fiber, next];
        }), (fiber) => fiber === undefined ? Effect.void : Fiber.interrupt(fiber).pipe(Effect.ignore));
        const scheduleExpiry = (grant) => Effect.gen(function* () {
            const fiber = yield* Effect.forkDaemon(Effect.sleep(Duration.millis(grantTtlMs)).pipe(Effect.flatMap(() => registry.markExpired(grant.grantId)), Effect.flatMap((marked) => marked
                ? audit(grant.request.agentId, grant.request.alias, grant.allowedScope, "expired", "grant expired before approval", true)
                : Effect.void), Effect.ensuring(Ref.update(sleepers, (map) => {
                const next = new Map(map);
                next.delete(grant.grantId);
                return next;
            }))));
            yield* Ref.update(sleepers, (map) => {
                const next = new Map(map);
                next.set(grant.grantId, fiber);
                return next;
            });
        });
        const decrypt = (ciphertext) => Effect.try({
            try: () => decryptSecret(masterKey, ciphertext),
            catch: () => new StorageError({ message: "failed to decrypt credential", operation: "decrypt" }),
        });
        const executeGrant = (req, allowedScope, ciphertext) => Effect.flatMap(decrypt(ciphertext), (secret) => connector.execute(req.alias, allowedScope, secret));
        // Shared tail of approve / approve-always: consume the pending grant
        // exactly once, audit the human decision, execute inside the daemon.
        const consumeAndExecute = (grantId, auditDetail) => Effect.gen(function* () {
            const now = yield* Clock.currentTimeMillis;
            const consumed = yield* registry.consumeForExecution(grantId, now).pipe(Effect.catchTag("GrantExpired", (err) => Effect.flatMap(registry.get(grantId), (grant) => Effect.flatMap(grant === undefined
                ? Effect.void
                : audit(grant.request.agentId, grant.request.alias, grant.allowedScope, "expired", "grant expired or already consumed", true), () => Effect.fail(err)))));
            yield* forgetDecision(grantId);
            yield* interruptSleeper(grantId);
            const grantReq = consumed.request;
            yield* audit(grantReq.agentId, grantReq.alias, consumed.allowedScope, "approved", auditDetail, true);
            const credential = yield* store.getCredential(grantReq.alias);
            if (credential === undefined) {
                return yield* Effect.fail(new StorageError({ message: "credential no longer exists", operation: "getCredential" }));
            }
            const result = yield* executeGrant(grantReq, consumed.allowedScope, credential.ciphertext);
            yield* audit(grantReq.agentId, grantReq.alias, consumed.allowedScope, "executed", "executed", true);
            return { status: "executed", result };
        });
        const service = {
            seedCredential: (alias, ceiling, plaintextSecret, website, enrollmentId) => Effect.flatMap(Effect.sync(() => encryptSecret(masterKey, plaintextSecret)), (blob) => Effect.flatMap(store.addCredential(alias, ceiling, blob, website ?? ""), () => Effect.flatMap(Ref.update(aliases, (set) => {
                const next = new Set(set);
                next.add(alias);
                return next;
            }), () => Effect.flatMap(audit("human", alias, ceiling, "credential-added", `credential added: ${alias} (${ceiling})`, false), () => enrollmentId === undefined
                ? Effect.void
                : Effect.gen(function* () {
                    const now = yield* Clock.currentTimeMillis;
                    const existing = (yield* Ref.get(enrollments)).get(enrollmentId);
                    if (existing === undefined || existing.status !== "pending" || existing.alias !== alias || existing.scope !== ceiling || existing.expiresAtMs <= now) {
                        return;
                    }
                    yield* Ref.update(enrollments, (map) => {
                        const next = new Map(map);
                        next.set(enrollmentId, { ...existing, status: "completed" });
                        return next;
                    });
                    yield* audit("agent", alias, existing.scope, "enrollment-completed", `enrollment completed: ${alias}`, false);
                }))))),
            createEnrollment: (alias, scope, website, reason) => Effect.gen(function* () {
                const now = yield* Clock.currentTimeMillis;
                yield* purgeExpiredEnrollments(now);
                const enrollmentId = yield* Effect.sync(() => randomUUID());
                const record = { enrollmentId, alias, scope, website: website ?? "", status: "pending", expiresAtMs: now + enrollmentTtlMs };
                yield* Ref.update(enrollments, (map) => { const next = new Map(map); next.set(enrollmentId, record); return next; });
                const cappedReason = (reason ?? "").trim().slice(0, ENROLLMENT_REASON_MAX_LENGTH);
                yield* audit("agent", alias, scope, "enrollment-created", cappedReason === "" ? `enrollment created: ${alias}` : `enrollment created: ${alias}: ${cappedReason}`, false);
                return record;
            }),
            getEnrollment: (enrollmentId) => Effect.gen(function* () {
                const now = yield* Clock.currentTimeMillis;
                yield* purgeExpiredEnrollments(now, enrollmentId);
                const record = (yield* Ref.get(enrollments)).get(enrollmentId);
                if (record === undefined) {
                    return null;
                }
                if (record.status === "pending" && record.expiresAtMs <= now) {
                    return { ...record, status: "expired" };
                }
                return record;
            }),
            updateCredential: (alias, patch) => Effect.gen(function* () {
                const existing = yield* store.getCredential(alias);
                if (existing === undefined) {
                    return null;
                }
                const affected = yield* registry.revokePendingForAlias(alias);
                for (const grant of affected) {
                    yield* forgetDecision(grant.grantId);
                    yield* interruptSleeper(grant.grantId);
                }
                const scopeCeiling = patch.scope !== undefined && patch.scope.trim() !== "" ? patch.scope.trim() : existing.scopeCeiling;
                const website = patch.website !== undefined ? patch.website.trim() : existing.website;
                const ciphertext = patch.secret !== undefined && patch.secret.trim() !== ""
                    ? yield* Effect.sync(() => encryptSecret(masterKey, patch.secret))
                    : existing.ciphertext;
                yield* store.updateCredential(alias, scopeCeiling, ciphertext, website);
                return { scopeCeiling, website };
            }),
            deleteCredential: (alias) => Effect.gen(function* () {
                const existing = yield* store.getCredential(alias);
                if (existing === undefined) {
                    return false;
                }
                const affected = yield* registry.revokePendingForAlias(alias);
                for (const grant of affected) {
                    yield* forgetDecision(grant.grantId);
                    yield* interruptSleeper(grant.grantId);
                }
                yield* Ref.update(standing, (list) => list.filter((entry) => entry.alias !== alias));
                yield* store.deleteCredential(alias);
                yield* Ref.update(aliases, (set) => {
                    const next = new Set(set);
                    next.delete(alias);
                    return next;
                });
                yield* audit("human", alias, "", "credential-deleted", `credential deleted: ${alias}`, false);
                return true;
            }),
            listCredentialMeta: () => store.listCredentials(),
            requestCapability: (req) => Effect.gen(function* () {
                const now = yield* Clock.currentTimeMillis;
                const credential = yield* store.getCredential(req.alias);
                const auditEvents = yield* store.listAudit();
                yield* audit(req.agentId, req.alias, req.requestedScope, "requested", "capability requested", false);
                if (yield* registry.isRevoked(req.agentId, req.alias)) {
                    yield* audit(req.agentId, req.alias, req.requestedScope, "denied", "revoked", true);
                    return { status: "denied", reason: "revoked" };
                }
                const agentEvents = auditEvents.filter((e) => e.agentId === req.agentId);
                const within = (e, windowMs) => now - Date.parse(e.ts) < windowMs;
                const historyCount = agentEvents.filter((e) => e.stage === "requested" && within(e, HOUR_MS)).length;
                const historySummary = {
                    requests24h: agentEvents.filter((e) => e.stage === "requested" && within(e, DAY_MS)).length,
                    denials24h: agentEvents.filter((e) => e.stage === "denied" && within(e, DAY_MS))
                        .length,
                };
                const ceilings = credential === undefined ? {} : { [req.alias]: credential.scopeCeiling };
                const standingNow = yield* Ref.get(standing);
                const cfg = { ceilings, standingApprovals: standingNow, rateLimitPerHour };
                // Policy pre-check: unknown alias / rate limit deny before the marshal runs.
                const preCheck = evaluatePolicy(req, null, cfg, historyCount);
                if (credential === undefined || preCheck.allowedScope === null) {
                    const reason = credential === undefined ? "unknown-alias" : preCheck.reason;
                    yield* audit(req.agentId, req.alias, req.requestedScope, "policy", reason, true);
                    yield* audit(req.agentId, req.alias, req.requestedScope, "denied", reason, true);
                    return { status: "denied", reason };
                }
                yield* Ref.update(aliases, (set) => {
                    const next = new Set(set);
                    next.add(req.alias);
                    return next;
                });
                const policyDigest = `${req.alias} ceiling=${credential.scopeCeiling}`;
                // The ONLY place marshal errors are absorbed: recovered to a null
                // decision for evaluatePolicy, with an audit event saying so.
                const decision = yield* brain
                    .assess(req, historySummary, policyDigest)
                    .pipe(Effect.catchTags({
                    MarshalUnavailable: () => Effect.flatMap(audit(req.agentId, req.alias, req.requestedScope, "marshal", "marshal unavailable; recovered to null decision", true), () => Effect.succeed(null)),
                    MarshalInvalidOutput: () => Effect.flatMap(audit(req.agentId, req.alias, req.requestedScope, "marshal", "marshal invalid output; recovered to null decision", true), () => Effect.succeed(null)),
                }));
                if (decision !== null) {
                    yield* audit(req.agentId, req.alias, req.requestedScope, "marshal", decision.explanation, true);
                }
                const result = evaluatePolicy(req, decision, cfg, historyCount);
                yield* audit(req.agentId, req.alias, result.allowedScope ?? req.requestedScope, "policy", result.reason, true);
                if (result.allowedScope === null) {
                    yield* audit(req.agentId, req.alias, req.requestedScope, "denied", result.reason, true);
                    return { status: "denied", reason: result.reason };
                }
                const allowedScope = result.allowedScope;
                if (result.requireApproval) {
                    const grantId = yield* Effect.sync(() => randomUUID());
                    const grant = createGrant(grantId, req, allowedScope, now, grantTtlMs);
                    yield* registry.register(grant);
                    yield* Ref.update(decisions, (map) => {
                        const next = new Map(map);
                        next.set(grantId, decision);
                        return next;
                    });
                    yield* scheduleExpiry(grant);
                    return { status: "awaiting-approval", grantId, reason: result.reason };
                }
                yield* audit(req.agentId, req.alias, allowedScope, "approved", "auto-approved by policy", true);
                const exit = yield* Effect.exit(executeGrant(req, allowedScope, credential.ciphertext));
                if (Exit.isFailure(exit)) {
                    yield* audit(req.agentId, req.alias, allowedScope, "executed", "connector-failed", true);
                    return { status: "denied", reason: "connector-failed" };
                }
                yield* audit(req.agentId, req.alias, allowedScope, "executed", "executed", true);
                return { status: "executed", result: exit.value, reason: result.reason };
            }),
            approve: (grantId) => consumeAndExecute(grantId, "approved by human"),
            approveAlways: (grantId) => Effect.gen(function* () {
                const grant = yield* registry.get(grantId);
                if (grant === undefined || grant.status !== "pending") {
                    return yield* Effect.fail(new GrantExpired({ grantId, message: "grant not found or already consumed" }));
                }
                const decision = (yield* Ref.get(decisions)).get(grantId) ?? null;
                // Standing approvals are only ever created for read-only scopes
                // the marshal rated low-risk — re-checked here, server-side, so
                // no client can widen them. Writes ask every time.
                if (decision === null || decision.risk !== "low" || isWriteScope(grant.allowedScope)) {
                    return yield* Effect.fail(new PolicyDenied({
                        message: "always-allow requires a read-only low-risk grant",
                        reason: "always-allow-not-eligible",
                        alias: grant.request.alias,
                        scope: grant.allowedScope,
                    }));
                }
                // Execute first: the standing approval is recorded only after a
                // successful execution, so a grant that expires (or whose
                // connector call fails) in between leaves no standing approval
                // behind for an execution that never happened.
                const executed = yield* consumeAndExecute(grantId, "approved by human (always allow)");
                yield* Ref.update(standing, (list) => {
                    const exists = list.some((entry) => entry.agentId === grant.request.agentId &&
                        entry.alias === grant.request.alias &&
                        entry.scope === grant.allowedScope);
                    return exists
                        ? list
                        : [
                            ...list,
                            {
                                agentId: grant.request.agentId,
                                alias: grant.request.alias,
                                scope: grant.allowedScope,
                            },
                        ];
                });
                yield* audit(grant.request.agentId, grant.request.alias, grant.allowedScope, "approved", "standing approval created (always allow)", true);
                return executed;
            }),
            deny: (grantId) => Effect.gen(function* () {
                const denied = yield* registry.markDenied(grantId);
                if (!denied) {
                    return;
                }
                yield* forgetDecision(grantId);
                yield* interruptSleeper(grantId);
                const grant = yield* registry.get(grantId);
                if (grant !== undefined) {
                    yield* audit(grant.request.agentId, grant.request.alias, grant.allowedScope, "denied", "denied by human", true);
                }
            }),
            revoke: (agentIdOrAlias) => Effect.gen(function* () {
                const affected = yield* registry.revokePendingFor(agentIdOrAlias);
                for (const grant of affected) {
                    yield* forgetDecision(grant.grantId);
                    yield* interruptSleeper(grant.grantId);
                    yield* audit(grant.request.agentId, grant.request.alias, grant.allowedScope, "revoked", `revoked: ${agentIdOrAlias}`, true);
                }
                if (affected.length === 0) {
                    yield* audit(agentIdOrAlias, agentIdOrAlias, "", "revoked", `revoked: ${agentIdOrAlias}`, true);
                }
            }),
            hasCredential: (alias) => Effect.map(store.getCredential(alias), (credential) => credential !== undefined),
            // Aliases live in the vault DB (the CLI enrolls credentials there
            // directly); the in-memory set only mirrors this process's activity.
            listAliases: () => Effect.flatMap(store.listCredentialAliases(), (fromDb) => Ref.get(aliases).pipe(Effect.map((seen) => [...new Set([...fromDb, ...seen])].sort()))),
            listAudit: () => store.listAudit(),
            listPendingApprovals: () => Effect.gen(function* () {
                const now = yield* Clock.currentTimeMillis;
                const grants = yield* registry.listGrants();
                const decisionMap = yield* Ref.get(decisions);
                const pending = [];
                for (const grant of grants) {
                    if (grant.status !== "pending" || grant.expiresAtMs <= now) {
                        continue;
                    }
                    const decision = decisionMap.get(grant.grantId) ?? null;
                    const base = {
                        grantId: grant.grantId,
                        agentId: grant.request.agentId,
                        ide: grant.request.ide,
                        tool: grant.request.tool,
                        alias: grant.request.alias,
                        requestedScope: grant.request.requestedScope,
                        allowedScope: grant.allowedScope,
                        reason: grant.request.reason,
                        risk: decision?.risk ?? "medium",
                        marshalExplanation: decision?.explanation ??
                            "Marshal unavailable — deterministic policy requires your approval.",
                        createdAtMs: grant.createdAtMs,
                        expiresAtMs: grant.expiresAtMs,
                    };
                    pending.push({ ...base, modelId });
                }
                pending.sort((a, b) => a.createdAtMs - b.createdAtMs);
                return pending;
            }),
            // Real policy state for the Policies view: the enforced ceiling for
            // every enrolled alias (read back from the vault, never inferred
            // from audit) plus the standing approvals currently in force.
            listPolicies: () => Effect.gen(function* () {
                const credentialAliases = yield* store.listCredentialAliases();
                const ceilings = {};
                for (const alias of [...credentialAliases].sort()) {
                    const credential = yield* store.getCredential(alias);
                    if (credential !== undefined) {
                        ceilings[alias] = credential.scopeCeiling;
                    }
                }
                const standingNow = yield* Ref.get(standing);
                const standingApprovals = standingNow
                    .map((entry) => ({
                    agentId: entry.agentId,
                    alias: entry.alias,
                    scope: entry.scope,
                }))
                    .sort((a, b) => a.agentId.localeCompare(b.agentId) ||
                    a.alias.localeCompare(b.alias) ||
                    a.scope.localeCompare(b.scope));
                return { ceilings, standingApprovals };
            }),
        };
        return service;
    }));
}
export const VaultServiceLive = makeVaultServiceLive();
