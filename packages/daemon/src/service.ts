import { randomBytes, randomUUID } from "node:crypto";
import { Cause, Clock, Context, Duration, Effect, Exit, Fiber, Layer, Ref } from "effect";
import { Brain, DEFAULT_MARSHAL_MODEL } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { decryptSecret, encryptSecret } from "../../core/src/crypto.js";
import {
  ConnectorFailed,
  GrantExpired,
  GrantRevoked,
  PolicyDenied,
  StorageError,
} from "../../core/src/errors.js";
import { createGrant, makeGrantRegistry, type Grant } from "../../core/src/grants.js";
import { evaluatePolicy, isWriteScope, type PolicyConfig } from "../../core/src/policy.js";
import {
  WARDEN_KEY_ALIAS,
  WARDEN_KEY_MIN_LENGTH,
  WARDEN_KEY_SCOPE,
  type WardenKeyStatus,
  type WardenSettings,
} from "../../core/src/settings.js";
import { VaultStore } from "../../core/src/storage.js";
import type { AuditEvent, CapabilityRequest, MarshalDecision } from "../../core/src/types.js";

export interface CapabilityResult {
  readonly status: "executed" | "awaiting-approval" | "denied";
  readonly grantId?: string;
  readonly result?: unknown;
  readonly reason?: string;
}

// What the desktop app may see about a queued approval: who is asking, for
// what scope, why, what the marshal said, and when the grant expires.
// Secret values and ciphertext never appear here by construction.
export interface PendingApproval {
  readonly grantId: string;
  readonly agentId: string;
  readonly ide: string;
  readonly tool: string;
  readonly alias: string;
  readonly requestedScope: string;
  readonly allowedScope: string;
  readonly reason: string;
  readonly risk: "low" | "medium" | "high";
  readonly marshalExplanation: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly modelId?: string;
}

// Policy state the desktop app may see: the enforced ceiling per alias and
// the standing approvals currently in force. Metadata only — secret values
// and ciphertext never appear here by construction.
export interface PoliciesState {
  readonly ceilings: Record<string, string>;
  readonly standingApprovals: readonly {
    readonly agentId: string;
    readonly alias: string;
    readonly scope: string;
  }[];
}

export { WARDEN_KEY_ALIAS, WARDEN_KEY_MIN_LENGTH, WARDEN_KEY_SCOPE };
export type { WardenKeyStatus, WardenSettings };

export type WardenSettingsPatch = Partial<WardenSettings>;

export type EnrollmentStatusValue = "pending" | "completed" | "expired";
export interface EnrollmentRecord {
  readonly enrollmentId: string;
  readonly alias: string;
  readonly scope: string;
  readonly website: string;
  readonly status: EnrollmentStatusValue;
  readonly expiresAtMs: number;
}

export interface VaultServiceService {
  readonly seedCredential: (
    alias: string,
    ceiling: string,
    plaintextSecret: string,
    website?: string,
    enrollmentId?: string,
  ) => Effect.Effect<void, StorageError>;
  readonly createEnrollment: (
    alias: string,
    scope: string,
    website?: string,
    reason?: string,
  ) => Effect.Effect<EnrollmentRecord, StorageError>;
  readonly getEnrollment: (
    enrollmentId: string,
  ) => Effect.Effect<EnrollmentRecord | null, StorageError>;
  readonly updateCredential: (
    alias: string,
    patch: { readonly scope?: string; readonly website?: string; readonly secret?: string },
  ) => Effect.Effect<{ readonly scopeCeiling: string; readonly website: string } | null, StorageError>;
  readonly deleteCredential: (alias: string) => Effect.Effect<boolean, StorageError>;
  readonly listCredentialMeta: () => Effect.Effect<
    readonly { readonly alias: string; readonly scopeCeiling: string; readonly website: string }[],
    StorageError
  >;
  readonly requestCapability: (
    req: CapabilityRequest,
  ) => Effect.Effect<CapabilityResult, StorageError>;
  readonly approve: (
    grantId: string,
  ) => Effect.Effect<
    { readonly status: "executed"; readonly result: unknown },
    GrantExpired | GrantRevoked | ConnectorFailed | StorageError
  >;
  readonly deny: (grantId: string) => Effect.Effect<void, StorageError>;
  readonly approveAlways: (
    grantId: string,
  ) => Effect.Effect<
    { readonly status: "executed"; readonly result: unknown },
    GrantExpired | GrantRevoked | PolicyDenied | ConnectorFailed | StorageError
  >;
  readonly revoke: (agentIdOrAlias: string) => Effect.Effect<void, StorageError>;
  readonly hasCredential: (alias: string) => Effect.Effect<boolean, StorageError>;
  readonly listAliases: () => Effect.Effect<string[], StorageError>;
  readonly listAudit: () => Effect.Effect<AuditEvent[], StorageError>;
  readonly listPendingApprovals: () => Effect.Effect<PendingApproval[], StorageError>;
  readonly listPolicies: () => Effect.Effect<PoliciesState, StorageError>;
  readonly getWardenSettings: () => Effect.Effect<WardenSettings, StorageError>;
  readonly updateWardenSettings: (
    patch: WardenSettingsPatch,
  ) => Effect.Effect<WardenSettings, StorageError>;
  readonly setWardenKey: (key: string) => Effect.Effect<WardenKeyStatus, StorageError>;
  readonly deleteWardenKey: () => Effect.Effect<WardenKeyStatus, StorageError>;
  readonly wardenKeyStatus: () => Effect.Effect<WardenKeyStatus, StorageError>;
}

export class VaultService extends Context.Tag("VaultService")<VaultService, VaultServiceService>() {}

export interface VaultServiceOptions {
  readonly masterKey?: Buffer;
  readonly grantTtlMs?: number;
  readonly rateLimitPerHour?: number;
  readonly standingApprovals?: PolicyConfig["standingApprovals"];
  readonly modelId?: string;
  readonly enrollmentTtlMs?: number;
}

export const DEFAULT_ENROLLMENT_TTL_MS = 600_000;
export const ENROLLMENT_REASON_MAX_LENGTH = 256;

const DEFAULT_GRANT_TTL_MS = 60_000;
const DEFAULT_RATE_LIMIT_PER_HOUR = 20;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

function resolveMasterKey(options: VaultServiceOptions): Buffer {
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

export function makeVaultServiceLive(
  options: VaultServiceOptions = {},
): Layer.Layer<VaultService, never, VaultStore | Brain | Connector> {
  const grantTtlMs = options.grantTtlMs ?? DEFAULT_GRANT_TTL_MS;
  const rateLimitPerHour = options.rateLimitPerHour ?? DEFAULT_RATE_LIMIT_PER_HOUR;
  const initialStandingApprovals = options.standingApprovals ?? [];
  const modelId = options.modelId ?? DEFAULT_MARSHAL_MODEL;
  const enrollmentTtlMs = options.enrollmentTtlMs ?? DEFAULT_ENROLLMENT_TTL_MS;

  return Layer.effect(
    VaultService,
    Effect.gen(function* () {
      const store = yield* VaultStore;
      const brain = yield* Brain;
      const connector = yield* Connector;
      const masterKey = yield* Effect.sync(() => resolveMasterKey(options));
      const registry = yield* makeGrantRegistry();
      const sleepers = yield* Ref.make(new Map<string, Fiber.Fiber<void, StorageError>>());
      const aliases = yield* Ref.make(new Set<string>());
      // Standing approvals start from config and grow at runtime when the
      // human picks "Always allow" for a read-only low-risk grant.
      const standing = yield* Ref.make<PolicyConfig["standingApprovals"]>([
        ...initialStandingApprovals,
      ]);
      // Marshal decision per pending grant, kept so the app can show the
      // assessment (and so approve-always can re-check it server-side).
      const decisions = yield* Ref.make(new Map<string, MarshalDecision | null>());
      const grantAudit = yield* Ref.make(
        new Map<string, { readonly requestId: string; readonly decisionSource: AuditEvent["decisionSource"] }>(),
      );
      const enrollments = yield* Ref.make(new Map<string, EnrollmentRecord>());

      const purgeExpiredEnrollments = (now: number, keepId?: string): Effect.Effect<void> =>
        Ref.update(enrollments, (map) => {
          const next = new Map(map);
          for (const [id, record] of next) {
            if (id !== keepId && record.status === "pending" && record.expiresAtMs <= now) {
              next.delete(id);
            }
          }
          return next;
        });

      const forgetDecision = (grantId: string): Effect.Effect<void> =>
        Ref.update(decisions, (map) => {
          const next = new Map(map);
          next.delete(grantId);
          return next;
        });

      const forgetGrantAudit = (grantId: string): Effect.Effect<void> =>
        Ref.update(grantAudit, (map) => {
          const next = new Map(map);
          next.delete(grantId);
          return next;
        });

      const grantAuditExtras = (
        ctx: { readonly requestId: string } | undefined,
        decisionSource?: AuditEvent["decisionSource"],
      ): Partial<Pick<AuditEvent, "requestId" | "decisionSource">> =>
        ctx === undefined
          ? decisionSource === undefined
            ? {}
            : { decisionSource }
          : decisionSource === undefined
            ? { requestId: ctx.requestId }
            : { requestId: ctx.requestId, decisionSource };

      const audit = (
        agentId: string,
        alias: string,
        scope: string,
        stage: AuditEvent["stage"],
        detail: string,
        withModel: boolean,
        modelOverride?: string,
        extras?: Partial<
          Pick<AuditEvent, "requestId" | "risk" | "recommendedScope" | "decisionSource" | "latencyMs" | "explanation">
        >,
      ): Effect.Effect<void, StorageError> =>
        Effect.flatMap(Clock.currentTimeMillis, (now) => {
          const base: AuditEvent = {
            ts: new Date(now).toISOString(),
            agentId,
            alias,
            scope,
            stage,
            detail,
          };
          const event: AuditEvent = { ...(withModel ? { ...base, modelId: modelOverride ?? modelId } : base), ...extras };
          return store.appendAudit(event);
        });

      const interruptSleeper = (grantId: string): Effect.Effect<void> =>
        Effect.flatMap(
          Ref.modify(sleepers, (map) => {
            const fiber = map.get(grantId);
            const next = new Map(map);
            next.delete(grantId);
            return [fiber, next] as const;
          }),
          (fiber) =>
            fiber === undefined ? Effect.void : Fiber.interrupt(fiber).pipe(Effect.ignore),
        );

      const scheduleExpiry = (grant: Grant): Effect.Effect<void> =>
        Effect.gen(function* () {
          const fiber = yield* Effect.forkDaemon(
            Effect.sleep(Duration.millis(grantTtlMs)).pipe(
              Effect.flatMap(() => registry.markExpired(grant.grantId)),
              Effect.flatMap((marked) =>
                marked
                  ? Effect.flatMap(Ref.get(grantAudit), (ctxMap) =>
                      Effect.flatMap(
                        audit(
                          grant.request.agentId,
                          grant.request.alias,
                          grant.allowedScope,
                          "expired",
                          "grant expired before approval",
                          true,
                          undefined,
                          grantAuditExtras(ctxMap.get(grant.grantId)),
                        ),
                        () => forgetGrantAudit(grant.grantId),
                      ),
                    )
                  : Effect.void,
              ),
              Effect.ensuring(
                Ref.update(sleepers, (map) => {
                  const next = new Map(map);
                  next.delete(grant.grantId);
                  return next;
                }),
              ),
            ),
          );
          yield* Ref.update(sleepers, (map) => {
            const next = new Map(map);
            next.set(grant.grantId, fiber);
            return next;
          });
        });

      const decrypt = (ciphertext: string): Effect.Effect<string, StorageError> =>
        Effect.try({
          try: () => decryptSecret(masterKey, ciphertext),
          catch: () =>
            new StorageError({ message: "failed to decrypt credential", operation: "decrypt" }),
        });

      const executeGrant = (
        req: CapabilityRequest,
        allowedScope: string,
        ciphertext: string,
      ): Effect.Effect<unknown, ConnectorFailed | StorageError> =>
        Effect.flatMap(decrypt(ciphertext), (secret) =>
          connector.execute(req.alias, allowedScope, secret),
        );

      // Shared tail of approve / approve-always: consume the pending grant
      // exactly once, audit the human decision, execute inside the daemon.
      const consumeAndExecute = (
        grantId: string,
        auditDetail: string,
      ): Effect.Effect<
        { readonly status: "executed"; readonly result: unknown },
        GrantExpired | GrantRevoked | ConnectorFailed | StorageError
      > =>
        Effect.gen(function* () {
          const now = yield* Clock.currentTimeMillis;
          const auditCtx = (yield* Ref.get(grantAudit)).get(grantId);
          const consumed = yield* registry.consumeForExecution(grantId, now).pipe(
            Effect.catchTag("GrantExpired", (err) =>
              Effect.flatMap(registry.get(grantId), (grant) =>
                Effect.flatMap(
                  grant === undefined
                    ? Effect.void
                    : audit(
                        grant.request.agentId,
                        grant.request.alias,
                        grant.allowedScope,
                        "expired",
                        "grant expired or already consumed",
                        true,
                        undefined,
                        grantAuditExtras(auditCtx),
                      ),
                  () => Effect.fail(err),
                ),
              ),
            ),
          );
          yield* forgetDecision(grantId);
          yield* forgetGrantAudit(grantId);
          yield* interruptSleeper(grantId);
          const grantReq = consumed.request;
          yield* audit(grantReq.agentId, grantReq.alias, consumed.allowedScope, "approved", auditDetail, true, undefined, grantAuditExtras(auditCtx, "human"));
          const credential = yield* store.getCredential(grantReq.alias);
          if (credential === undefined) {
            return yield* Effect.fail(
              new StorageError({ message: "credential no longer exists", operation: "getCredential" }),
            );
          }
          const result = yield* executeGrant(grantReq, consumed.allowedScope, credential.ciphertext);
          yield* audit(grantReq.agentId, grantReq.alias, consumed.allowedScope, "executed", "executed", true, undefined, grantAuditExtras(auditCtx, "human"));
          return { status: "executed", result } as const;
        });

      const service: VaultServiceService = {
        seedCredential: (alias, ceiling, plaintextSecret, website, enrollmentId) =>
          alias === WARDEN_KEY_ALIAS
            ? Effect.fail(
                new StorageError({ message: "reserved alias", operation: "seedCredential" }),
              )
            : Effect.flatMap(Effect.sync(() => encryptSecret(masterKey, plaintextSecret)), (blob) =>
            Effect.flatMap(store.addCredential(alias, ceiling, blob, website ?? ""), () =>
              Effect.flatMap(
                Ref.update(aliases, (set) => {
                  const next = new Set(set);
                  next.add(alias);
                  return next;
                }),
                () =>
                  Effect.flatMap(
                    audit("human", alias, ceiling, "credential-added", `credential added: ${alias} (${ceiling})`, false),
                    () =>
                      enrollmentId === undefined
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
                          }),
                  ),
              ),
            ),
          ),

        createEnrollment: (alias, scope, website, reason) =>
          Effect.gen(function* () {
            if (alias === WARDEN_KEY_ALIAS) {
              return yield* Effect.fail(
                new StorageError({ message: "reserved alias", operation: "createEnrollment" }),
              );
            }
            const now = yield* Clock.currentTimeMillis;
            yield* purgeExpiredEnrollments(now);
            const enrollmentId = yield* Effect.sync(() => randomUUID());
            const record: EnrollmentRecord = { enrollmentId, alias, scope, website: website ?? "", status: "pending", expiresAtMs: now + enrollmentTtlMs };
            yield* Ref.update(enrollments, (map) => { const next = new Map(map); next.set(enrollmentId, record); return next; });
            const cappedReason = (reason ?? "").trim().slice(0, ENROLLMENT_REASON_MAX_LENGTH);
            yield* audit("agent", alias, scope, "enrollment-created", cappedReason === "" ? `enrollment created: ${alias}` : `enrollment created: ${alias}: ${cappedReason}`, false);
            return record;
          }),

        getEnrollment: (enrollmentId) =>
          Effect.gen(function* () {
            const now = yield* Clock.currentTimeMillis;
            yield* purgeExpiredEnrollments(now, enrollmentId);
            const record = (yield* Ref.get(enrollments)).get(enrollmentId);
            if (record === undefined) { return null; }
            if (record.status === "pending" && record.expiresAtMs <= now) { return { ...record, status: "expired" as const }; }
            return record;
          }),

        updateCredential: (alias, patch) =>
          Effect.gen(function* () {
            const existing = yield* store.getCredential(alias);
            if (existing === undefined) {
              return null;
            }
            const affected = yield* registry.revokePendingForAlias(alias);
            for (const grant of affected) {
              yield* forgetDecision(grant.grantId);
              yield* interruptSleeper(grant.grantId);
            }
            const scopeCeiling =
              patch.scope !== undefined && patch.scope.trim() !== "" ? patch.scope.trim() : existing.scopeCeiling;
            const website = patch.website !== undefined ? patch.website.trim() : existing.website;
            const ciphertext =
              patch.secret !== undefined && patch.secret.trim() !== ""
                ? yield* Effect.sync(() => encryptSecret(masterKey, patch.secret as string))
                : existing.ciphertext;
            yield* store.updateCredential(alias, scopeCeiling, ciphertext, website);
            return { scopeCeiling, website };
          }),

        deleteCredential: (alias) =>
          Effect.gen(function* () {
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

        listCredentialMeta: () =>
          Effect.map(store.listCredentials(), (metas) =>
            metas.filter((m) => m.alias !== WARDEN_KEY_ALIAS),
          ),

        requestCapability: (req) =>
          Effect.gen(function* () {
            const now = yield* Clock.currentTimeMillis;
            const storedCredential = yield* store.getCredential(req.alias);
            const credential = req.alias === WARDEN_KEY_ALIAS ? undefined : storedCredential;
            const auditEvents = yield* store.listAudit();
            const requestId = yield* Effect.sync(() => randomUUID());
            yield* audit(req.agentId, req.alias, req.requestedScope, "requested", "capability requested", false, undefined, { requestId });

            if (yield* registry.isRevoked(req.agentId, req.alias)) {
              yield* audit(req.agentId, req.alias, req.requestedScope, "denied", "revoked", true, undefined, { requestId, decisionSource: "policy" });
              return { status: "denied", reason: "revoked" } as const;
            }
            const agentEvents = auditEvents.filter((e) => e.agentId === req.agentId);
            const within = (e: AuditEvent, windowMs: number) => now - Date.parse(e.ts) < windowMs;
            const historyCount = agentEvents.filter(
              (e) => e.stage === "requested" && within(e, HOUR_MS),
            ).length;
            const historySummary = {
              requests24h: agentEvents.filter(
                (e) => e.stage === "requested" && within(e, DAY_MS),
              ).length,
              denials24h: agentEvents.filter((e) => e.stage === "denied" && within(e, DAY_MS))
                .length,
            };

            const ceilings: Record<string, string> =
              credential === undefined ? {} : { [req.alias]: credential.scopeCeiling };
            const standingNow = yield* Ref.get(standing);
            const cfg: PolicyConfig = { ceilings, standingApprovals: standingNow, rateLimitPerHour };

            // Policy pre-check: unknown alias / rate limit deny before the marshal runs.
            const preCheck = evaluatePolicy(req, null, cfg, historyCount);
            if (credential === undefined || preCheck.allowedScope === null) {
              const reason = credential === undefined ? "unknown-alias" : preCheck.reason;
              yield* audit(req.agentId, req.alias, req.requestedScope, "policy", reason, true, undefined, { requestId, decisionSource: "policy" });
              yield* audit(req.agentId, req.alias, req.requestedScope, "denied", reason, true, undefined, { requestId, decisionSource: "policy" });
              return { status: "denied", reason } as const;
            }
            yield* Ref.update(aliases, (set) => {
              const next = new Set(set);
              next.add(req.alias);
              return next;
            });

            const policyDigest = `${req.alias} ceiling=${credential.scopeCeiling}`;
            // The ONLY place marshal errors are absorbed: recovered to a null
            // decision for evaluatePolicy, with an audit event saying so.
            const wardenSettings = yield* store.getWardenSettings();
            const marshalModelId =
              wardenSettings.model.trim() !== "" ? wardenSettings.model : modelId;
            let decision: MarshalDecision | null = null;
            let latencyMs: number | undefined;
            if (wardenSettings.provider !== "none") {
              const assessStarted = yield* Clock.currentTimeMillis;
              const assessExit = yield* Effect.exit(
                brain.assess(req, historySummary, policyDigest),
              );
              const assessEnded = yield* Clock.currentTimeMillis;
              latencyMs = Math.max(0, assessEnded - assessStarted);
              if (Exit.isSuccess(assessExit)) {
                decision = assessExit.value;
                yield* audit(
                  req.agentId,
                  req.alias,
                  req.requestedScope,
                  "marshal",
                  "marshal decision",
                  true,
                  marshalModelId,
                  {
                    requestId,
                    risk: decision.risk,
                    recommendedScope: decision.recommendedScope,
                    decisionSource: "marshal",
                    latencyMs,
                    explanation: decision.explanation,
                  },
                );
              } else {
                const failure = Cause.failureOption(assessExit.cause);
                if (failure._tag === "None") {
                  return yield* Effect.die(Cause.squash(assessExit.cause));
                }
                const tag = failure.value._tag;
                yield* audit(
                  req.agentId,
                  req.alias,
                  req.requestedScope,
                  "marshal",
                  tag === "MarshalInvalidOutput"
                    ? "marshal invalid output; recovered to null decision"
                    : "marshal unavailable; recovered to null decision",
                  true,
                  marshalModelId,
                  { requestId, decisionSource: "marshal", latencyMs },
                );
              }
            }
            const finalDecisionSource: AuditEvent["decisionSource"] =
              decision !== null ? "marshal+policy" : "policy";

            const result = evaluatePolicy(req, decision, cfg, historyCount);
            yield* audit(
              req.agentId,
              req.alias,
              result.allowedScope ?? req.requestedScope,
              "policy",
              result.reason,
              true,
              marshalModelId,
              decision === null
                ? { requestId, decisionSource: finalDecisionSource }
                : {
                    requestId,
                    decisionSource: finalDecisionSource,
                    risk: decision.risk,
                    recommendedScope: decision.recommendedScope,
                  },
            );
            if (result.allowedScope === null) {
              yield* audit(req.agentId, req.alias, req.requestedScope, "denied", result.reason, true, marshalModelId, { requestId, decisionSource: finalDecisionSource });
              return { status: "denied", reason: result.reason } as const;
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
              yield* Ref.update(grantAudit, (map) => {
                const next = new Map(map);
                next.set(grantId, { requestId, decisionSource: finalDecisionSource });
                return next;
              });
              yield* scheduleExpiry(grant);
              return { status: "awaiting-approval", grantId, reason: result.reason } as const;
            }

            yield* audit(req.agentId, req.alias, allowedScope, "approved", "auto-approved by policy", true, marshalModelId, { requestId, decisionSource: finalDecisionSource });
            const exit = yield* Effect.exit(executeGrant(req, allowedScope, credential.ciphertext));
            if (Exit.isFailure(exit)) {
              yield* audit(req.agentId, req.alias, allowedScope, "executed", "connector-failed", true, marshalModelId, { requestId, decisionSource: finalDecisionSource });
              return { status: "denied", reason: "connector-failed" } as const;
            }
            yield* audit(req.agentId, req.alias, allowedScope, "executed", "executed", true, marshalModelId, { requestId, decisionSource: finalDecisionSource });
            return { status: "executed", result: exit.value, reason: result.reason } as const;
          }),

        approve: (grantId) => consumeAndExecute(grantId, "approved by human"),

        approveAlways: (grantId) =>
          Effect.gen(function* () {
            const grant = yield* registry.get(grantId);
            if (grant === undefined || grant.status !== "pending") {
              return yield* Effect.fail(
                new GrantExpired({ grantId, message: "grant not found or already consumed" }),
              );
            }
            const decision = (yield* Ref.get(decisions)).get(grantId) ?? null;
            // Standing approvals are only ever created for read-only scopes
            // the marshal rated low-risk — re-checked here, server-side, so
            // no client can widen them. Writes ask every time.
            if (decision === null || decision.risk !== "low" || isWriteScope(grant.allowedScope)) {
              return yield* Effect.fail(
                new PolicyDenied({
                  message: "always-allow requires a read-only low-risk grant",
                  reason: "always-allow-not-eligible",
                  alias: grant.request.alias,
                  scope: grant.allowedScope,
                }),
              );
            }
            // Execute first: the standing approval is recorded only after a
            // successful execution, so a grant that expires (or whose
            // connector call fails) in between leaves no standing approval
            // behind for an execution that never happened.
            const auditCtx = (yield* Ref.get(grantAudit)).get(grantId);
            const executed = yield* consumeAndExecute(grantId, "approved by human (always allow)");
            yield* Ref.update(standing, (list) => {
              const exists = list.some(
                (entry) =>
                  entry.agentId === grant.request.agentId &&
                  entry.alias === grant.request.alias &&
                  entry.scope === grant.allowedScope,
              );
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
            yield* audit(
              grant.request.agentId,
              grant.request.alias,
              grant.allowedScope,
              "approved",
              "standing approval created (always allow)",
              true,
              undefined,
              grantAuditExtras(auditCtx, "human"),
            );
            return executed;
          }),

        deny: (grantId) =>
          Effect.gen(function* () {
            const denied = yield* registry.markDenied(grantId);
            if (!denied) {
              return;
            }
            const auditCtx = (yield* Ref.get(grantAudit)).get(grantId);
            yield* forgetDecision(grantId);
            yield* forgetGrantAudit(grantId);
            yield* interruptSleeper(grantId);
            const grant = yield* registry.get(grantId);
            if (grant !== undefined) {
              yield* audit(grant.request.agentId, grant.request.alias, grant.allowedScope, "denied", "denied by human", true, undefined, grantAuditExtras(auditCtx, "human"));
            }
          }),

        revoke: (agentIdOrAlias) =>
          Effect.gen(function* () {
            const affected = yield* registry.revokePendingFor(agentIdOrAlias);
            for (const grant of affected) {
              const auditCtx = (yield* Ref.get(grantAudit)).get(grant.grantId);
              yield* forgetDecision(grant.grantId);
              yield* forgetGrantAudit(grant.grantId);
              yield* interruptSleeper(grant.grantId);
              yield* audit(grant.request.agentId, grant.request.alias, grant.allowedScope, "revoked", `revoked: ${agentIdOrAlias}`, true, undefined, grantAuditExtras(auditCtx));
            }
            if (affected.length === 0) {
              yield* audit(agentIdOrAlias, agentIdOrAlias, "", "revoked", `revoked: ${agentIdOrAlias}`, true);
            }
          }),

        hasCredential: (alias) =>
          Effect.map(store.getCredential(alias), (credential) => credential !== undefined),

        // Aliases live in the vault DB (the CLI enrolls credentials there
        // directly); the in-memory set only mirrors this process's activity.
        listAliases: () =>
          Effect.flatMap(store.listCredentialAliases(), (fromDb) =>
            Ref.get(aliases).pipe(
              Effect.map((seen) =>
                [...new Set([...fromDb, ...seen])].filter((a) => a !== WARDEN_KEY_ALIAS).sort(),
              ),
            ),
          ),
        listAudit: () => store.listAudit(),
        listPendingApprovals: () =>
          Effect.gen(function* () {
            const now = yield* Clock.currentTimeMillis;
            const grants = yield* registry.listGrants();
            const wardenSettings = yield* store.getWardenSettings();
            const pendingModelId =
              wardenSettings.provider !== "none" && wardenSettings.model.trim() !== ""
                ? wardenSettings.model
                : modelId;
            const decisionMap = yield* Ref.get(decisions);
            const pending: PendingApproval[] = [];
            for (const grant of grants) {
              if (grant.status !== "pending" || grant.expiresAtMs <= now) {
                continue;
              }
              const decision = decisionMap.get(grant.grantId) ?? null;
              const base: PendingApproval = {
                grantId: grant.grantId,
                agentId: grant.request.agentId,
                ide: grant.request.ide,
                tool: grant.request.tool,
                alias: grant.request.alias,
                requestedScope: grant.request.requestedScope,
                allowedScope: grant.allowedScope,
                reason: grant.request.reason,
                risk: decision?.risk ?? "medium",
                marshalExplanation:
                  decision?.explanation ??
                  "Marshal unavailable — deterministic policy requires your approval.",
                createdAtMs: grant.createdAtMs,
                expiresAtMs: grant.expiresAtMs,
              };
              pending.push({ ...base, modelId: pendingModelId });
            }
            pending.sort((a, b) => a.createdAtMs - b.createdAtMs);
            return pending;
          }),
        // Real policy state for the Policies view: the enforced ceiling for
        // every enrolled alias (read back from the vault, never inferred
        // from audit) plus the standing approvals currently in force.
        getWardenSettings: () => store.getWardenSettings(),

        updateWardenSettings: (patch) =>
          Effect.gen(function* () {
            const current = yield* store.getWardenSettings();
            const next: WardenSettings = {
              provider: patch.provider ?? current.provider,
              model: patch.model !== undefined ? patch.model.trim() : current.model,
              effort: patch.effort ?? current.effort,
              metaApiBaseUrl:
                patch.metaApiBaseUrl !== undefined
                  ? patch.metaApiBaseUrl.trim()
                  : current.metaApiBaseUrl,
            };
            yield* store.setWardenSettings(next);
            if (
              patch.provider !== undefined ||
              patch.model !== undefined ||
              patch.effort !== undefined ||
              patch.metaApiBaseUrl !== undefined
            ) {
              yield* audit(
                "human",
                "warden",
                "",
                "settings-changed",
                `warden settings changed: provider=${next.provider} model=${next.model}`,
                false,
              );
            }
            return next;
          }),

        setWardenKey: (key) =>
          Effect.gen(function* () {
            const trimmed = key.trim();
            if (trimmed.length < WARDEN_KEY_MIN_LENGTH) {
              return yield* Effect.fail(
                new StorageError({ message: "warden key too short", operation: "setWardenKey" }),
              );
            }
            const blob = yield* Effect.sync(() => encryptSecret(masterKey, trimmed));
            yield* store.addCredential(WARDEN_KEY_ALIAS, WARDEN_KEY_SCOPE, blob, "");
            return { configured: true, last4: trimmed.slice(-4) } as const;
          }),

        deleteWardenKey: () =>
          Effect.gen(function* () {
            yield* store.deleteCredential(WARDEN_KEY_ALIAS);
            return { configured: false, last4: null } as const;
          }),

        wardenKeyStatus: () =>
          Effect.gen(function* () {
            const credential = yield* store.getCredential(WARDEN_KEY_ALIAS);
            if (credential === undefined) {
              return { configured: false, last4: null } as const;
            }
            const plain = yield* decrypt(credential.ciphertext).pipe(
              Effect.catchAll(() => Effect.succeed("")),
            );
            return {
              configured: true,
              last4: plain.length > 4 ? plain.slice(-4) : null,
            } as const;
          }),

        listPolicies: () =>
          Effect.gen(function* () {
            const credentialAliases = (yield* store.listCredentialAliases()).filter(
              (a) => a !== WARDEN_KEY_ALIAS,
            );
            const ceilings: Record<string, string> = {};
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
              .sort(
                (a, b) =>
                  a.agentId.localeCompare(b.agentId) ||
                  a.alias.localeCompare(b.alias) ||
                  a.scope.localeCompare(b.scope),
              );
            return { ceilings, standingApprovals };
          }),
      };
      return service;
    }),
  );
}

export const VaultServiceLive: Layer.Layer<VaultService, never, VaultStore | Brain | Connector> =
  makeVaultServiceLive();
