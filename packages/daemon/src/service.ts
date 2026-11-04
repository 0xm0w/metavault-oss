import { createHash, randomBytes, randomInt, randomUUID, timingSafeEqual } from "node:crypto";
import { Cause, Clock, Context, Duration, Effect, Exit, Fiber, Layer, Ref } from "effect";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { decryptSecret, encryptSecret } from "../../core/src/crypto.js";
import {
  CARD_KIND,
  DEFAULT_CARD_SCOPE,
  isCardSecretPayload,
  parseCardInput,
  parseCardPublicMeta,
  serializeCardSecret,
  type CardInput,
  type CardPublicMeta,
  type CredentialKind,
} from "../../core/src/card.js";
import {
  createKeySession,
  envMasterKeyIfAllowed,
  VaultLockedError,
  type KeySession,
  type KeySessionStatus,
  type SetupResult,
  type UnlockResult,
} from "../../core/src/key-session.js";
import {
  ConnectorFailed,
  GrantExpired,
  GrantRevoked,
  PolicyDenied,
  PairingNotConfirmable,
  PresenceRequired,
  StorageError,
} from "../../core/src/errors.js";
import { createGrant, makeGrantRegistry, type Grant } from "../../core/src/grants.js";
import {
  escalateFinancialDecision,
  evaluatePolicy,
  isAgentRateLimited,
  isWriteScope,
  recordAgentRequest,
  type AgentVelocityTracker,
  type PolicyConfig,
} from "../../core/src/policy.js";
import { calculateSecurityPosture, type SecurityPostureReport } from "../../core/src/posture.js";
import {
  WARDEN_KEY_ALIAS,
  WARDEN_KEY_MIN_LENGTH,
  WARDEN_KEY_SCOPE,
  generatePinSalt,
  hashPin,
  DEFAULT_META_API_WARDEN_MODEL,
  effectiveWardenModel,
  verifyPin,
  type AgentSecuritySettings,
  type LocalAuthStatus,
  type WardenKeyStatus,
  type WardenSettings,
} from "../../core/src/settings.js";
import { VaultStore, type AgentRecord, type DeviceAliasPolicy, type DeviceRecord } from "../../core/src/storage.js";
import { ensureVaultCa, signLeafCertificate, spkiFingerprintFromPublicKeyPem, type VaultCa } from "../../core/src/vault-ca.js";
import type { AuditEvent, CapabilityRequest, MarshalDecision } from "../../core/src/types.js";

export interface CapabilityResult {
  readonly status: "executed" | "awaiting-approval" | "denied";
  readonly grantId?: string;
  readonly result?: unknown;
  readonly reason?: string;
}

// Channel metadata the daemon trusts only when it arrives with the
// loopback gateway secret. Remote agents never set this themselves.
export interface RemoteRequestContext {
  readonly deviceId: string;
  readonly transport: string;
}

export interface RemoteSettings {
  readonly enabled: boolean;
  readonly host: string;
  readonly port: number;
  readonly requireAuthForRemoteApproval: boolean;
}

export const DEFAULT_REMOTE_SETTINGS: RemoteSettings = {
  enabled: false,
  host: "127.0.0.1",
  port: 7078,
  requireAuthForRemoteApproval: true,
};

export type PairingStatus = "waiting" | "joined" | "confirmed" | "failed";

// What the app may display about an in-flight pairing. The code is shown
// only while the session waits for a device to join; the SAS is shown once
// a device has joined so the human can compare both screens.
export interface PairingSessionView {
  readonly pairingId: string;
  readonly status: PairingStatus;
  readonly expiresAtMs: number;
  readonly code?: string;
  readonly deviceName?: string;
  readonly platform?: string;
  readonly sas?: string;
  readonly deviceId?: string;
}

export interface PairBeginInput {
  readonly code: string;
  readonly deviceName: string;
  readonly platform: string;
  readonly clientPublicKeyPem: string;
  readonly clientNonce: string;
}

export type PairBeginError =
  | "pairing-unavailable"
  | "pairing-code-invalid"
  | "pairing-key-invalid"
  | "pairing-expired";

export interface PairBeginResult {
  readonly pairingId: string;
  readonly serverNonce: string;
}

export interface PairingInternalStatus {
  readonly status: PairingStatus | "unknown";
  readonly certificatePem?: string;
  readonly caCertPem?: string;
}

const PAIRING_TTL_MS = 5 * 60 * 1000;
const PAIRING_MAX_FAILED_ATTEMPTS = 5;
const PAIRING_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

interface PairingSession {
  readonly pairingId: string;
  readonly code: string;
  readonly codeHash: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly failedAttempts: number;
  readonly status: PairingStatus;
  readonly serverNonce: string;
  readonly clientNonce?: string;
  readonly deviceName?: string;
  readonly platform?: string;
  readonly clientPublicKeyPem?: string;
  readonly clientFingerprint?: string;
  readonly sas?: string;
  readonly deviceId?: string;
  readonly certificatePem?: string;
}

function hashPairingCode(code: string): string {
  return createHash("sha256").update(code.trim().toUpperCase(), "utf8").digest("hex");
}

function generatePairingCode(): string {
  // randomInt is uniform over the alphabet; a modulo of raw bytes is not.
  let out = "";
  for (let i = 0; i < 8; i += 1) out += PAIRING_CODE_ALPHABET[randomInt(PAIRING_CODE_ALPHABET.length)] ?? "";
  return out;
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
  readonly verified?: boolean;
  // Remote origin banner data: set when the request arrived via a paired
  // device through the gateway.
  readonly deviceId?: string;
  readonly origin?: "local" | "remote";
  readonly transport?: string;
  readonly clientPid?: number | undefined;
  readonly clientProcess?: string | undefined;
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
  readonly agents?: readonly AgentRecord[];
}

export { WARDEN_KEY_ALIAS, WARDEN_KEY_MIN_LENGTH, WARDEN_KEY_SCOPE };
export type { WardenKeyStatus, WardenSettings };

export type WardenSettingsPatch = Partial<WardenSettings>;

// Fixed, secret-free failure reasons for the warden self-check. Only these
// strings ever leave the daemon: never a response body, header, or key part.
export const WARDEN_TEST_REASONS = [
  "no_key",
  "vault_locked",
  "key_unreadable",
  "unauthorized",
  "rate_limited",
  "bad_request",
  "http_error",
  "timeout",
  "network",
  "bad_response",
  "unavailable",
] as const;
export type WardenTestReason = (typeof WARDEN_TEST_REASONS)[number];

export interface WardenTestResult {
  readonly ok: boolean;
  readonly provider: WardenSettings["provider"];
  readonly model: string;
  readonly latencyMs: number;
  readonly detail: string;
  readonly reason?: WardenTestReason;
}

// Maps the fixed MarshalUnavailable/MarshalInvalidOutput messages raised by
// the brain providers to a reason. Reads only the status code and fixed
// phrases, so a message that happens to carry a secret cannot leak through.
export function classifyWardenFailure(message: string): WardenTestReason {
  if (message.includes("key not configured")) return "no_key";
  const http = /returned HTTP (\d{3})/.exec(message);
  if (http?.[1] !== undefined) {
    const status = Number(http[1]);
    if (status === 401 || status === 403) return "unauthorized";
    if (status === 429) return "rate_limited";
    if (status === 400 || status === 404) return "bad_request";
    return "http_error";
  }
  if (message.includes("timed out")) return "timeout";
  if (message.includes("request to Meta API failed")) return "network";
  if (message.includes("MarshalInvalidOutput")) return "bad_response";
  return "unavailable";
}

export const WARDEN_SELFCHECK_REQUEST: CapabilityRequest = {
  agentId: "metavault-selfcheck",
  ide: "MetaVault OSS",
  tool: "selfcheck",
  alias: "selfcheck",
  requestedScope: "selfcheck.read",
  reason: "warden connection test",
};

export type EnrollmentStatusValue = "pending" | "completed" | "expired";
export interface EnrollmentRecord {
  readonly enrollmentId: string;
  readonly alias: string;
  readonly scope: string;
  readonly website: string;
  readonly status: EnrollmentStatusValue;
  readonly expiresAtMs: number;
  readonly agentId?: string;
}

// What callers outside the daemon may see about a stored credential.
export interface PublicCredentialMeta {
  readonly alias: string;
  readonly scopeCeiling: string;
  readonly website: string;
  readonly kind: CredentialKind;
  readonly card?: CardPublicMeta;
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
    agentId?: string,
  ) => Effect.Effect<EnrollmentRecord, StorageError>;
  readonly getEnrollment: (
    enrollmentId: string,
  ) => Effect.Effect<EnrollmentRecord | null, StorageError>;
  readonly updateCredential: (
    alias: string,
    patch: { readonly scope?: string; readonly website?: string; readonly secret?: string },
  ) => Effect.Effect<{ readonly scopeCeiling: string; readonly website: string } | null, StorageError>;
  readonly deleteCredential: (alias: string) => Effect.Effect<boolean, StorageError>;
  readonly listCredentialMeta: () => Effect.Effect<readonly PublicCredentialMeta[], StorageError>;
  // Payment card: validated (Luhn, expiry, CVV), stored encrypted as one
  // blob. Only brand + last 4 are returned or ever listed.
  readonly seedCardCredential: (
    alias: string,
    card: CardInput,
    scope?: string,
    website?: string,
  ) => Effect.Effect<CardPublicMeta, StorageError>;
  readonly keyStatus: () => Effect.Effect<KeySessionStatus>;
  readonly unlockVault: (passphrase: string) => Effect.Effect<UnlockResult, StorageError>;
  readonly lockVault: () => Effect.Effect<void>;
  // First-run only: create, wrap and store a new master key.
  readonly setupVault: (passphrase: string) => Effect.Effect<SetupResult | "not-supported", StorageError>;
  readonly requestCapability: (
    req: CapabilityRequest,
    agentToken?: string,
    deviceCtx?: RemoteRequestContext,
  ) => Effect.Effect<CapabilityResult, StorageError>;
  readonly approve: (
    grantId: string,
    presenceProof?: string,
  ) => Effect.Effect<
    { readonly status: "executed"; readonly result: unknown },
    GrantExpired | GrantRevoked | ConnectorFailed | PresenceRequired | StorageError
  >;
  readonly deny: (grantId: string) => Effect.Effect<void, StorageError>;
  readonly approveAlways: (
    grantId: string,
    presenceProof?: string,
  ) => Effect.Effect<
    { readonly status: "executed"; readonly result: unknown },
    GrantExpired | GrantRevoked | PolicyDenied | ConnectorFailed | PresenceRequired | StorageError
  >;
  readonly revoke: (agentIdOrAlias: string) => Effect.Effect<void, StorageError>;
  readonly hasCredential: (alias: string) => Effect.Effect<boolean, StorageError>;
  readonly listAliases: () => Effect.Effect<string[], StorageError>;
  readonly listAudit: () => Effect.Effect<AuditEvent[], StorageError>;
  readonly listPendingApprovals: () => Effect.Effect<PendingApproval[], StorageError>;
  readonly listPolicies: () => Effect.Effect<PoliciesState, StorageError>;
  readonly listAgents: () => Effect.Effect<AgentRecord[], StorageError>;
  readonly getAgentByToken: (token: string) => Effect.Effect<AgentRecord | undefined, StorageError>;
  readonly registerAgent: (id: string, name: string, rotate?: boolean, deviceId?: string) => Effect.Effect<AgentRecord, StorageError>;
  readonly revokeAgentToken: (id: string) => Effect.Effect<void, StorageError>;
  readonly listDevices: () => Effect.Effect<DeviceRecord[], StorageError>;
  readonly getDeviceByFingerprint: (fingerprint: string) => Effect.Effect<DeviceRecord | undefined, StorageError>;
  readonly renameDevice: (id: string, name: string) => Effect.Effect<void, StorageError>;
  readonly revokeDevice: (id: string) => Effect.Effect<void, StorageError>;
  readonly listDeviceAliasPolicies: (deviceId: string) => Effect.Effect<DeviceAliasPolicy[], StorageError>;
  readonly setDeviceAliasPolicy: (deviceId: string, alias: string, allowWrite: boolean) => Effect.Effect<void, StorageError>;
  readonly getRemoteSettings: () => Effect.Effect<RemoteSettings, StorageError>;
  readonly updateRemoteSettings: (patch: Partial<RemoteSettings>, presenceProof?: string) => Effect.Effect<RemoteSettings, PresenceRequired | StorageError>;
  readonly createPairingSession: () => Effect.Effect<PairingSessionView, StorageError>;
  readonly getPairingSession: () => Effect.Effect<PairingSessionView | undefined, StorageError>;
  readonly cancelPairingSession: (pairingId: string) => Effect.Effect<void, StorageError>;
  readonly pairBegin: (input: PairBeginInput) => Effect.Effect<PairBeginResult, PairBeginError | StorageError>;
  readonly attachPairingSas: (pairingId: string, sas: string) => Effect.Effect<void, StorageError>;
  readonly confirmPairing: (pairingId: string) => Effect.Effect<{ deviceId: string; certFingerprint: string }, PairingNotConfirmable | StorageError>;
  readonly pairingInternalStatus: (pairingId: string) => Effect.Effect<PairingInternalStatus, StorageError>;
  // True only while a live, unconfirmed, unexpired pairing session exists.
  readonly pairingOpen: () => Effect.Effect<{ readonly open: boolean }, StorageError>;
  readonly getAgentSecuritySettings: () => Effect.Effect<AgentSecuritySettings, StorageError>;
  readonly updateAgentSecuritySettings: (
    patch: { readonly strictMode?: boolean | undefined; readonly verifyCallerProcess?: boolean | undefined },
  ) => Effect.Effect<AgentSecuritySettings, StorageError>;
  readonly getWardenSettings: () => Effect.Effect<WardenSettings, StorageError>;
  readonly updateWardenSettings: (
    patch: WardenSettingsPatch,
  ) => Effect.Effect<WardenSettings, StorageError>;
  readonly setWardenKey: (key: string) => Effect.Effect<WardenKeyStatus, StorageError>;
  readonly deleteWardenKey: () => Effect.Effect<WardenKeyStatus, StorageError>;
  readonly wardenKeyStatus: () => Effect.Effect<WardenKeyStatus, StorageError>;
  readonly testWarden: () => Effect.Effect<WardenTestResult, StorageError>;
    readonly getLocalAuthStatus: () => Effect.Effect<LocalAuthStatus, StorageError>;
  readonly updateLocalAuthSettings: (patch: {
    readonly enabled?: boolean;
    readonly biometricEnabled?: boolean;
    readonly requireOnApproval?: boolean;
    readonly requireOnLaunch?: boolean;
    readonly requireOnSettings?: boolean;
    readonly autoLockMinutes?: number;
  }) => Effect.Effect<LocalAuthStatus, StorageError>;
  readonly setLocalPin: (
    pin: string,
    currentPin?: string,
  ) => Effect.Effect<{ readonly ok: boolean }, StorageError>;
  readonly verifyLocalPin: (pin: string) => Effect.Effect<{ readonly ok: boolean; readonly presenceProof?: string }, StorageError>;
  readonly verifyBiometric: () => Effect.Effect<{ readonly ok: boolean }, StorageError>;
  readonly getSecurityPosture: () => Effect.Effect<SecurityPostureReport, StorageError>;
}

export class VaultService extends Context.Tag("VaultService")<VaultService, VaultServiceService>() {}

export interface VaultServiceOptions {
  // An always-unlocked key (tests, embedded use). Production daemons pass
  // keySession instead so the key can be locked and re-unlocked.
  readonly masterKey?: Buffer;
  readonly keySession?: KeySession;
  readonly grantTtlMs?: number;
  readonly rateLimitPerHour?: number;
  readonly standingApprovals?: PolicyConfig["standingApprovals"];
  readonly modelId?: string;
  readonly enrollmentTtlMs?: number;
  // Where vault-CA and gateway certificate files live (usually the DB's
  // directory). Pairing confirmation signs device certs with this CA.
  // Tests may inject vaultCa directly to skip the filesystem.
  readonly vaultDir?: string;
  readonly vaultCa?: VaultCa;
}

export const DEFAULT_ENROLLMENT_TTL_MS = 600_000;
export const ENROLLMENT_REASON_MAX_LENGTH = 256;
export const MAX_PENDING_ENROLLMENTS = 100;

const DEFAULT_GRANT_TTL_MS = 60_000;
const DEFAULT_RATE_LIMIT_PER_HOUR = 20;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

function resolveKeySession(options: VaultServiceOptions): KeySession {
  if (options.keySession !== undefined) return options.keySession;
  if (options.masterKey !== undefined) {
    if (options.masterKey.length !== 32) {
      throw new Error("masterKey must be 32 bytes");
    }
    return createKeySession({ mode: "injected", key: options.masterKey });
  }
  const fromEnv = envMasterKeyIfAllowed();
  if (fromEnv !== undefined) return createKeySession({ mode: "env", key: fromEnv });
  // Ephemeral key: nothing persisted can be decrypted after restart.
  return createKeySession({ mode: "injected", key: randomBytes(32) });
}

export const VAULT_LOCKED_OPERATION = "locked";
export const CARD_INVALID_OPERATION = "card-invalid";

function lockedError(): StorageError {
  return new StorageError({ message: "VaultLocked: vault is locked; unlock it with your passphrase", operation: VAULT_LOCKED_OPERATION });
}

export function makeVaultServiceLive(
  options: VaultServiceOptions = {},
): Layer.Layer<VaultService, never, VaultStore | Brain | Connector> {
  const grantTtlMs = options.grantTtlMs ?? DEFAULT_GRANT_TTL_MS;
  const rateLimitPerHour = options.rateLimitPerHour ?? DEFAULT_RATE_LIMIT_PER_HOUR;
  const initialStandingApprovals = options.standingApprovals ?? [];
  const modelId = options.modelId ?? DEFAULT_META_API_WARDEN_MODEL;
  const enrollmentTtlMs = options.enrollmentTtlMs ?? DEFAULT_ENROLLMENT_TTL_MS;

  return Layer.effect(
    VaultService,
    Effect.gen(function* () {
      const store = yield* VaultStore;
      const brain = yield* Brain;
      const connector = yield* Connector;
      const keySession = yield* Effect.sync(() => resolveKeySession(options));
      // Every use of the master key goes through the session, so a locked
      // (or auto-locked) vault fails closed with VaultLocked.
      const withKey = <A>(f: (key: Buffer) => A): Effect.Effect<A, StorageError> =>
        Effect.try({
          try: () => f(keySession.key()),
          catch: (err) =>
            err instanceof VaultLockedError
              ? lockedError()
              : new StorageError({ message: "key operation failed", operation: "crypto" }),
        });
      const registry = yield* makeGrantRegistry();
      const agentEpoch = new Map<string, number>();
      const agentManagement = yield* Effect.makeSemaphore(1);
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
      const agentVelocities = yield* Ref.make(new Map<string, AgentVelocityTracker>());
      // At most one pairing session exists; starting a new one kills the
      // old. In-memory only: pairing state never persists across restarts.
      const pairing = yield* Ref.make<PairingSession | undefined>(undefined);
      // Daemon-issued local-presence proofs: single-use, 60s TTL, minted
      // only by a real PIN verification (or an attested Hello). Required
      // to approve remote-origin grants when the setting is on.
      const presenceProofs = yield* Ref.make(new Map<string, number>());
      const PRESENCE_PROOF_TTL_MS = 60_000;
      const mintPresenceProof = () : Effect.Effect<string> =>
        Effect.gen(function* () {
          const now = yield* Clock.currentTimeMillis;
          const token = randomBytes(24).toString("hex");
          yield* Ref.update(presenceProofs, (proofs) => {
            const next = new Map<string, number>();
            for (const [t, exp] of proofs) {
              if (exp > now) next.set(t, exp);
            }
            next.set(token, now + PRESENCE_PROOF_TTL_MS);
            return next;
          });
          return token;
        });
      const consumePresenceProof = (token: string | undefined): Effect.Effect<boolean> =>
        Effect.gen(function* () {
          if (token === undefined || token === "") return false;
          const now = yield* Clock.currentTimeMillis;
          const proofs = yield* Ref.get(presenceProofs);
          const exp = proofs.get(token);
          if (exp === undefined) return false;
          yield* Ref.update(presenceProofs, (current) => {
            const next = new Map(current);
            next.delete(token);
            return next;
          });
          return exp > now;
        });
      // Remote-origin approvals require fresh local presence at the DAEMON
      // boundary: any caller - app main or another daemon-token holder -
      // must present a proof minted by a real verification moments ago.
      // Origin is provenance-bound (gateway stamps), never client-supplied.
      const requirePresenceForRemoteApproval = (
        grantId: string,
        presenceProof: string | undefined,
      ): Effect.Effect<void, PresenceRequired | StorageError> =>
        Effect.gen(function* () {
          const grant = yield* registry.get(grantId);
          if (grant === undefined || grant.request.origin !== "remote") return;
          const remote = yield* store.getRemoteSettingsRow();
          if (!remote.requireAuthForRemoteApproval) return;
          const ok = yield* consumePresenceProof(presenceProof);
          if (!ok) {
            return yield* Effect.fail(
              new PresenceRequired({ message: "remote approval requires fresh local presence (PIN or Windows Hello)", grantId }),
            );
          }
        });
      let injectedCa: VaultCa | undefined = options.vaultCa;
      const vaultDir = options.vaultDir;
      const loadVaultCa = (): Effect.Effect<VaultCa, StorageError> =>
        Effect.try({
          try: () => {
            if (injectedCa !== undefined) return injectedCa;
            if (vaultDir === undefined) {
              throw new Error("vault directory unavailable");
            }
            const ca = ensureVaultCa(vaultDir);
            injectedCa = ca;
            return ca;
          },
          catch: (err) => new StorageError({ message: `vault CA unavailable: ${err instanceof Error ? err.message : "unknown"}`, operation: "pairing" }),
        });

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
          Pick<AuditEvent, "requestId" | "risk" | "recommendedScope" | "decisionSource" | "latencyMs" | "explanation" | "verified" | "deviceId" | "origin" | "transport">
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
                          false,
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
          try: () => decryptSecret(keySession.key(), ciphertext),
          catch: (err) =>
            err instanceof VaultLockedError
              ? lockedError()
              : new StorageError({ message: "failed to decrypt credential", operation: "decrypt" }),
        });

      const executeGrant = (
        req: CapabilityRequest,
        allowedScope: string,
        ciphertext: string,
      ): Effect.Effect<unknown, ConnectorFailed | StorageError> =>
        Effect.flatMap(decrypt(ciphertext), (secret) =>
          // No payment connector ships. A decrypted card never reaches the
          // generic HTTP connector (which would put it in a header).
          isCardSecretPayload(secret)
            ? Effect.fail(
                new ConnectorFailed({
                  message: "no payment connector is configured for card credentials",
                  alias: req.alias,
                }),
              )
            : connector.execute(req.alias, allowedScope, secret),
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
                        false,
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
          const epoch = agentEpoch.get(grantReq.agentId) ?? 0;
          yield* audit(grantReq.agentId, grantReq.alias, consumed.allowedScope, "approved", auditDetail, false, undefined, grantAuditExtras(auditCtx, "human"));
          const credential = yield* store.getCredential(grantReq.alias);
          if (credential === undefined) {
            return yield* Effect.fail(
              new StorageError({ message: "credential no longer exists", operation: "getCredential" }),
            );
          }
          if ((agentEpoch.get(grantReq.agentId) ?? 0) !== epoch) return yield* Effect.fail(new GrantRevoked({grantId}));
          const execExit = yield* Effect.exit(executeGrant(grantReq, consumed.allowedScope, credential.ciphertext));
          if (Exit.isFailure(execExit)) {
            yield* audit(grantReq.agentId, grantReq.alias, consumed.allowedScope, "denied", "connector-failed", false, undefined, grantAuditExtras(auditCtx, "human"));
            return yield* Effect.failCause(execExit.cause);
          }
          const result = execExit.value;
          yield* audit(grantReq.agentId, grantReq.alias, consumed.allowedScope, "executed", "executed", false, undefined, grantAuditExtras(auditCtx, "human"));
          return { status: "executed", result } as const;
        });

      const service: VaultServiceService = {
        seedCredential: (alias, ceiling, plaintextSecret, website, enrollmentId) =>
          alias === WARDEN_KEY_ALIAS
            ? Effect.fail(
                new StorageError({ message: "reserved alias", operation: "seedCredential" }),
              )
            : isCardSecretPayload(plaintextSecret)
              ? Effect.fail(
                  new StorageError({ message: "use add-card for payment cards", operation: CARD_INVALID_OPERATION }),
                )
            : Effect.flatMap(withKey((key) => encryptSecret(key, plaintextSecret)), (blob) =>
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

        createEnrollment: (alias, scope, website, reason, agentId) =>
          Effect.gen(function* () {
            if (alias === WARDEN_KEY_ALIAS) {
              return yield* Effect.fail(
                new StorageError({ message: "reserved alias", operation: "createEnrollment" }),
              );
            }
            const now = yield* Clock.currentTimeMillis;
            yield* purgeExpiredEnrollments(now);
            const owner = agentId !== undefined && agentId.trim() !== "" ? agentId.trim().slice(0, 128) : undefined;
            // Bound the pending registry (expired already purged above).
            // Fairness: evict the incoming agent's own oldest pendings
            // first, so one flooding agent cannot evict another agent's
            // pending enrollment; only when the incoming agent has none
            // pending fall back to the globally oldest pending.
            yield* Ref.update(enrollments, (map) => {
              const pending = [...map.values()].filter((r) => r.status === "pending");
              if (pending.length < MAX_PENDING_ENROLLMENTS) {
                return map;
              }
              const next = new Map(map);
              let remaining = pending.length - MAX_PENDING_ENROLLMENTS + 1;
              if (owner !== undefined) {
                for (const record of pending) {
                  if (remaining <= 0) break;
                  if (record.agentId === owner) {
                    next.delete(record.enrollmentId);
                    remaining -= 1;
                  }
                }
              }
              for (const record of pending) {
                if (remaining <= 0) break;
                if (next.has(record.enrollmentId)) {
                  next.delete(record.enrollmentId);
                  remaining -= 1;
                }
              }
              return next;
            });
            const enrollmentId = yield* Effect.sync(() => randomUUID());
            const record: EnrollmentRecord = { enrollmentId, alias, scope, website: website ?? "", status: "pending", expiresAtMs: now + enrollmentTtlMs, ...(owner !== undefined ? { agentId: owner } : {}) };
            yield* Ref.update(enrollments, (map) => { const next = new Map(map); next.set(enrollmentId, record); return next; });
            const cappedReason = (reason ?? "").trim().slice(0, ENROLLMENT_REASON_MAX_LENGTH);
            yield* audit(owner ?? "agent", alias, scope, "enrollment-created", cappedReason === "" ? `enrollment created: ${alias}` : `enrollment created: ${alias}: ${cappedReason}`, false);
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
            if (existing.kind === CARD_KIND && patch.secret !== undefined && patch.secret.trim() !== "") {
              return yield* Effect.fail(
                new StorageError({
                  message: "card credentials are replaced with add-card, not a raw secret",
                  operation: CARD_INVALID_OPERATION,
                }),
              );
            }
            const ciphertext =
              patch.secret !== undefined && patch.secret.trim() !== ""
                ? yield* withKey((key) => encryptSecret(key, patch.secret as string))
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
            metas
              .filter((m) => m.alias !== WARDEN_KEY_ALIAS)
              .map((m): PublicCredentialMeta => {
                const kind = m.kind ?? "secret";
                const card = kind === CARD_KIND ? parseCardPublicMeta(m.publicMeta ?? "") : null;
                return {
                  alias: m.alias,
                  scopeCeiling: m.scopeCeiling,
                  website: m.website,
                  kind,
                  ...(card !== null ? { card } : {}),
                };
              }),
          ),

        seedCardCredential: (alias, card, scope, website) =>
          Effect.gen(function* () {
            const trimmedAlias = alias.trim();
            if (trimmedAlias === "" || trimmedAlias === WARDEN_KEY_ALIAS) {
              return yield* Effect.fail(
                new StorageError({ message: "invalid alias", operation: CARD_INVALID_OPERATION }),
              );
            }
            const now = yield* Clock.currentTimeMillis;
            const parsed = parseCardInput(card, new Date(now));
            if (!parsed.ok) {
              return yield* Effect.fail(
                new StorageError({
                  message: `invalid card: ${parsed.issues.join(", ")}`,
                  operation: CARD_INVALID_OPERATION,
                }),
              );
            }
            const ceiling = scope !== undefined && scope.trim() !== "" ? scope.trim() : DEFAULT_CARD_SCOPE;
            if (!isWriteScope(ceiling)) {
              return yield* Effect.fail(
                new StorageError({
                  message: "card scopes must be write scopes (e.g. card.payment:write)",
                  operation: CARD_INVALID_OPERATION,
                }),
              );
            }
            const blob = yield* withKey((key) => encryptSecret(key, serializeCardSecret(parsed.card)));
            yield* store.addCredential(trimmedAlias, ceiling, blob, website?.trim() ?? "", CARD_KIND, JSON.stringify(parsed.meta));
            yield* Ref.update(aliases, (set) => new Set(set).add(trimmedAlias));
            yield* audit(
              "human",
              trimmedAlias,
              ceiling,
              "credential-added",
              `card added: ${trimmedAlias} (${parsed.meta.brand} ${parsed.meta.masked})`,
              false,
            );
            return parsed.meta;
          }),

        keyStatus: () => Effect.sync(() => keySession.status()),

        unlockVault: (passphrase) =>
          Effect.tryPromise({
            try: () => keySession.unlock(passphrase),
            catch: () => new StorageError({ message: "unlock failed", operation: "unlock" }),
          }),

        lockVault: () =>
          Effect.sync(() => {
            keySession.lock();
          }),

        setupVault: (passphrase) =>
          Effect.tryPromise({
            try: async () => (keySession.setup === undefined ? "not-supported" : keySession.setup(passphrase)),
            catch: () => new StorageError({ message: "vault setup failed", operation: "setup" }),
          }),

        requestCapability: (reqIn, agentToken, deviceCtx) =>
          Effect.gen(function* () {
            // Channel metadata is stamped by the daemon from the gateway's
            // authenticated session, never taken from the agent's body.
            const req: CapabilityRequest =
              deviceCtx !== undefined
                ? { ...reqIn, deviceId: deviceCtx.deviceId, origin: "remote", transport: deviceCtx.transport }
                : reqIn;
            const deviceAuditExtras =
              deviceCtx !== undefined
                ? { deviceId: deviceCtx.deviceId, origin: "remote" as const, transport: deviceCtx.transport }
                : {};
            let deviceAllowWrite = true;
            if (deviceCtx !== undefined) {
              // The daemon re-checks the device at its own policy floor; it
              // never relies on the gateway having already done so.
              const device = yield* store.getDevice(deviceCtx.deviceId);
              if (device === undefined || device.revoked) {
                return { status: "denied", reason: "device-revoked" } as const;
              }
              const devicePolicies = yield* store.listDeviceAliasPolicies(deviceCtx.deviceId);
              deviceAllowWrite = devicePolicies.find((p) => p.alias === req.alias)?.allowWrite === true;
              yield* store.touchDeviceLastSeen(deviceCtx.deviceId, new Date().toISOString());
            }
            const epoch = agentEpoch.get(req.agentId) ?? 0;
            if (agentToken !== undefined) {
              const current = yield* store.getAgentByToken(agentToken);
              if (current === undefined || current.revoked || current.id !== req.agentId) return { status: "denied", reason: "agent-credentials-changed" } as const;
              // Device binding is enforced in both directions: a bound
              // token works only inside its own device's session, and a
              // local (unbound) token never works from a remote device.
              const boundDevice = current.deviceId ?? null;
              if (deviceCtx !== undefined && boundDevice !== deviceCtx.deviceId) return { status: "denied", reason: "agent-token-device-mismatch" } as const;
              if (deviceCtx === undefined && boundDevice !== null) return { status: "denied", reason: "agent-token-device-bound" } as const;
            }
            const now = yield* Clock.currentTimeMillis;
            const storedCredential = yield* store.getCredential(req.alias);
            const credential = req.alias === WARDEN_KEY_ALIAS ? undefined : storedCredential;
            const auditEvents = yield* store.listAudit();
            const requestId = yield* Effect.sync(() => randomUUID());
            yield* audit(req.agentId, req.alias, req.requestedScope, "requested", req.verified ? "capability requested (verified)" : "capability requested (unverified)", false, undefined, { requestId, ...(req.verified !== undefined ? { verified: req.verified } : {}), ...deviceAuditExtras });

            if (yield* registry.isRevoked(req.agentId, req.alias)) {
              yield* audit(req.agentId, req.alias, req.requestedScope, "denied", "revoked", false, undefined, { requestId, decisionSource: "policy", ...deviceAuditExtras });
              return { status: "denied", reason: "revoked" } as const;
            }

            // Check granular agent rate limiting & burst circuit breaker (#18)
            const velocities = yield* Ref.get(agentVelocities);
            const agentTracker = velocities.get(req.agentId);
            const velocityCheck = isAgentRateLimited(agentTracker, undefined, now);
            if (velocityCheck.limited) {
              const reason = velocityCheck.reason ?? "rate-limit-velocity";
              yield* audit(req.agentId, req.alias, req.requestedScope, "policy", reason, false, undefined, { requestId, decisionSource: "policy", ...deviceAuditExtras });
              yield* audit(req.agentId, req.alias, req.requestedScope, "denied", reason, false, undefined, { requestId, decisionSource: "policy", ...deviceAuditExtras });
              return { status: "denied", reason } as const;
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
            const financialAliases = credential?.kind === CARD_KIND ? [req.alias] : [];
            const cfg: PolicyConfig = {
              ceilings,
              standingApprovals: standingNow,
              rateLimitPerHour,
              financialAliases,
              disableStandingApprovals: deviceCtx !== undefined,
              deviceAllowWrite,
            };

            // Policy pre-check: unknown alias / rate limit deny before the marshal runs.
            const preCheck = evaluatePolicy(req, null, cfg, historyCount);
            if (credential === undefined || preCheck.allowedScope === null) {
              const reason = credential === undefined ? "unknown-alias" : preCheck.reason;
              // Record failure in velocity tracker
              yield* Ref.update(agentVelocities, (map) => {
                const next = new Map(map);
                next.set(req.agentId, recordAgentRequest(next.get(req.agentId), now, false));
                return next;
              });
              yield* audit(req.agentId, req.alias, req.requestedScope, "policy", reason, false, undefined, { requestId, decisionSource: "policy", ...deviceAuditExtras });
              yield* audit(req.agentId, req.alias, req.requestedScope, "denied", reason, false, undefined, { requestId, decisionSource: "policy", ...deviceAuditExtras });
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
            const marshalRan = wardenSettings.provider !== "none";
            const effectiveModel = effectiveWardenModel(wardenSettings);
            const marshalModelId = effectiveModel.trim() !== "" ? effectiveModel : modelId;
            let decision: MarshalDecision | null = null;
            let latencyMs: number | undefined;
            if (marshalRan) {
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
                    ...deviceAuditExtras,
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

            // Card use is a financial write: whatever the warden said, the
            // stored decision is escalated to high risk, so neither policy
            // nor approve-always can treat it as low.
            if (credential.kind === CARD_KIND) {
              decision = escalateFinancialDecision(decision);
            }
            const result = evaluatePolicy(req, decision, cfg, historyCount);
            yield* audit(
              req.agentId,
              req.alias,
              result.allowedScope ?? req.requestedScope,
              "policy",
              result.reason,
              marshalRan,
              marshalRan ? marshalModelId : undefined,
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
              yield* Ref.update(agentVelocities, (map) => {
                const next = new Map(map);
                next.set(req.agentId, recordAgentRequest(next.get(req.agentId), now, false));
                return next;
              });
              yield* audit(req.agentId, req.alias, req.requestedScope, "denied", result.reason, marshalRan, marshalRan ? marshalModelId : undefined, { requestId, decisionSource: finalDecisionSource, ...deviceAuditExtras });
              return { status: "denied", reason: result.reason } as const;
            }
            const allowedScope = result.allowedScope;
            if ((agentEpoch.get(req.agentId) ?? 0) !== epoch) return { status: "denied", reason: "agent-credentials-changed" } as const;

            // Record successful capability validation in tracker
            yield* Ref.update(agentVelocities, (map) => {
              const next = new Map(map);
              next.set(req.agentId, recordAgentRequest(next.get(req.agentId), now, true));
              return next;
            });

            if (result.requireApproval) {
              const grantId = yield* Effect.sync(() => randomUUID());
              const grant = createGrant(grantId, req, allowedScope, now, grantTtlMs);
              yield* registry.register(grant);
              if ((agentEpoch.get(req.agentId) ?? 0) !== epoch) { yield* registry.markDenied(grantId); return {status:"denied",reason:"agent-credentials-changed"} as const; }
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

            yield* audit(req.agentId, req.alias, allowedScope, "approved", "auto-approved by policy", marshalRan, marshalRan ? marshalModelId : undefined, { requestId, decisionSource: finalDecisionSource, ...deviceAuditExtras });
            if ((agentEpoch.get(req.agentId) ?? 0) !== epoch) return { status: "denied", reason: "agent-credentials-changed" } as const;
            const exit = yield* Effect.exit(executeGrant(req, allowedScope, credential.ciphertext));
            if (Exit.isFailure(exit)) {
              yield* audit(req.agentId, req.alias, allowedScope, "denied", "connector-failed", marshalRan, marshalRan ? marshalModelId : undefined, { requestId, decisionSource: finalDecisionSource, ...deviceAuditExtras });
              return { status: "denied", reason: "connector-failed" } as const;
            }
            yield* audit(req.agentId, req.alias, allowedScope, "executed", "executed", marshalRan, marshalRan ? marshalModelId : undefined, { requestId, decisionSource: finalDecisionSource, ...deviceAuditExtras });
            return { status: "executed", result: exit.value, reason: result.reason } as const;
          }),

        approve: (grantId, presenceProof) =>
          Effect.gen(function* () {
            yield* requirePresenceForRemoteApproval(grantId, presenceProof);
            return yield* consumeAndExecute(grantId, "approved by human");
          }),

        approveAlways: (grantId, presenceProof) =>
          Effect.gen(function* () {
            yield* requirePresenceForRemoteApproval(grantId, presenceProof);
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
            const grantCredential = yield* store.getCredential(grant.request.alias);
            if (
              decision === null ||
              decision.risk !== "low" ||
              isWriteScope(grant.allowedScope) ||
              grantCredential?.kind === CARD_KIND
            ) {
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
            const epoch = agentEpoch.get(grant.request.agentId) ?? 0;
            const executed = yield* consumeAndExecute(grantId, "approved by human (always allow)");
            if ((agentEpoch.get(grant.request.agentId) ?? 0) !== epoch) return executed;
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
                      verifiedOnly: grant.request.verified === true,
                    },
                  ];
            });
            yield* audit(
              grant.request.agentId,
              grant.request.alias,
              grant.allowedScope,
              "approved",
              "standing approval created (always allow)",
              false,
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
              yield* audit(grant.request.agentId, grant.request.alias, grant.allowedScope, "denied", "denied by human", false, undefined, grantAuditExtras(auditCtx, "human"));
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
              yield* audit(grant.request.agentId, grant.request.alias, grant.allowedScope, "revoked", `revoked: ${agentIdOrAlias}`, false, undefined, grantAuditExtras(auditCtx));
            }
            if (affected.length === 0) {
              yield* audit(agentIdOrAlias, agentIdOrAlias, "", "revoked", `revoked: ${agentIdOrAlias}`, false);
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
            const hasMarshal = wardenSettings.provider !== "none";
            const pendingEffective = effectiveWardenModel(wardenSettings);
            const pendingModelId =
              hasMarshal && pendingEffective.trim() !== "" ? pendingEffective : modelId;
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
                  (hasMarshal
                    ? "Marshal unavailable — deterministic policy requires your approval."
                    : "Policy requires human approval."),
                createdAtMs: grant.createdAtMs,
                expiresAtMs: grant.expiresAtMs,
                verified: grant.request.verified ?? false,
                ...(grant.request.clientPid !== undefined ? { clientPid: grant.request.clientPid } : {}),
                ...(grant.request.clientProcess !== undefined ? { clientProcess: grant.request.clientProcess } : {}),
                ...(grant.request.deviceId !== undefined ? { deviceId: grant.request.deviceId } : {}),
                ...(grant.request.origin !== undefined ? { origin: grant.request.origin } : {}),
                ...(grant.request.transport !== undefined ? { transport: grant.request.transport } : {}),
              };
              pending.push(hasMarshal ? { ...base, modelId: pendingModelId } : base);
            }
            pending.sort((a, b) => a.createdAtMs - b.createdAtMs);
            return pending;
          }),
        // Real policy state for the Policies view: the enforced ceiling for
        // every enrolled alias (read back from the vault, never inferred
        // from audit) plus the standing approvals currently in force.
        getAgentSecuritySettings: () => store.getAgentSecuritySettings(),
        updateAgentSecuritySettings: (patch) =>
          Effect.gen(function* () {
            const current = yield* store.getAgentSecuritySettings();
            const next: AgentSecuritySettings = {
              strictMode: patch.strictMode !== undefined ? patch.strictMode : current.strictMode,
              verifyCallerProcess:
                patch.verifyCallerProcess !== undefined ? patch.verifyCallerProcess : current.verifyCallerProcess,
            };
            yield* store.setAgentSecuritySettings(next);
            yield* audit(
              "system",
              "security",
              "settings",
              "settings-changed",
              `agent security settings changed: strictMode=${String(next.strictMode)} verifyCallerProcess=${String(next.verifyCallerProcess)}`,
              false,
            );
            return next;
          }),
        getWardenSettings: () => store.getWardenSettings(),

        updateWardenSettings: (patch) =>
          Effect.gen(function* () {
            const current = yield* store.getWardenSettings();
            // The Meta API model and the local endpoint model are separate
            // fields, so switching provider never carries a local tag to
            // the Meta API (or the reverse).
            const next: WardenSettings = {
              provider: patch.provider ?? current.provider,
              model: patch.model !== undefined ? patch.model.trim() : current.model,
              effort: patch.effort ?? current.effort,
              metaApiBaseUrl:
                patch.metaApiBaseUrl !== undefined ? patch.metaApiBaseUrl.trim() : current.metaApiBaseUrl,
              localBaseUrl: patch.localBaseUrl !== undefined ? patch.localBaseUrl.trim() : current.localBaseUrl,
              localApi: patch.localApi ?? current.localApi,
              localModel: patch.localModel !== undefined ? patch.localModel.trim() : current.localModel,
            };
            yield* store.setWardenSettings(next);
            if (
              patch.provider !== undefined ||
              patch.model !== undefined ||
              patch.effort !== undefined ||
              patch.metaApiBaseUrl !== undefined ||
              patch.localBaseUrl !== undefined ||
              patch.localApi !== undefined ||
              patch.localModel !== undefined
            ) {
              yield* audit(
                "human",
                "warden",
                "",
                "settings-changed",
                `warden settings changed: provider=${next.provider} model=${effectiveWardenModel(next)}`,
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
            const blob = yield* withKey((key) => encryptSecret(key, trimmed));
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

        // One synthetic metadata-only marshal assessment through the
        // current settings/provider. Never audits and never creates grants:
        // it calls the brain directly, not requestCapability.
        testWarden: () =>
          Effect.gen(function* () {
            const settings = yield* store.getWardenSettings();
            const effective = effectiveWardenModel(settings);
            const model = effective.trim() !== "" ? effective : modelId;
            if (settings.provider === "none") {
              return { ok: true, provider: settings.provider, model, latencyMs: 0, detail: "policy-only" } as const;
            }
            const started = yield* Clock.currentTimeMillis;
            const exit = yield* Effect.exit(
              brain.assess(WARDEN_SELFCHECK_REQUEST, { requests24h: 0, denials24h: 0 }, "selfcheck"),
            );
            const ended = yield* Clock.currentTimeMillis;
            const latencyMs = Math.max(0, ended - started);
            if (Exit.isSuccess(exit)) {
              return { ok: true, provider: settings.provider, model, latencyMs, detail: "ok" } as const;
            }
            const failure = Cause.failureOption(exit.cause);
            const failureMessage =
              failure._tag === "Some" &&
              typeof (failure.value as { readonly message?: unknown }).message === "string"
                ? (failure.value as { readonly message: string }).message
                : "";
            let reason = classifyWardenFailure(failureMessage);
            if (reason === "no_key") {
              // The brain reports a missing key for both "nothing saved" and
              // "saved but cannot be decrypted", so look at the stored entry.
              const stored = yield* Effect.either(store.getCredential(WARDEN_KEY_ALIAS));
              if (stored._tag === "Right" && stored.right !== undefined) {
                const opened = yield* Effect.either(decrypt(stored.right.ciphertext));
                if (opened._tag === "Left") {
                  reason = opened.left.operation === VAULT_LOCKED_OPERATION ? "vault_locked" : "key_unreadable";
                } else if (opened.right.trim() === "") {
                  reason = "key_unreadable";
                }
              }
            }
            return { ok: false, provider: settings.provider, model, latencyMs, detail: "warden unavailable", reason } as const;
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
            const agents = yield* store.listAgents();
            return { ceilings, standingApprovals, agents };
          }),

        listAgents: () => store.listAgents(),
        getAgentByToken: (token) => store.getAgentByToken(token),
        registerAgent: (id, name, rotate = false, deviceId) =>
          Effect.gen(function* () {
            const existing = yield* store.getAgent(id);
            if (existing !== undefined && !existing.revoked && !rotate) return yield* Effect.fail(new StorageError({ message: "agent already exists; rotate explicitly", operation: "registerAgent" }));
            if (rotate && existing === undefined) return yield* Effect.fail(new StorageError({ message: "agent not found", operation: "registerAgent" }));
            agentEpoch.set(id, (agentEpoch.get(id) ?? 0) + 1);
            const affected = yield* registry.invalidatePendingForAgent(id);
            for (const grant of affected) { yield* forgetDecision(grant.grantId); yield* forgetGrantAudit(grant.grantId); yield* interruptSleeper(grant.grantId); }
            yield* Ref.update(standing, (entries) => entries.filter((entry) => entry.agentId !== id));
            const token = `ov_agent_${id.replace(/[^a-zA-Z0-9_-]/g, "")}_${randomBytes(16).toString("hex")}`;
            yield* store.addAgent(id, name, token, deviceId);
            const created = yield* store.getAgent(id);
            if (created === undefined) {
              return yield* Effect.fail(new StorageError({ message: "failed to create agent", operation: "registerAgent" }));
            }
            return { ...created, token };
          }).pipe(agentManagement.withPermits(1)),
        revokeAgentToken: (id) =>
          Effect.gen(function* () {
            yield* store.revokeAgent(id);
            agentEpoch.set(id, (agentEpoch.get(id) ?? 0) + 1);
            const affected = yield* registry.invalidatePendingForAgent(id);
            for (const grant of affected) { yield* forgetDecision(grant.grantId); yield* forgetGrantAudit(grant.grantId); yield* interruptSleeper(grant.grantId); }
            yield* Ref.update(standing, (entries) => entries.filter((entry) => entry.agentId !== id));
          }).pipe(agentManagement.withPermits(1)),
        listDevices: () => store.listDevices(),
        getDeviceByFingerprint: (fingerprint) => store.getDeviceByFingerprint(fingerprint),
        renameDevice: (id, name) =>
          Effect.gen(function* () {
            const device = yield* store.getDevice(id);
            if (device === undefined) return yield* Effect.fail(new StorageError({ message: "device not found", operation: "renameDevice" }));
            yield* store.renameDevice(id, name.trim());
          }),
        // Revocation is complete by construction: the device row, every
        // agent token bound to it, its pending grants, its standing
        // approvals and its per-alias write opt-ins all die together. The
        // gateway independently re-checks status on every request.
        revokeDevice: (id) =>
          Effect.gen(function* () {
            const device = yield* store.getDevice(id);
            if (device === undefined) return yield* Effect.fail(new StorageError({ message: "device not found", operation: "revokeDevice" }));
            yield* store.setDeviceRevoked(id, true);
            const agents = yield* store.listAgents();
            for (const agent of agents) {
              if ((agent.deviceId ?? null) === id && !agent.revoked) {
                yield* store.revokeAgent(agent.id);
                const affected = yield* registry.invalidatePendingForAgent(agent.id);
                for (const grant of affected) { yield* forgetDecision(grant.grantId); yield* forgetGrantAudit(grant.grantId); yield* interruptSleeper(grant.grantId); }
                yield* Ref.update(standing, (entries) => entries.filter((entry) => entry.agentId !== agent.id));
              }
            }
            yield* store.deleteDeviceAliasPolicies(id);
            yield* audit("devices", "*", "*", "revoked", `device revoked: ${device.name}`, false, undefined, { deviceId: id, origin: "remote", transport: device.transport });
          }).pipe(agentManagement.withPermits(1)),
        listDeviceAliasPolicies: (deviceId) => store.listDeviceAliasPolicies(deviceId),
        setDeviceAliasPolicy: (deviceId, alias, allowWrite) =>
          Effect.gen(function* () {
            const device = yield* store.getDevice(deviceId);
            if (device === undefined) return yield* Effect.fail(new StorageError({ message: "device not found", operation: "setDeviceAliasPolicy" }));
            if (device.revoked) return yield* Effect.fail(new StorageError({ message: "device revoked", operation: "setDeviceAliasPolicy" }));
            const hasAlias = yield* store.listCredentialAliases().pipe(Effect.map((list) => list.includes(alias)));
            if (!hasAlias) return yield* Effect.fail(new StorageError({ message: "unknown alias", operation: "setDeviceAliasPolicy" }));
            yield* store.setDeviceAliasPolicy(deviceId, alias, allowWrite);
          }),
        getRemoteSettings: () => store.getRemoteSettingsRow(),
        updateRemoteSettings: (patch, presenceProof) =>
          Effect.gen(function* () {
            const current = yield* store.getRemoteSettingsRow();
            // Turning the remote-approval presence requirement OFF is itself
            // a privileged weakening: any caller - app main or a direct
            // daemon-token holder - must prove fresh local presence (PIN).
            if (patch.requireAuthForRemoteApproval === false && current.requireAuthForRemoteApproval) {
              const ok = yield* consumePresenceProof(presenceProof);
              if (!ok) {
                return yield* Effect.fail(
                  new PresenceRequired({ message: "disabling remote-approval presence requires fresh local presence (app PIN)" }),
                );
              }
            }
            const next = {
              enabled: patch.enabled ?? current.enabled,
              host: patch.host ?? current.host,
              port: patch.port ?? current.port,
              requireAuthForRemoteApproval: patch.requireAuthForRemoteApproval ?? current.requireAuthForRemoteApproval,
            };
            yield* store.setRemoteSettingsRow(next);
            yield* audit("settings", "*", "*", "settings-changed", `remote access ${next.enabled ? "enabled" : "disabled"} (${next.host}:${String(next.port)})`, false, undefined, {});
            return next;
          }),
        createPairingSession: () =>
          Effect.gen(function* () {
            const now = yield* Clock.currentTimeMillis;
            const code = generatePairingCode();
            const session: PairingSession = {
              pairingId: randomBytes(16).toString("hex"),
              code,
              codeHash: hashPairingCode(code),
              createdAtMs: now,
              expiresAtMs: now + PAIRING_TTL_MS,
              failedAttempts: 0,
              status: "waiting",
              serverNonce: randomBytes(16).toString("hex"),
            };
            yield* Ref.set(pairing, session);
            return { pairingId: session.pairingId, status: session.status, expiresAtMs: session.expiresAtMs, code: session.code };
          }),
        getPairingSession: () =>
          Effect.gen(function* () {
            const now = yield* Clock.currentTimeMillis;
            const session = yield* Ref.get(pairing);
            if (session === undefined) return undefined;
            if (session.expiresAtMs <= now && session.status !== "confirmed") {
              yield* Ref.set(pairing, undefined);
              return undefined;
            }
            return {
              pairingId: session.pairingId,
              status: session.status,
              expiresAtMs: session.expiresAtMs,
              ...(session.status === "waiting" ? { code: session.code } : {}),
              ...(session.deviceName !== undefined ? { deviceName: session.deviceName } : {}),
              ...(session.platform !== undefined ? { platform: session.platform } : {}),
              ...(session.sas !== undefined && session.status === "joined" ? { sas: session.sas } : {}),
              ...(session.deviceId !== undefined ? { deviceId: session.deviceId } : {}),
            };
          }),
        cancelPairingSession: (pairingId) =>
          Effect.gen(function* () {
            const session = yield* Ref.get(pairing);
            if (session !== undefined && session.pairingId === pairingId) {
              yield* Ref.set(pairing, undefined);
            }
          }),
        pairBegin: (input) =>
          Effect.gen(function* () {
            const now = yield* Clock.currentTimeMillis;
            const session = yield* Ref.get(pairing);
            if (session === undefined || session.status !== "waiting") {
              return yield* Effect.fail("pairing-unavailable" as const);
            }
            if (session.expiresAtMs <= now) {
              yield* Ref.set(pairing, undefined);
              return yield* Effect.fail("pairing-expired" as const);
            }
            if (session.failedAttempts >= PAIRING_MAX_FAILED_ATTEMPTS) {
              // Too many wrong codes: the human must start a fresh session.
              yield* Ref.set(pairing, undefined);
              return yield* Effect.fail("pairing-unavailable" as const);
            }
            const provided = hashPairingCode(input.code);
            const ok =
              provided.length === session.codeHash.length &&
              timingSafeEqual(Buffer.from(provided), Buffer.from(session.codeHash));
            if (!ok) {
              yield* Ref.update(pairing, (cur) =>
                cur === undefined ? cur : { ...cur, failedAttempts: cur.failedAttempts + 1 },
              );
              return yield* Effect.fail("pairing-code-invalid" as const);
            }
            let fingerprint: string;
            try {
              fingerprint = spkiFingerprintFromPublicKeyPem(input.clientPublicKeyPem);
            } catch {
              return yield* Effect.fail("pairing-key-invalid" as const);
            }
            // Single-use: the code cannot pair a second device.
            yield* Ref.set(pairing, {
              ...session,
              status: "joined",
              deviceName: input.deviceName.slice(0, 64),
              platform: input.platform.slice(0, 64),
              clientPublicKeyPem: input.clientPublicKeyPem,
              clientFingerprint: fingerprint,
              clientNonce: input.clientNonce.slice(0, 128),
            });
            return { pairingId: session.pairingId, serverNonce: session.serverNonce };
          }),
        attachPairingSas: (pairingId, sas) =>
          Effect.gen(function* () {
            const session = yield* Ref.get(pairing);
            if (session === undefined || session.pairingId !== pairingId || session.status !== "joined") return;
            // The SAS lives only in the in-memory session: never persisted,
            // never logged, cleared with the session.
            yield* Ref.set(pairing, { ...session, sas: sas.slice(0, 32) });
          }),
        confirmPairing: (pairingId) =>
          Effect.gen(function* () {
            const now = yield* Clock.currentTimeMillis;
            const session = yield* Ref.get(pairing);
            if (
              session === undefined ||
              session.pairingId !== pairingId ||
              session.status !== "joined" ||
              session.sas === undefined ||
              session.clientPublicKeyPem === undefined ||
              session.clientFingerprint === undefined ||
              session.expiresAtMs <= now
            ) {
              return yield* Effect.fail(new PairingNotConfirmable({ message: "pairing not confirmable", pairingId }));
            }
            const ca = yield* loadVaultCa();
            const deviceId = `dev-${session.clientFingerprint.slice(0, 12)}`;
            const certificatePem = signLeafCertificate({
              caKeyPem: ca.keyPem,
              caCertPem: ca.certPem,
              publicKeyPem: session.clientPublicKeyPem,
              commonName: deviceId,
              serialNumber: randomBytes(8).toString("hex"),
              validityDays: 365,
              usage: "client",
            });
            const device: DeviceRecord = {
              id: deviceId,
              name: session.deviceName ?? deviceId,
              platform: session.platform ?? "",
              certFingerprint: session.clientFingerprint,
              transport: "",
              createdAt: new Date(now).toISOString(),
              lastSeenAt: null,
              revoked: false,
            };
            yield* store.addDevice(device);
            yield* Ref.set(pairing, { ...session, status: "confirmed", deviceId, certificatePem });
            yield* audit("devices", "*", "*", "settings-changed", `device paired: ${device.name}`, false, undefined, { deviceId });
            return { deviceId, certFingerprint: session.clientFingerprint };
          }).pipe(agentManagement.withPermits(1)),
        pairingInternalStatus: (pairingId) =>
          Effect.gen(function* () {
            const now = yield* Clock.currentTimeMillis;
            const session = yield* Ref.get(pairing);
            if (session === undefined || session.pairingId !== pairingId || session.expiresAtMs <= now) {
              return { status: "unknown" as const };
            }
            if (session.status !== "confirmed" || session.certificatePem === undefined) {
              return { status: session.status };
            }
            const ca = yield* loadVaultCa();
            return { status: "confirmed" as const, certificatePem: session.certificatePem, caCertPem: ca.certPem };
          }),

        pairingOpen: () =>
          Effect.gen(function* () {
            const now = yield* Clock.currentTimeMillis;
            const session = yield* Ref.get(pairing);
            return { open: session !== undefined && session.expiresAtMs > now && session.status !== "confirmed" };
          }),

        getLocalAuthStatus: () =>
          Effect.gen(function* () {
            const record = yield* store.getLocalAuthRecord();
            return {
              enabled: record.enabled,
              configured: record.pinHash !== null,
              biometricEnabled: record.biometricEnabled,
              requireOnApproval: record.requireOnApproval,
              requireOnLaunch: record.requireOnLaunch,
              requireOnSettings: record.requireOnSettings,
              autoLockMinutes: record.autoLockMinutes,
            };
          }),

        updateLocalAuthSettings: (patch) =>
          Effect.gen(function* () {
            const current = yield* store.getLocalAuthRecord();
            const next = {
              ...current,
              enabled: patch.enabled !== undefined ? patch.enabled : current.enabled,
              biometricEnabled:
                patch.biometricEnabled !== undefined ? patch.biometricEnabled : current.biometricEnabled,
              requireOnApproval:
                patch.requireOnApproval !== undefined ? patch.requireOnApproval : current.requireOnApproval,
              requireOnLaunch:
                patch.requireOnLaunch !== undefined ? patch.requireOnLaunch : current.requireOnLaunch,
              requireOnSettings:
                patch.requireOnSettings !== undefined ? patch.requireOnSettings : current.requireOnSettings,
              autoLockMinutes:
                patch.autoLockMinutes !== undefined ? patch.autoLockMinutes : current.autoLockMinutes,
            };
            yield* store.setLocalAuthRecord(next);
            return {
              enabled: next.enabled,
              configured: next.pinHash !== null,
              biometricEnabled: next.biometricEnabled,
              requireOnApproval: next.requireOnApproval,
              requireOnLaunch: next.requireOnLaunch,
              requireOnSettings: next.requireOnSettings,
              autoLockMinutes: next.autoLockMinutes,
            };
          }),

        setLocalPin: (pin, currentPin) =>
          Effect.gen(function* () {
            const current = yield* store.getLocalAuthRecord();
            if (current.pinHash !== null && current.salt !== null) {
              const matches = verifyPin(currentPin ?? "", current.salt, current.pinHash);
              if (!matches) {
                return yield* Effect.fail(
                  new StorageError({ message: "invalid current pin", operation: "setLocalPin" }),
                );
              }
            }
            const salt = generatePinSalt();
            const pinHash = hashPin(pin, salt);
            yield* store.setLocalAuthRecord({
              ...current,
              pinHash,
              salt,
            });
            return { ok: true } as const;
          }),

        verifyLocalPin: (pin) =>
          Effect.gen(function* () {
            const current = yield* store.getLocalAuthRecord();
            if (current.pinHash === null || current.salt === null) {
              // No PIN configured: verification is vacuous and must NOT
              // mint presence proofs - fail closed for remote approvals.
              return { ok: true } as const;
            }
            const ok = verifyPin(pin, current.salt, current.pinHash);
            if (!ok) return { ok } as const;
            const presenceProof = yield* mintPresenceProof();
            return { ok, presenceProof } as const;
          }),

        verifyBiometric: () =>
          Effect.gen(function* () {
            const current = yield* store.getLocalAuthRecord();
            if (!current.enabled || !current.biometricEnabled) {
              return { ok: false } as const;
            }
            // Deliberately NO presence proof: this result is caller-attested
            // (the daemon cannot verify a Hello prompt happened), so it must
            // never authorize remote approvals. PIN is the only proof source.
            return { ok: true } as const;
          }),

        getSecurityPosture: () =>
          Effect.gen(function* () {
            const credentials = yield* store.listCredentials();
            const filteredCreds = credentials.filter((c) => c.alias !== WARDEN_KEY_ALIAS);
            const standingApprovals = yield* Ref.get(standing);
            const auditEvents = yield* store.listAudit();
            const wardenSettings = yield* store.getWardenSettings();
            const now = yield* Clock.currentTimeMillis;
            return calculateSecurityPosture({
              credentials: filteredCreds,
              standingApprovals,
              auditEvents,
              wardenProvider: wardenSettings.provider,
              nowMs: now,
            });
          }),
      };
      return service;
    }),
  );
}

export const VaultServiceLive: Layer.Layer<VaultService, never, VaultStore | Brain | Connector> =
  makeVaultServiceLive();
