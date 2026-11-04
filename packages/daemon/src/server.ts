import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import Database from "better-sqlite3";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { Cause, Effect, Exit, Layer, ManagedRuntime, Schema } from "effect";
import { assessFromSettings, Brain, MarshalUnavailable } from "../../brain/src/brain.js";
import { ConnectorLive, makeConnectorLive, type ConnectorPresets } from "../../connectors/src/http.js";
import { Connector } from "../../core/src/connector.js";
import { DEFAULT_AGENT_SECURITY_SETTINGS, WARDEN_KEY_ALIAS, WARDEN_KEY_MIN_LENGTH, normalizeWardenProvider, type AgentSecuritySettings } from "../../core/src/settings.js";
import { inspectProcess } from "./process-inspector.js";
import { decryptSecret } from "../../core/src/crypto.js";
import { metavaultEnv } from "../../core/src/env.js";
import { ensureGatewayCertificate, ensureVaultCa } from "../../core/src/vault-ca.js";
import { retrieveMasterKey } from "../../core/src/keychain.js";
import { VaultStore, VaultStoreLive } from "../../core/src/storage.js";
import type { CapabilityRequest } from "../../core/src/types.js";
import {
  CapabilityRequestSchema,
  CardCredentialSchema,
  CredentialSchema,
  EnrollmentRequestSchema,
  UnlockSchema,
  GrantIdSchema,
  PoliciesResponseSchema,
  RevokeSchema,
  UpdateCredentialSchema,
  WardenKeyPutSchema,
  AgentSecuritySettingsPatchSchema,
  WardenSettingsPatchSchema,
} from "./schemas.js";
import {
  CARD_INVALID_OPERATION,
  makeVaultServiceLive,
  VAULT_LOCKED_OPERATION,
  VaultService,
  type VaultServiceService,
  type WardenSettingsPatch,
} from "./service.js";
import {
  autoLockMsFromEnv,
  createFirstRunKeySession,
  createKeySession,
  envMasterKeyIfAllowed,
  type KeySession,
} from "../../core/src/key-session.js";
import { readWrappedKeyFile, wrappedKeyFilePath } from "../../core/src/keywrap.js";

export {
  CapabilityRequestSchema,
  CardCredentialSchema,
  CredentialSchema,
  UnlockSchema,
  EnrollmentIdSchema,
  EnrollmentRequestSchema,
  GrantIdSchema,
  PoliciesResponseSchema,
  RevokeSchema,
  UpdateCredentialSchema,
  WardenKeyPutSchema,
  WardenSettingsPatchSchema,
} from "./schemas.js";

export function buildEnrollmentDeeplink(record: { enrollmentId: string; alias: string; scope: string; website: string }): string {
  const params = new URLSearchParams({ alias: record.alias, scope: record.scope, enrollment: record.enrollmentId });
  if (record.website !== "") { params.set("website", record.website); }
  return `metavault://add?${params.toString()}`;
}

export function statusForErrorTag(tag: string): number {
  switch (tag) {
    case "GrantExpired":
    case "GrantRevoked":
    case "PairingNotConfirmable":
      return 409;
    case "PolicyDenied":
    case "UnknownAlias":
    case "PresenceRequired":
      return 403;
    case "ConnectorFailed":
      return 502;
    case "VaultLocked":
      return 423;
    case "CardInvalid":
      return 400;
    default:
      return 500;
  }
}

interface SafeErrorBody {
  readonly error: { readonly _tag: string; readonly message: string };
}

function safeErrorBody(err: unknown): SafeErrorBody {
  if (typeof err === "object" && err !== null && "_tag" in err) {
    const tag = String(err._tag);
    const message =
      "message" in err && typeof err.message === "string" ? err.message : tag;
    const operation = "operation" in err ? err.operation : undefined;
    if (tag === "StorageError" && operation === VAULT_LOCKED_OPERATION) {
      return { error: { _tag: "VaultLocked", message } };
    }
    if (tag === "StorageError" && operation === CARD_INVALID_OPERATION) {
      return { error: { _tag: "CardInvalid", message } };
    }
    return { error: { _tag: tag, message } };
  }
  return { error: { _tag: "InternalError", message: "internal error" } };
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(text);
}

export class HttpBodyError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function readBodyWithText(req: IncomingMessage): Promise<{ parsed: unknown; text: string }> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    size += buf.length;
    if (size > 65_536) {
      throw new HttpBodyError(413, "request body too large");
    }
    chunks.push(buf);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (text === "") {
    return { parsed: {}, text };
  }
  try {
    return { parsed: JSON.parse(text) as unknown, text };
  } catch {
    throw new HttpBodyError(400, "malformed JSON body");
  }
}

// Gateway request stamps. The gateway proves it (and only it) forwarded a
// request by MACing the device identity, method, path, exact body bytes, a
// timestamp and a single-use nonce with the loopback-shared secret. The
// daemon recomputes and compares in constant time, enforces a freshness
// window and rejects replayed nonces. The stamp authenticates the gateway
// as the transport; it is not independent proof of device intent beyond
// what the gateway verified (mTLS certificate + revocation status).
export const GATEWAY_STAMP_WINDOW_SECONDS = 120;
const GATEWAY_STAMP_NONCE_CACHE_LIMIT = 50_000;
const seenStampNonces = new Map<string, number>();

export function computeGatewayStampMac(
  secret: string,
  fields: {
    readonly deviceId: string;
    readonly transport: string;
    readonly method: string;
    readonly path: string;
    readonly bodyText: string;
    readonly timestamp: string;
    readonly nonce: string;
  },
): string {
  const bodyHash = createHash("sha256").update(fields.bodyText, "utf8").digest("hex");
  return createHmac("sha256", secret)
    .update(
      [
        fields.deviceId,
        fields.transport,
        fields.method,
        fields.path,
        bodyHash,
        fields.timestamp,
        fields.nonce,
      ].join("\n"),
      "utf8",
    )
    .digest("hex");
}

export function validateGatewayStamp(
  secret: string,
  fields: {
    readonly mac: string;
    readonly deviceId: string;
    readonly transport: string;
    readonly method: string;
    readonly path: string;
    readonly bodyText: string;
    readonly timestamp: string;
    readonly nonce: string;
  },
  nowSeconds: number = Math.floor(Date.now() / 1000),
): boolean {
  const ts = Number(fields.timestamp);
  if (!Number.isInteger(ts) || Math.abs(nowSeconds - ts) > GATEWAY_STAMP_WINDOW_SECONDS) {
    return false;
  }
  if (!/^[0-9a-f]{64}$/.test(fields.mac) || !/^[0-9a-f]{32}$/.test(fields.nonce)) {
    return false;
  }
  const expected = computeGatewayStampMac(secret, fields);
  const macOk = tokenMatches(expected, fields.mac);
  if (!macOk) {
    return false;
  }
  // Replay defense: a nonce may be used once within the freshness window.
  for (const [nonce, expiry] of seenStampNonces) {
    if (expiry <= nowSeconds) {
      seenStampNonces.delete(nonce);
    }
  }
  if (seenStampNonces.has(fields.nonce)) {
    return false;
  }
  if (seenStampNonces.size >= GATEWAY_STAMP_NONCE_CACHE_LIMIT) {
    return false;
  }
  seenStampNonces.set(fields.nonce, ts + GATEWAY_STAMP_WINDOW_SECONDS);
  return true;
}

export function clearGatewayStampNoncesForTests(): void {
  seenStampNonces.clear();
}

export function isSafeAlias(alias: string): boolean {
  if (alias === "" || alias.length > 128 || alias === "." || alias === "..") {
    return false;
  }
  for (let i = 0; i < alias.length; i += 1) {
    const code = alias.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      return false;
    }
  }
  return !alias.includes("/") && !alias.includes("\\");
}

async function run<A, E>(effect: Effect.Effect<A, E>): Promise<{ status: number; body: unknown }> {
  const exit = await Effect.runPromiseExit(effect);
  if (Exit.isSuccess(exit)) {
    return { status: 200, body: exit.value };
  }
  const failure = Cause.failureOption(exit.cause);
  if (failure._tag === "Some") {
    const body = safeErrorBody(failure.value);
    return { status: statusForErrorTag(body.error._tag), body };
  }
  return { status: 500, body: { error: { _tag: "InternalError", message: "internal error" } } };
}

async function decode<A, I>(schema: Schema.Schema<A, I>, body: unknown): Promise<A | null> {
  const exit = await Effect.runPromiseExit(Schema.decodeUnknown(schema)(body));
  return Exit.isSuccess(exit) ? exit.value : null;
}

function safeDecodeSegment(raw: string): string | null {
  try {
    return decodeURIComponent(raw);
  } catch {
    return null;
  }
}

const BAD_REQUEST: { status: number; body: unknown } = {
  status: 400,
  body: { error: { _tag: "BadRequest", message: "invalid request body" } },
};

// Terminal, structured outcome an agent can act on. "executed" means the
// human approved and vaultd ran the call; the result goes to the approver
// path, never back through this route.
export function grantOutcome(
  status: string,
  expiresAtMs: number,
  nowMs: number,
): { status: "pending" | "executed" | "denied" | "expired" | "revoked"; terminal: boolean; message: string } {
  if (status === "pending" && nowMs >= expiresAtMs) return grantOutcome("expired", expiresAtMs, nowMs);
  switch (status) {
    case "executed":
      return { status: "executed", terminal: true, message: "The user approved this request and vaultd ran it. The result is not returned here." };
    case "denied":
      return { status: "denied", terminal: true, message: "The user denied this request in MetaVault OSS. Do not retry it or look for another way around it; ask the user what they want." };
    case "expired":
      return { status: "expired", terminal: true, message: "This request expired before the user decided. Nothing ran. Ask the user before requesting again." };
    case "revoked":
      return { status: "revoked", terminal: true, message: "This request was revoked. Nothing ran. Ask the user before requesting again." };
    default:
      return { status: "pending", terminal: false, message: "Still waiting for the user to decide in MetaVault OSS. Do not send the request again." };
  }
}

export const DAEMON_TOKEN_HEADER = "x-metavault-token";

// The daemon token gates the human-decision routes. Without it any local
// process (including the agent asking for a capability) could approve its
// own grants, so /approve, /approve-always, /deny and the pending queue
// require it. Agent-facing and safe-direction routes (/request, /aliases,
// /audit, /policies, /revoke) stay open: requesting never grants anything
// and revoking only ever removes access. Open routes must not hand out
// credentials: /policies answers with agent tokens stripped, so the only
// way to read an agent bearer token is the token-guarded GET /agents.
export function daemonTokenFilePath(dbPath: string): string {
  return join(dirname(dbPath), "metavault.token");
}

export function gatewaySecretFilePath(dbPath: string): string {
  return join(dirname(dbPath), "metavault.gateway-token");
}

// The gateway secret authenticates the sibling gateway process over
// loopback so local processes cannot stamp forged device identity headers.
// It is created only when remote access is enabled; until then every
// stamped request fails closed.
export function loadGatewaySecret(dbPath: string): string | undefined {
  const fromEnv = metavaultEnv("GATEWAY_TOKEN");
  if (fromEnv !== undefined && fromEnv !== "") return fromEnv;
  try {
    if (existsSync(gatewaySecretFilePath(dbPath))) {
      return readFileSync(gatewaySecretFilePath(dbPath), "utf8").trim();
    }
  } catch {
    // Unreadable secret: fail closed (no gateway validation possible).
  }
  return undefined;
}

export function ensureGatewaySecret(dbPath: string): string {
  const existing = loadGatewaySecret(dbPath);
  if (existing !== undefined && existing !== "") return existing;
  const secret = randomBytes(32).toString("hex");
  writeFileSync(gatewaySecretFilePath(dbPath), secret, { encoding: "utf8", mode: 0o600 });
  return secret;
}

export function resolveDaemonToken(dbPath: string): string {
  const fromEnv = metavaultEnv("DAEMON_TOKEN");
  if (fromEnv !== undefined && fromEnv !== "") {
    return fromEnv;
  }
  const token = randomBytes(32).toString("hex");
  try {
    // Best-effort restrictive perms; the token is exposed only via this
    // file (or METAVAULT_DAEMON_TOKEN), never via an API response or log.
    writeFileSync(daemonTokenFilePath(dbPath), token, { encoding: "utf8", mode: 0o600 });
  } catch {
    // A read-only vault directory must not stop the daemon from starting;
    // the in-memory token still guards this process.
  }
  return token;
}

export interface VaultRequestOptions {
  readonly daemonToken?: string;
  readonly providedToken?: string;
  readonly providedAgentToken?: string;
  // The private receipt /request returned with awaiting-approval.
  readonly providedGrantReceipt?: string;
  readonly clientPid?: number | undefined;
  // Loopback gateway authentication and device identity stamps. The
  // configured secret is server state; the provided one comes from the
  // caller. Device headers are honored only with a valid gateway secret.
  readonly gatewaySecret?: string;
  // Raw loopback secret presented on /internal/* routes only.
  readonly providedGatewaySecret?: string;
  // Set only after the HTTP layer validated the gateway stamp MAC,
  // freshness window and nonce. Never set from raw header presence.
  readonly gatewayStampValid?: boolean;
  readonly deviceId?: string;
  readonly transport?: string;
  // Vault directory for remote-enable asset creation (CA, gateway cert).
  readonly vaultDir?: string;
}

const UNAUTHORIZED: { status: number; body: unknown } = {
  status: 401,
  body: { error: { _tag: "Unauthorized", message: "unauthorized" } },
};

function isTokenProtected(method: string, path: string): boolean {
  if ((path === "/agents" || path.startsWith("/agents/")) && (method === "GET" || method === "POST")) {
    return true;
  }
  if (method === "GET" && path === "/pending") {
    return true;
  }
  if (
    method === "POST" &&
    (path === "/approve" ||
      path === "/approve-always" ||
      path === "/deny" ||
      path === "/credentials" ||
      path === "/cards" ||
      path === "/unlock" ||
      path === "/setup" ||
      path === "/lock")
  ) {
    return true;
  }
  if ((method === "PATCH" || method === "DELETE") && path.startsWith("/credentials/")) {
    return true;
  }
  if ((path === "/settings/warden" || path === "/settings/security" || path === "/settings/remote") && (method === "GET" || method === "PATCH")) {
    return true;
  }
  if ((path === "/devices" || path.startsWith("/devices/")) && (method === "GET" || method === "POST" || method === "PATCH" || method === "DELETE")) {
    return true;
  }
  if (path === "/settings/warden" && (method === "GET" || method === "PATCH")) {
    return true;
  }
  if (path === "/settings/warden/test" && method === "POST") {
    return true;
  }
  if (
    path === "/settings/warden/key" &&
    (method === "GET" || method === "PUT" || method === "DELETE")
  ) {
    return true;
  }
  if (
    path.startsWith("/settings/local-auth") &&
    method !== "GET" &&
    path !== "/settings/local-auth/verify" &&
    path !== "/settings/local-auth/verify-biometric"
  ) {
    return true;
  }
  return false;
}

function tokenMatches(expected: string, provided: string | undefined): boolean {
  if (provided === undefined) {
    return false;
  }
  const expectedBuf = Buffer.from(expected, "utf8");
  const providedBuf = Buffer.from(provided, "utf8");
  return expectedBuf.length === providedBuf.length && timingSafeEqual(expectedBuf, providedBuf);
}

export async function handleVaultRequest(
  service: VaultServiceService,
  method: string,
  path: string,
  body?: unknown,
  options?: VaultRequestOptions,
): Promise<{ status: number; body: unknown }> {
  // Gateway stamp validation runs before anything else: any request
  // carrying device-identity headers or a gateway secret that does not
  // validate is rejected outright, so a local process can never spoof a
  // remote device and a remote caller can never pose as local.
  const gatewayConfigured = options?.gatewaySecret !== undefined && options.gatewaySecret !== "";
  const gatewayValid = gatewayConfigured && options.gatewayStampValid === true;
  const stampPresent =
    options?.gatewayStampValid !== undefined ||
    options?.deviceId !== undefined ||
    options?.transport !== undefined;
  if (stampPresent && !gatewayValid) {
    return {
      status: 403,
      body: { error: { _tag: "Forbidden", message: "device identity stamps require a valid gateway stamp" } },
    };
  }
  const deviceCtx =
    gatewayValid && options.deviceId !== undefined
      ? { deviceId: options.deviceId, transport: options.transport ?? "unknown" }
      : undefined;
  // A remote-origin request can never exercise human-decision routes even
  // if the daemon token leaked to the remote machine: the gateway strips
  // it, and the daemon ignores any token on a device-stamped request.
  const effectiveProvidedToken = deviceCtx !== undefined ? undefined : options?.providedToken;

  // Fail closed: a protected route with no configured token is denied,
  // never open. Callers that bypass the token (in-process service calls)
  // do not go through this handler's protected routes.
  if (
    isTokenProtected(method, path) &&
    (options?.daemonToken === undefined ||
      options.daemonToken === "" ||
      !tokenMatches(options.daemonToken, effectiveProvidedToken))
  ) {
    return UNAUTHORIZED;
  }

  // Gateway-internal routes: the sibling gateway process only. Not open,
  // not daemon-token routes: the gateway secret alone authorizes them.
  if (path.startsWith("/internal/")) {
    const internalSecretValid =
      gatewayConfigured && tokenMatches(options.gatewaySecret, options.providedGatewaySecret);
    if (!internalSecretValid) {
      return UNAUTHORIZED;
    }
    if (method === "POST" && path === "/internal/pair-begin") {
      const b = (body ?? {}) as Record<string, unknown>;
      if (
        typeof b["code"] !== "string" ||
        typeof b["deviceName"] !== "string" ||
        typeof b["clientPublicKeyPem"] !== "string" ||
        typeof b["clientNonce"] !== "string" ||
        b["code"] === "" ||
        b["clientPublicKeyPem"].length > 4096 ||
        b["clientNonce"] === ""
      ) {
        return BAD_REQUEST;
      }
      const either = await Effect.runPromise(
        Effect.either(
          service.pairBegin({
            code: b["code"],
            deviceName: b["deviceName"],
            platform: typeof b["platform"] === "string" ? (b["platform"]) : "",
            clientPublicKeyPem: b["clientPublicKeyPem"],
            clientNonce: b["clientNonce"],
          }),
        ),
      );
      return either._tag === "Right"
        ? { status: 200, body: either.right }
        : { status: 403, body: { error: { _tag: "PairingFailed", message: either.left } } };
    }
    if (method === "POST" && path === "/internal/pair-sas") {
      const b = (body ?? {}) as Record<string, unknown>;
      if (typeof b["pairingId"] !== "string" || typeof b["sas"] !== "string") {
        return BAD_REQUEST;
      }
      return run(service.attachPairingSas(b["pairingId"], b["sas"]).pipe(Effect.map(() => ({ status: "ok" as const }))));
    }
    if (method === "POST" && path === "/internal/pair-open") {
      // Whether a live, unconfirmed, unexpired pairing session exists.
      // The gateway checks this before doing ANY pairing work so its
      // pairing listener stays inert outside an explicit pairing window.
      return run(service.pairingOpen());
    }
    if (method === "POST" && path === "/internal/pair-status") {
      const b = (body ?? {}) as Record<string, unknown>;
      if (typeof b["pairingId"] !== "string") {
        return BAD_REQUEST;
      }
      return run(service.pairingInternalStatus(b["pairingId"]));
    }
    if (method === "POST" && path === "/internal/device-status") {
      const b = (body ?? {}) as Record<string, unknown>;
      if (typeof b["fingerprint"] !== "string" || b["fingerprint"] === "") {
        return BAD_REQUEST;
      }
      return run(
        service.getDeviceByFingerprint(b["fingerprint"]).pipe(
          Effect.map((device) =>
            device === undefined
              ? { known: false, revoked: true }
              : { known: true, revoked: device.revoked, deviceId: device.id, name: device.name },
          ),
        ),
      );
    }
    return { status: 404, body: { error: { _tag: "NotFound", message: "not found" } } };
  }

  // Liveness probe for the desktop app and the installer smoke test. It
  // is open (no token) and says nothing about the vault's contents.
  if (method === "GET" && path === "/health") {
    return { status: 200, body: { status: "ok", service: "vaultd" } };
  }
  if (method === "GET" && path === "/aliases") {
    return run(
      Effect.all([service.listAliases(), service.listCredentialMeta()]).pipe(
        Effect.map(([aliases, meta]) => ({
          aliases,
          // Cards expose brand + last 4 only: never name, expiry or CVV.
          credentials: meta.map((m) => ({
            alias: m.alias,
            website: m.website,
            kind: m.kind,
            ...(m.card !== undefined ? { card: { brand: m.card.brand, last4: m.card.last4, masked: m.card.masked } } : {}),
          })),
        })),
      ),
    );
  }
  if (method === "GET" && path === "/audit") {
    return run(service.listAudit().pipe(Effect.map((events) => ({ events }))));
  }
  if (method === "POST" && (path === "/agents" || path === "/agents/rotate")) {
    const input = typeof body === "object" && body !== null ? body as Record<string, unknown> : {};
    const id = input["id"]; const name = input["name"];
    if (typeof id !== "string" || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(id) || typeof name !== "string" || name.trim().length === 0 || name.length > 100 || /[\x00-\x1f\x7f]/.test(name)) return BAD_REQUEST;
    return run(service.registerAgent(id, name.trim(), path === "/agents/rotate"));
  }
  if (method === "GET" && path === "/agents") {
    return run(service.listAgents());
  }
  if (method === "POST" && path === "/agents/revoke") {
    const decoded = await decode(RevokeSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    return run(
      service.revokeAgentToken(decoded.target).pipe(
        Effect.map(() => ({ revoked: true, target: decoded.target })),
      ),
    );
  }
  if (method === "GET" && path === "/pending") {
    return run(service.listPendingApprovals().pipe(Effect.map((approvals) => ({ approvals }))));
  }
  if (method === "GET" && path === "/policies") {
    // Schema-validated response: the payload is checked against
    // PoliciesResponseSchema before it leaves the daemon (metadata only).
    // This route is open, so agent bearer tokens are stripped here; they
    // are served only by the token-guarded GET /agents route.
    return run(
      service
        .listPolicies()
        .pipe(
          Effect.map((policies) => ({
            ...policies,
            ...(policies.agents !== undefined
              ? {
                  agents: policies.agents.map((agent) => {
                    const publicAgent: Record<string, unknown> = { ...agent };
                    delete publicAgent["token"];
                    return publicAgent;
                  }),
                }
              : {}),
          })),
          Effect.flatMap((policies) => Schema.decodeUnknown(PoliciesResponseSchema)(policies)),
        ),
    );
  }
  if (method === "GET" && path === "/security/posture") {
    return run(service.getSecurityPosture());
  }
  if (method === "GET" && path === "/settings/security") {
    return run(service.getAgentSecuritySettings());
  }
    if (method === "PATCH" && path === "/settings/security") {
    const decoded = await decode(AgentSecuritySettingsPatchSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    const patch: { strictMode?: boolean; verifyCallerProcess?: boolean } = {};
    if (decoded.strictMode !== undefined) patch.strictMode = decoded.strictMode;
    if (decoded.verifyCallerProcess !== undefined) patch.verifyCallerProcess = decoded.verifyCallerProcess;
    return run(service.updateAgentSecuritySettings(patch));
  }
  if (method === "GET" && path === "/settings/warden") {
    return run(service.getWardenSettings());
  }
  if (method === "PATCH" && path === "/settings/warden") {
    const decoded = await decode(WardenSettingsPatchSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    if (decoded.model !== undefined && decoded.model.trim() === "") {
      return BAD_REQUEST;
    }
    if (decoded.metaApiBaseUrl !== undefined && decoded.metaApiBaseUrl.trim() === "") {
      return BAD_REQUEST;
    }
    if (decoded.localBaseUrl !== undefined && !isLocalBaseUrlAcceptable(decoded.localBaseUrl)) {
      return BAD_REQUEST;
    }
    const patch: WardenSettingsPatch = {
      ...(decoded.provider !== undefined ? { provider: normalizeWardenProvider(decoded.provider) ?? "local" } : {}),
      ...(decoded.model !== undefined ? { model: decoded.model } : {}),
      ...(decoded.effort !== undefined ? { effort: decoded.effort } : {}),
      ...(decoded.metaApiBaseUrl !== undefined ? { metaApiBaseUrl: decoded.metaApiBaseUrl } : {}),
      ...(decoded.localBaseUrl !== undefined ? { localBaseUrl: decoded.localBaseUrl } : {}),
      ...(decoded.localApi !== undefined ? { localApi: decoded.localApi } : {}),
      ...(decoded.localModel !== undefined ? { localModel: decoded.localModel } : {}),
    };
    return run(service.updateWardenSettings(patch));
  }
  if (method === "POST" && path === "/settings/warden/test") {
    return run(service.testWarden());
  }
  if (method === "GET" && path === "/settings/warden/key") {
    return run(service.wardenKeyStatus());
  }
  if (method === "PUT" && path === "/settings/warden/key") {
    const decoded = await decode(WardenKeyPutSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    const key = decoded.key ?? decoded.apiKey ?? decoded.secret;
    if (key === undefined || key.trim() === "" || key.trim().length < WARDEN_KEY_MIN_LENGTH) {
      return BAD_REQUEST;
    }
    return run(service.setWardenKey(key));
  }
  if (method === "DELETE" && path === "/settings/warden/key") {
    return run(service.deleteWardenKey());
  }
    if (method === "GET" && path === "/settings/local-auth") {
    return run(service.getLocalAuthStatus());
  }
  if (method === "PATCH" && path === "/settings/local-auth") {
    const rawPatch = typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
    const patch: {
      enabled?: boolean;
      biometricEnabled?: boolean;
      requireOnApproval?: boolean;
      requireOnLaunch?: boolean;
      requireOnSettings?: boolean;
      autoLockMinutes?: number;
    } = {};
    if (typeof rawPatch["enabled"] === "boolean") patch.enabled = rawPatch["enabled"];
    if (typeof rawPatch["biometricEnabled"] === "boolean") patch.biometricEnabled = rawPatch["biometricEnabled"];
    if (typeof rawPatch["requireOnApproval"] === "boolean") patch.requireOnApproval = rawPatch["requireOnApproval"];
    if (typeof rawPatch["requireOnLaunch"] === "boolean") patch.requireOnLaunch = rawPatch["requireOnLaunch"];
    if (typeof rawPatch["requireOnSettings"] === "boolean") patch.requireOnSettings = rawPatch["requireOnSettings"];
    if (typeof rawPatch["autoLockMinutes"] === "number") patch.autoLockMinutes = rawPatch["autoLockMinutes"];
    return run(service.updateLocalAuthSettings(patch));
  }
  if (method === "POST" && path === "/settings/local-auth/pin") {
    const data = typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
    const pin = data["pin"];
    const currentPin = data["currentPin"];
    if (typeof pin !== "string" || pin.trim().length < 4) {
      return BAD_REQUEST;
    }
    return run(service.setLocalPin(pin.trim(), typeof currentPin === "string" ? currentPin.trim() : undefined));
  }
  if (method === "POST" && path === "/settings/local-auth/verify") {
    const data = typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
    const pin = data["pin"];
    if (typeof pin !== "string") {
      return BAD_REQUEST;
    }
    return run(service.verifyLocalPin(pin.trim()));
  }
  if (method === "POST" && path === "/settings/local-auth/verify-biometric") {
    return run(service.verifyBiometric());
  }
  if (method === "POST" && path === "/enrollments") {
    const decoded = await decode(EnrollmentRequestSchema, body ?? {});
    if (decoded === null || decoded.alias.trim() === "" || decoded.scope.trim() === "" || decoded.alias.length > 128 || decoded.scope.length > 256 || (decoded.website !== undefined && decoded.website.length > 253)) {
      return BAD_REQUEST;
    }
    const alias = decoded.alias.trim();
    if (alias === WARDEN_KEY_ALIAS || !isSafeAlias(alias)) {
      return BAD_REQUEST;
    }
    const scope = decoded.scope.trim();
    const website = (decoded.website ?? "").trim();
    const reason = (decoded.reason ?? "").trim().slice(0, 256);
    const agentId = decoded.agentId !== undefined ? decoded.agentId.trim().slice(0, 128) : "";
    const created = await run(service.createEnrollment(alias, scope, website, reason === "" ? undefined : reason, agentId === "" ? undefined : agentId));
    if (created.status !== 200) { return created; }
    const record = created.body as { enrollmentId: string; alias: string; scope: string; website: string };
    return { status: 201, body: { enrollmentId: record.enrollmentId, deeplink: buildEnrollmentDeeplink(record) } };
  }
  if (method === "GET" && path.startsWith("/enrollments/")) {
    const decodedId = safeDecodeSegment(path.slice("/enrollments/".length));
    if (decodedId === null) { return BAD_REQUEST; }
    const id = decodedId.trim();
    if (id === "" || id.includes("/")) { return BAD_REQUEST; }
    const found = await run(service.getEnrollment(id));
    if (found.status !== 200) { return found; }
    if (found.body === null) { return { status: 404, body: { error: { _tag: "NotFound", message: "enrollment not found" } } }; }
    const record = found.body as { enrollmentId: string; status: string; alias: string; scope: string };
    return { status: 200, body: { status: record.status, alias: record.alias, scope: record.scope } };
  }
  if (method === "GET" && path === "/key/status") {
    return run(service.keyStatus());
  }
  if (method === "POST" && path === "/lock") {
    return run(service.lockVault().pipe(Effect.map(() => ({ locked: true }))));
  }
  if (method === "POST" && path === "/unlock") {
    const decoded = await decode(UnlockSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    const result = await run(service.unlockVault(decoded.passphrase));
    if (result.status !== 200) {
      return result;
    }
    switch (result.body) {
      case "unlocked":
      case "already-unlocked":
        return { status: 200, body: { status: result.body } };
      case "key-mismatch":
        return { status: 409, body: { error: { _tag: "VaultRecoveryRequired", message: "key does not match stored records, or vault data is damaged; restore the matching database and key backup" } } };
      case "wrong-passphrase":
        return { status: 401, body: { error: { _tag: "WrongPassphrase", message: "wrong passphrase" } } };
      case "throttled":
        return { status: 429, body: { error: { _tag: "UnlockThrottled", message: "too many failed attempts; wait and retry" } } };
      case "not-initialized":
        return { status: 409, body: { error: { _tag: "VaultNotInitialized", message: "no vault key yet; create a passphrase first" } } };
      default:
        return { status: 409, body: { error: { _tag: "NotPassphraseMode", message: "vault key is not passphrase-protected; run `metavault key protect`" } } };
    }
  }
  if (method === "POST" && path === "/setup") {
    const decoded = await decode(UnlockSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    const result = await run(service.setupVault(decoded.passphrase));
    if (result.status !== 200) {
      return result;
    }
    switch (result.body) {
      case "initialized":
        return { status: 200, body: { status: "initialized" } };
      case "too-short":
        return { status: 400, body: { error: { _tag: "PassphraseTooShort", message: "passphrase must be at least 12 characters" } } };
      case "already-initialized":
        return { status: 409, body: { error: { _tag: "AlreadyInitialized", message: "the vault already has a key" } } };
      default:
        return { status: 409, body: { error: { _tag: "SetupUnavailable", message: "first-run setup is not enabled for this daemon" } } };
    }
  }
  if (method === "POST" && path === "/cards") {
    const decoded = await decode(CardCredentialSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    const alias = decoded.alias.trim();
    if (alias === "" || alias === WARDEN_KEY_ALIAS || !isSafeAlias(alias)) {
      return BAD_REQUEST;
    }
    const exists = await run(service.hasCredential(alias));
    if (exists.status !== 200) {
      return exists;
    }
    if (exists.body === true) {
      return { status: 409, body: { error: "alias-exists" } };
    }
    const result = await run(
      service
        .seedCardCredential(
          alias,
          {
            number: decoded.number,
            name: decoded.name,
            expMonth: decoded.expMonth,
            expYear: decoded.expYear,
            cvv: decoded.cvv,
          },
          decoded.scope,
          decoded.website,
        )
        .pipe(Effect.map((card) => ({ alias, kind: "card", card }))),
    );
    return result.status === 200 ? { status: 201, body: result.body } : result;
  }
  if (method === "POST" && path === "/credentials") {
    const decoded = await decode(CredentialSchema, body ?? {});
    if (
      decoded === null ||
      decoded.alias.trim() === "" ||
      decoded.scope.trim() === "" ||
      decoded.secret.trim() === ""
    ) {
      return BAD_REQUEST;
    }
    // Duplicate aliases conflict instead of silently overwriting: the
    // store INSERT OR REPLACE stays for CLI/test seeding, but this
    // endpoint never replaces an existing credential.
    const alias = decoded.alias.trim();
    if (alias === WARDEN_KEY_ALIAS || !isSafeAlias(alias)) {
      return BAD_REQUEST;
    }
    const scope = decoded.scope.trim();
    const exists = await run(service.hasCredential(alias));
    if (exists.status !== 200) {
      return exists;
    }
    if (exists.body === true) {
      return { status: 409, body: { error: "alias-exists" } };
    }
    const website = (decoded.website ?? "").trim();
    const enrollmentId = decoded.enrollmentId?.trim();
    const result = await run(
      service
        .seedCredential(alias, scope, decoded.secret, website, enrollmentId !== undefined && enrollmentId !== "" ? enrollmentId : undefined)
        .pipe(Effect.map(() => ({ alias, scope, website }))),
    );
    return result.status === 200 ? { status: 201, body: result.body } : result;
  }
  if ((method === "PATCH" || method === "DELETE") && path.startsWith("/credentials/")) {
    const decodedAlias = safeDecodeSegment(path.slice("/credentials/".length));
    if (decodedAlias === null) {
      return BAD_REQUEST;
    }
    const alias = decodedAlias.trim();
    if (alias === "" || alias.includes("/")) {
      return BAD_REQUEST;
    }
    if (method === "DELETE") {
      const deleted = await run(service.deleteCredential(alias));
      if (deleted.status !== 200) {
        return deleted;
      }
      if (deleted.body === false) {
        return { status: 404, body: { error: { _tag: "NotFound", message: "credential not found" } } };
      }
      return { status: 200, body: { alias, deleted: true } };
    }
    const decoded = await decode(UpdateCredentialSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    if (decoded.scope !== undefined && decoded.scope.trim() === "") {
      return BAD_REQUEST;
    }
    if (decoded.secret !== undefined && decoded.secret !== "" && decoded.secret.trim() === "") {
      return BAD_REQUEST;
    }
    const patch: { scope?: string; website?: string; secret?: string } = {};
    if (decoded.scope !== undefined) patch.scope = decoded.scope;
    if (decoded.website !== undefined) patch.website = decoded.website;
    if (decoded.secret !== undefined) patch.secret = decoded.secret;
    const updated = await run(service.updateCredential(alias, patch));
    if (updated.status !== 200) {
      return updated;
    }
    if (updated.body === null) {
      return { status: 404, body: { error: { _tag: "NotFound", message: "credential not found" } } };
    }
    const meta = updated.body as { scopeCeiling: string; website: string };
    return { status: 200, body: { alias, scope: meta.scopeCeiling, website: meta.website } };
  }
    if (method === "POST" && path === "/request") {
    const decoded = await decode(CapabilityRequestSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    const tokenFromOptions = options?.providedAgentToken;
    const tokenFromBody = decoded.agentToken;
    const token =
      tokenFromOptions !== undefined && tokenFromOptions !== ""
        ? tokenFromOptions
        : tokenFromBody !== undefined && tokenFromBody !== ""
          ? tokenFromBody
          : undefined;

    let verified = false;
    let agentId = decoded.agentId;

    if (token !== undefined) {
      const agentRes = await run(service.getAgentByToken(token.trim()));
      if (agentRes.status === 200 && agentRes.body !== null && agentRes.body !== undefined) {
        const agent = agentRes.body as { id: string; name: string; revoked: boolean };
        if (agent.revoked) {
          return { status: 403, body: { error: { _tag: "Revoked", message: "agent is revoked" } } };
        }
        agentId = agent.id;
        verified = true;
      } else {
        return { status: 401, body: { error: { _tag: "Unauthorized", message: "invalid agent token" } } };
      }
    }

    const secSettingsRes = await run(service.getAgentSecuritySettings());
    const secSettings =
      secSettingsRes.status === 200
        ? (secSettingsRes.body as AgentSecuritySettings)
        : DEFAULT_AGENT_SECURITY_SETTINGS;

    // Defense-in-depth Layer 1: Strict Agent Verification Mode
    if (secSettings.strictMode && !verified) {
      return {
        status: 403,
        body: {
          status: "denied",
          reason: "strict-mode-unverified-blocked",
          error: {
            _tag: "Forbidden",
            message: "Strict agent verification is enabled: unverified agents without a valid token are rejected.",
          },
        },
      };
    }

    // Defense-in-depth Layer 2: Caller Process & Binary Inspection
    // Remote requests carry no meaningful PID: a remote clientPid is
    // self-reported by an untrusted host and is ignored entirely. The
    // authenticated device session is the identity (DD3).
    const clientPid = deviceCtx !== undefined ? undefined : (decoded.clientPid ?? options?.clientPid);
    let clientProcess: string | undefined = deviceCtx !== undefined ? "remote-gateway" : undefined;

    if (secSettings.verifyCallerProcess && deviceCtx === undefined) {
      if (clientPid === undefined) {
        return {
          status: 403,
          body: {
            status: "denied",
            reason: "process-verification-failed",
            error: {
              _tag: "Forbidden",
              message: "Process verification failed: missing caller process PID.",
            },
          },
        };
      }
      const inspectRes = inspectProcess(clientPid);
      if (!inspectRes.ok) {
        return {
          status: 403,
          body: {
            status: "denied",
            reason: "process-verification-failed",
            error: {
              _tag: "Forbidden",
              message: `Caller process verification failed: ${inspectRes.reason ?? "unauthorized process"}`,
            },
          },
        };
      }
      clientProcess = inspectRes.binary;
    } else if (clientPid !== undefined) {
      const inspectRes = inspectProcess(clientPid);
      if (inspectRes.ok) {
        clientProcess = inspectRes.binary;
      }
    }

        const request: CapabilityRequest = {
      agentId,
      ide: decoded.ide,
      tool: decoded.tool,
      alias: decoded.alias,
      requestedScope: decoded.requestedScope,
      reason: decoded.reason,
      verified,
      ...(clientPid !== undefined ? { clientPid } : {}),
      ...(clientProcess !== undefined ? { clientProcess } : {}),
    };
    return run(service.requestCapability(request, token?.trim(), deviceCtx));
  }
  // Agent-visible outcome of one grant. /request answers awaiting-approval
  // and returns at once, so without this an agent could never learn that
  // the human denied (or let expire) its request. Metadata only: it never
  // returns the request details, the executed result or any secret. A
  // grant is readable only with the receipt from its own /request answer;
  // every miss answers the same 404 so ids cannot be probed. The receipt,
  // not an agent token, so a revoked agent still learns its request died.
  if (method === "GET" && path.startsWith("/grants/")) {
    const decodedId = safeDecodeSegment(path.slice("/grants/".length));
    const grantId = decodedId === null ? "" : decodedId.trim();
    const notFound = { status: 404, body: { status: "unknown", error: { _tag: "NotFound", message: "grant not found" } } };
    if (grantId === "" || grantId.includes("/")) { return notFound; }
    // The unguessable receipt from that grant's own /request answer is the
    // authorization, for verified and unverified agents alike. A grant id,
    // an agent name or an agent token without it reads nothing.
    const receipt = options?.providedGrantReceipt?.trim();
    if (receipt === undefined || receipt === "") { return notFound; }
    const receiptOk = await run(service.checkGrantReceipt(grantId, receipt));
    if (receiptOk.status !== 200 || receiptOk.body !== true) { return notFound; }
    const found = await run(service.getGrant(grantId));
    if (found.status !== 200 || found.body === null || found.body === undefined) { return notFound; }
    const grant = found.body as { status: string; expiresAtMs: number };
    const outcome = grantOutcome(grant.status, grant.expiresAtMs, Date.now());
    return { status: 200, body: { grantId, ...outcome } };
  }
  if (method === "POST" && path === "/approve") {
    const decoded = await decode(GrantIdSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    const proof = typeof body === "object" && body !== null ? (body as Record<string, unknown>)["presenceProof"] : undefined;
    return run(service.approve(decoded.grantId, typeof proof === "string" ? proof : undefined));
  }
  if (method === "POST" && path === "/approve-always") {
    const decoded = await decode(GrantIdSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    const proof = typeof body === "object" && body !== null ? (body as Record<string, unknown>)["presenceProof"] : undefined;
    return run(service.approveAlways(decoded.grantId, typeof proof === "string" ? proof : undefined));
  }
  if (method === "POST" && path === "/deny") {
    const decoded = await decode(GrantIdSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    return run(service.deny(decoded.grantId).pipe(Effect.map(() => ({ status: "denied" as const }))));
  }
  if (method === "POST" && path === "/revoke") {
    const decoded = await decode(RevokeSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    return run(service.revoke(decoded.target).pipe(Effect.map(() => ({ status: "revoked" as const }))));
  }

  // Device management and pairing control: every route here is
  // token-guarded (isTokenProtected) and loopback-only. The gateway never
  // forwards them, so remote callers cannot reach device administration.
  if (method === "GET" && path === "/devices") {
    return run(service.listDevices().pipe(Effect.map((devices) => ({ devices }))));
  }
  if (method === "POST" && path === "/devices/pair") {
    return run(service.createPairingSession());
  }
  if (method === "GET" && path === "/devices/pairing") {
    return run(service.getPairingSession().pipe(Effect.map((session) => ({ session: session ?? null }))));
  }
  if (method === "POST" && path === "/devices/pairing/confirm") {
    const b = (body ?? {}) as Record<string, unknown>;
    if (typeof b["pairingId"] !== "string" || b["pairingId"] === "") {
      return BAD_REQUEST;
    }
    return run(service.confirmPairing(b["pairingId"]));
  }
  if (method === "POST" && path === "/devices/pairing/cancel") {
    const b = (body ?? {}) as Record<string, unknown>;
    if (typeof b["pairingId"] !== "string" || b["pairingId"] === "") {
      return BAD_REQUEST;
    }
    return run(service.cancelPairingSession(b["pairingId"]).pipe(Effect.map(() => ({ status: "canceled" as const }))));
  }
  if (method === "POST" && path === "/devices/rename") {
    const b = (body ?? {}) as Record<string, unknown>;
    if (typeof b["id"] !== "string" || typeof b["name"] !== "string" || b["name"].trim() === "" || b["name"].length > 64) {
      return BAD_REQUEST;
    }
    return run(service.renameDevice(b["id"], b["name"]).pipe(Effect.map(() => ({ status: "renamed" as const }))));
  }
  if (method === "POST" && path === "/devices/revoke") {
    const decoded = await decode(RevokeSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    return run(service.revokeDevice(decoded.target).pipe(Effect.map(() => ({ status: "revoked" as const }))));
  }
  if (method === "POST" && path === "/devices/policy") {
    const b = (body ?? {}) as Record<string, unknown>;
    if (
      typeof b["deviceId"] !== "string" ||
      typeof b["alias"] !== "string" ||
      typeof b["allowWrite"] !== "boolean" ||
      b["alias"].trim() === ""
    ) {
      return BAD_REQUEST;
    }
    return run(
      service.setDeviceAliasPolicy(b["deviceId"], b["alias"].trim(), b["allowWrite"]).pipe(
        Effect.map(() => ({ status: "ok" as const })),
      ),
    );
  }
  if (method === "GET" && path.startsWith("/devices/policies/")) {
    const deviceId = decodeURIComponent(path.slice("/devices/policies/".length));
    if (deviceId === "") {
      return BAD_REQUEST;
    }
    return run(service.listDeviceAliasPolicies(deviceId).pipe(Effect.map((policies) => ({ policies }))));
  }
  if (method === "GET" && path === "/settings/remote") {
    return run(service.getRemoteSettings());
  }
  if (method === "PATCH" && path === "/settings/remote") {
    const b = (body ?? {}) as Record<string, unknown>;
    const patch: { enabled?: boolean; host?: string; port?: number; requireAuthForRemoteApproval?: boolean } = {};
    if (b["enabled"] !== undefined) {
      if (typeof b["enabled"] !== "boolean") return BAD_REQUEST;
      patch.enabled = b["enabled"];
    }
    if (b["host"] !== undefined) {
      if (typeof b["host"] !== "string" || b["host"].trim() === "") return BAD_REQUEST;
      const host = b["host"].trim();
      // The gateway never binds a wildcard or plain LAN address. Loopback
      // is always allowed; an overlay address (CGNAT 100.64.0.0/10 or the
      // overlay ULA range) requires the explicit overlay flag.
      // Loopback-only until an explicit transport/interface decision
      // approves anything broader. Overlay ranges alone do not establish
      // tailnet membership, so they are not accepted here.
      const isLoopback = host === "127.0.0.1" || host === "::1" || host === "localhost";
      if (!isLoopback) {
        return {
          status: 400,
          body: { error: { _tag: "BadRequest", message: "gateway host must be a loopback address" } },
        };
      }
      patch.host = host;
    }
    if (b["port"] !== undefined) {
      if (typeof b["port"] !== "number" || !Number.isInteger(b["port"]) || b["port"] < 1024 || b["port"] > 65535) return BAD_REQUEST;
      patch.port = b["port"];
    }
    if (b["requireAuthForRemoteApproval"] !== undefined) {
      if (typeof b["requireAuthForRemoteApproval"] !== "boolean") return BAD_REQUEST;
      patch.requireAuthForRemoteApproval = b["requireAuthForRemoteApproval"];
    }
    const presenceProof = b["presenceProof"];
    const updated = await run(service.updateRemoteSettings(patch, typeof presenceProof === "string" ? presenceProof : undefined));
    if (updated.status !== 200) {
      return updated;
    }
    // Enabling creates the local CA, gateway certificate and gateway
    // secret (all loopback-local, 0600 where secret-bearing). Idempotent.
    if (patch.enabled === true && options?.vaultDir !== undefined) {
      try {
        const ca = ensureVaultCa(options.vaultDir);
        ensureGatewayCertificate(options.vaultDir, ca);
        ensureGatewaySecret(join(options.vaultDir, "metavault.db"));
      } catch (err) {
        return {
          status: 500,
          body: { error: { _tag: "InternalError", message: `failed to prepare remote access: ${err instanceof Error ? err.message : "unknown"}` } },
        };
      }
    }
    return updated;
  }
  return { status: 404, body: { error: { _tag: "NotFound", message: "not found" } } };
}

export interface VaultHttpServerOptions {
  readonly daemonToken?: string;
  readonly gatewaySecret?: string;
  readonly vaultDir?: string;
}

export function createVaultHttpServer(
  service: VaultServiceService,
  options: VaultHttpServerOptions = {},
): Server {
  // Fail closed: without a configured token, guard protected routes with
  // an ephemeral token nobody knows, so they stay 401 over the wire.
  const guardToken =
    options.daemonToken !== undefined && options.daemonToken !== ""
      ? options.daemonToken
      : randomBytes(32).toString("hex");
  return createServer((req, res) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? "/", "http://127.0.0.1");
        const reqMethod = req.method ?? "GET";
        const hasBody = reqMethod === "POST" || reqMethod === "PATCH" || reqMethod === "PUT";
        const bodyResult = hasBody ? await readBodyWithText(req) : undefined;
        const body: unknown = bodyResult?.parsed;
        const bodyText = bodyResult?.text ?? "";
        const header = req.headers[DAEMON_TOKEN_HEADER];
        const authHeader = req.headers["authorization"];
        const bearerToken =
          typeof authHeader === "string" && authHeader.toLowerCase().startsWith("bearer ")
            ? authHeader.slice(7).trim()
            : undefined;
        const providedToken = (Array.isArray(header) ? header[0] : header) ?? bearerToken;
        const agentTokenHeader = req.headers["x-metavault-agent-token"];
        const rawAgentToken = Array.isArray(agentTokenHeader) ? agentTokenHeader[0] : agentTokenHeader;
        const providedAgentToken =
          rawAgentToken ?? (bearerToken !== undefined && bearerToken !== guardToken ? bearerToken : undefined);
        const receiptHeader = req.headers["x-metavault-grant-receipt"];
        const providedGrantReceipt = Array.isArray(receiptHeader) ? receiptHeader[0] : receiptHeader;
        const clientPidHeader = req.headers["x-metavault-client-pid"];
        const rawClientPid = Array.isArray(clientPidHeader) ? clientPidHeader[0] : clientPidHeader;
        const parsedPid = rawClientPid !== undefined ? parseInt(rawClientPid, 10) : undefined;
        const clientPid = parsedPid !== undefined && !Number.isNaN(parsedPid) ? parsedPid : undefined;
        const stampMacHeader = req.headers["x-metavault-gateway-mac"];
        const stampTsHeader = req.headers["x-metavault-gateway-ts"];
        const stampNonceHeader = req.headers["x-metavault-gateway-nonce"];
        const devHeader = req.headers["x-metavault-device-id"];
        const transHeader = req.headers["x-metavault-transport"];
        const legacyStampHeader = req.headers["x-metavault-gateway-secret"];
        const stampMac = Array.isArray(stampMacHeader) ? stampMacHeader[0] : stampMacHeader;
        const stampTs = Array.isArray(stampTsHeader) ? stampTsHeader[0] : stampTsHeader;
        const stampNonce = Array.isArray(stampNonceHeader) ? stampNonceHeader[0] : stampNonceHeader;
        const deviceId = Array.isArray(devHeader) ? devHeader[0] : devHeader;
        const transport = Array.isArray(transHeader) ? transHeader[0] : transHeader;
        // /internal/* routes authenticate with the raw loopback secret and
        // are exempt from device-stamp validation; every other path with
        // any stamp material fails closed unless the MAC validates.
        const isInternalPath = url.pathname.startsWith("/internal/");
        const providedInternalSecret = Array.isArray(legacyStampHeader) ? legacyStampHeader[0] : legacyStampHeader;
        const anyStampHeader =
          !isInternalPath &&
          (stampMac !== undefined ||
            stampTs !== undefined ||
            stampNonce !== undefined ||
            deviceId !== undefined ||
            transport !== undefined ||
            legacyStampHeader !== undefined);
        const stampFields =
          stampMac !== undefined &&
          stampTs !== undefined &&
          stampNonce !== undefined &&
          deviceId !== undefined &&
          transport !== undefined
            ? {
                mac: stampMac,
                deviceId,
                transport,
                method: reqMethod,
                path: url.pathname,
                bodyText,
                timestamp: stampTs,
                nonce: stampNonce,
              }
            : undefined;
        // Valid only when every stamp field is present, the MAC matches,
        // the timestamp is fresh and the nonce is new. Anything else that
        // carries stamp headers fails closed below.
        const gatewayStampValid =
          options.gatewaySecret !== undefined &&
          options.gatewaySecret !== "" &&
          stampFields !== undefined &&
          validateGatewayStamp(options.gatewaySecret, stampFields);
        const out = await handleVaultRequest(service, req.method ?? "GET", url.pathname, body, {
          ...(clientPid !== undefined ? { clientPid } : {}),
          daemonToken: guardToken,
          ...(providedToken !== undefined ? { providedToken } : {}),
          ...(providedAgentToken !== undefined ? { providedAgentToken } : {}),
          ...(providedGrantReceipt !== undefined ? { providedGrantReceipt } : {}),
          ...(options.gatewaySecret !== undefined ? { gatewaySecret: options.gatewaySecret } : {}),
          ...(anyStampHeader ? { gatewayStampValid } : {}),
          ...(isInternalPath && providedInternalSecret !== undefined ? { providedGatewaySecret: providedInternalSecret } : {}),
          ...(gatewayStampValid && deviceId !== undefined ? { deviceId } : {}),
          ...(gatewayStampValid && transport !== undefined ? { transport } : {}),
          ...(options.vaultDir !== undefined ? { vaultDir: options.vaultDir } : {}),
        });
        sendJson(res, out.status, out.body);
      } catch (err) {
        if (err instanceof HttpBodyError) {
          sendJson(res, err.status, {
            error: { _tag: err.status === 413 ? "PayloadTooLarge" : "BadRequest", message: err.message },
          });
        } else {
          sendJson(res, 500, { error: { _tag: "InternalError", message: "internal error" } });
        }
      }
    })();
  });
}

// Master-key source, in order of preference:
//   1. metavault.key.json next to the DB: passphrase-wrapped (scrypt or
//      argon2id). The daemon starts LOCKED and auto-locks when idle.
//   2. METAVAULT_MASTER_KEY, only with METAVAULT_ALLOW_ENV_MASTER_KEY=1.
//   3. A raw key in the OS keychain (legacy `metavault init` before
//      passphrase protection). Accepted with a migration warning.
// METAVAULT_FIRST_RUN_SETUP=1 (set by the desktop app when it starts its
// bundled daemon) lets a daemon with no key start in "uninitialized" mode
// so the app can walk the user through creating a passphrase. Without it
// a keyless daemon refuses to start, as before.
// The local endpoint is the user's own server. Empty clears it; otherwise it
// must be an http(s) URL with no embedded credentials.
export function isLocalBaseUrlAcceptable(raw: string): boolean {
  const value = raw.trim();
  if (value === "") return true;
  try {
    const url = new URL(value);
    return (url.protocol === "http:" || url.protocol === "https:") && url.username === "" && url.password === "";
  } catch {
    return false;
  }
}

export function firstRunSetupEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env["METAVAULT_FIRST_RUN_SETUP"] === "1";
}

// First-run is not recovery. A missing wrapped key must never invite creation
// of a new unrelated key over encrypted records. Inspect without creating or
// migrating a DB; unreadable/unknown existing DBs fail closed too.
export function assertFirstRunDatabaseEmpty(dbPath: string): void {
  if (dbPath === ":memory:" || !existsSync(dbPath)) return;
  let db: Database.Database | undefined;
  try {
    db = new Database(dbPath, { readonly: true, fileMustExist: true });
    const table = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='credentials'").get();
    if (table === undefined) throw new Error("existing database schema is unrecognized");
    const row = db.prepare("SELECT COUNT(*) AS count FROM credentials").get() as {count: number};
    if (row.count !== 0) throw new Error("existing credentials require their original key");
  } catch {
    throw new Error("Vault recovery required: an existing vault has no available key. Do not create a new vault or delete files. Stop MetaVault and restore the matching database and key backup, or recover its legacy OS keychain key.");
  } finally {
    db?.close();
  }
}

// Read-only authentication of every stored record. A damaged record and an
// unrelated readable key cannot be distinguished reliably, so report both.
// Never expose plaintext or mutate DB/key files during this check.
export function assertDatabaseKeyMatches(dbPath: string, key: Buffer): void {
  if (dbPath === ":memory:" || !existsSync(dbPath)) return;
  let db: Database.Database | undefined;
  try {
    db = new Database(dbPath, { readonly: true, fileMustExist: true });
    for (const row of db.prepare("SELECT ciphertext FROM credentials").iterate() as Iterable<{ciphertext: string}>) {
      decryptSecret(key, row.ciphertext);
    }
  } catch {
    throw new Error("Vault recovery required: the key does not authenticate the stored records, or the database is damaged. Stop MetaVault and restore the matching database and key backup. No new key was created.");
  } finally { db?.close(); }
}

export function resolveDaemonKeySession(
  dbPath: string,
  warn: (line: string) => void = (l) => process.stderr.write(`${l}\n`),
  allowFirstRun: boolean = firstRunSetupEnabled(),
): KeySession {
  const validateKey = (key: Buffer) => { assertDatabaseKeyMatches(dbPath, key); };
  const wrapped = readWrappedKeyFile(wrappedKeyFilePath(dbPath));
  if (wrapped !== null) {
    const autoLockMs = autoLockMsFromEnv();
    return createKeySession({ mode: "passphrase", wrapped, validateKey, ...(autoLockMs !== undefined ? { autoLockMs } : {}) });
  }
  const fromEnv = envMasterKeyIfAllowed();
  if (fromEnv !== undefined) {
    warn("warning: using METAVAULT_MASTER_KEY from the environment (opt-in legacy mode; no auto-lock).");
    return createKeySession({ mode: "env", key: fromEnv, validateKey });
  }
  const fromKeychain = retrieveMasterKey();
  if (fromKeychain !== null) {
    warn("warning: master key read unwrapped from the OS keychain (legacy mode; no auto-lock). Run `metavault key protect` to migrate.");
    return createKeySession({ mode: "keychain-legacy", key: fromKeychain, validateKey });
  }
  if (allowFirstRun) {
    assertFirstRunDatabaseEmpty(dbPath);
    const autoLockMs = autoLockMsFromEnv();
    return createFirstRunKeySession({
      wrappedKeyPath: wrappedKeyFilePath(dbPath),
      validateKey,
      ...(autoLockMs !== undefined ? { autoLockMs } : {}),
    });
  }
  throw new Error(
    "master key unavailable: run `metavault init` (passphrase-protected key), or `metavault key protect` to migrate a legacy key",
  );
}

export interface VaultDaemonOptions {
  readonly port?: number;
  readonly dbPath?: string;
  readonly masterKey?: Buffer;
  readonly keySession?: KeySession;
  // Dependency-injection seams (tests pass fakes / local presets through
  // these); production defaults are the real layers below.
  readonly connector?: Layer.Layer<Connector>;
  readonly connectorPresets?: ConnectorPresets;
  readonly brain?: Layer.Layer<Brain>;
  readonly daemonToken?: string;
}

export async function startVaultDaemon(options: VaultDaemonOptions = {}): Promise<Server> {
  const port = options.port ?? Number(metavaultEnv("PORT") ?? "7077");
  const dbPath = options.dbPath ?? metavaultEnv("DB_PATH") ?? join(process.cwd(), "metavault.db");
  const keySession =
    options.keySession ??
    (options.masterKey !== undefined
      ? createKeySession({ mode: "injected", key: options.masterKey })
      : resolveDaemonKeySession(dbPath));
  const daemonToken = options.daemonToken ?? resolveDaemonToken(dbPath);
  const gatewaySecret = loadGatewaySecret(dbPath);
  const vaultDir = dirname(dbPath);
  // The real connector layer (Task 6): approved grants execute against the
  // preset upstream URLs with the secret injected inside the daemon.
  const connectorLayer =
    options.connector ??
    (options.connectorPresets !== undefined
      ? makeConnectorLive(options.connectorPresets)
      : ConnectorLive);
  // Brain is built from stored warden settings and re-read per request,
  // so a settings PATCH takes effect without a daemon restart. The Meta
  // API key is decrypted here, in-daemon only, via the getKey callback.
  const dynamicBrain = Layer.effect(
    Brain,
    Effect.gen(function* () {
      const store = yield* VaultStore;
      const getKey = () =>
        Effect.flatMap(store.getCredential(WARDEN_KEY_ALIAS), (cred) =>
          cred === undefined
            ? Effect.succeed<string | null>(null)
            : Effect.try({
                try: () => decryptSecret(keySession.key(), cred.ciphertext) as string | null,
                catch: () => null,
              }),
        ).pipe(Effect.catchAll(() => Effect.succeed<string | null>(null)));
      return {
        assess: (
          req: Parameters<typeof assessFromSettings>[2],
          historySummary: Parameters<typeof assessFromSettings>[3],
          policyDigest: string,
        ) =>
          Effect.flatMap(store.getWardenSettings(), (settings) =>
            assessFromSettings(settings, getKey, req, historySummary, policyDigest),
          ).pipe(
            Effect.catchTag("StorageError", () =>
              Effect.fail(
                new MarshalUnavailable({
                  message: "MarshalUnavailable: warden settings unavailable",
                }),
              ),
            ),
          ),
      };
    }),
  );
  const storeLayer = VaultStoreLive(dbPath);
  const layers = Layer.mergeAll(
    storeLayer,
    options.brain ?? Layer.provide(dynamicBrain, storeLayer),
    connectorLayer,
  );
  const runtime = ManagedRuntime.make(
    Layer.provide(makeVaultServiceLive({ keySession, vaultDir }), layers),
  );
  const service = await runtime.runPromise(
    Effect.gen(function* () {
      return yield* VaultService;
    }),
  );
  const server = createVaultHttpServer(service, {
    daemonToken,
    ...(gatewaySecret !== undefined ? { gatewaySecret } : {}),
    vaultDir,
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      resolve();
    });
  });
  return server;
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  startVaultDaemon().catch((err: unknown) => {
    process.stderr.write(`${err instanceof Error ? err.message : "failed to start vaultd"}\n`);
    process.exitCode = 1;
  });
}
