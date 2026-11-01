import { randomBytes, timingSafeEqual } from "node:crypto";
import { writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { Cause, Effect, Exit, Layer, ManagedRuntime, Schema } from "effect";
import { assessFromSettings, Brain, MarshalUnavailable } from "../../brain/src/brain.js";
import { ConnectorLive, makeConnectorLive, type ConnectorPresets } from "../../connectors/src/http.js";
import { Connector } from "../../core/src/connector.js";
import { WARDEN_KEY_ALIAS, WARDEN_KEY_MIN_LENGTH } from "../../core/src/settings.js";
import { decryptSecret } from "../../core/src/crypto.js";
import { retrieveMasterKey } from "../../core/src/keychain.js";
import { VaultStore, VaultStoreLive } from "../../core/src/storage.js";
import type { CapabilityRequest } from "../../core/src/types.js";
import {
  CapabilityRequestSchema,
  CredentialSchema,
  EnrollmentRequestSchema,
  GrantIdSchema,
  PoliciesResponseSchema,
  RevokeSchema,
  UpdateCredentialSchema,
  WardenKeyPutSchema,
  WardenSettingsPatchSchema,
} from "./schemas.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "./service.js";

export {
  CapabilityRequestSchema,
  CredentialSchema,
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
  return `openvault://add?${params.toString()}`;
}

export function statusForErrorTag(tag: string): number {
  switch (tag) {
    case "GrantExpired":
    case "GrantRevoked":
      return 409;
    case "PolicyDenied":
    case "UnknownAlias":
      return 403;
    case "ConnectorFailed":
      return 502;
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

async function readBody(req: IncomingMessage): Promise<unknown> {
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
    return {};
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new HttpBodyError(400, "malformed JSON body");
  }
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

export const DAEMON_TOKEN_HEADER = "x-openvault-token";

// The daemon token gates the human-decision routes. Without it any local
// process (including the agent asking for a capability) could approve its
// own grants, so /approve, /approve-always, /deny and the pending queue
// require it. Agent-facing and safe-direction routes (/request, /aliases,
// /audit, /policies, /revoke) stay open: requesting never grants anything
// and revoking only ever removes access.
export function daemonTokenFilePath(dbPath: string): string {
  return join(dirname(dbPath), "openvault.token");
}

export function resolveDaemonToken(dbPath: string): string {
  const fromEnv = process.env["OPENVAULT_DAEMON_TOKEN"];
  if (fromEnv !== undefined && fromEnv !== "") {
    return fromEnv;
  }
  const token = randomBytes(32).toString("hex");
  try {
    // Best-effort restrictive perms; the token is exposed only via this
    // file (or OPENVAULT_DAEMON_TOKEN), never via an API response or log.
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
}

const UNAUTHORIZED: { status: number; body: unknown } = {
  status: 401,
  body: { error: { _tag: "Unauthorized", message: "unauthorized" } },
};

function isTokenProtected(method: string, path: string): boolean {
  if (method === "GET" && path === "/pending") {
    return true;
  }
  if (
    method === "POST" &&
    (path === "/approve" || path === "/approve-always" || path === "/deny" || path === "/credentials")
  ) {
    return true;
  }
  if ((method === "PATCH" || method === "DELETE") && path.startsWith("/credentials/")) {
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
  // Fail closed: a protected route with no configured token is denied,
  // never open. Callers that bypass the token (in-process service calls)
  // do not go through this handler's protected routes.
  if (
    isTokenProtected(method, path) &&
    (options?.daemonToken === undefined ||
      options.daemonToken === "" ||
      !tokenMatches(options.daemonToken, options.providedToken))
  ) {
    return UNAUTHORIZED;
  }
  if (method === "GET" && path === "/aliases") {
    return run(
      Effect.all([service.listAliases(), service.listCredentialMeta()]).pipe(
        Effect.map(([aliases, meta]) => ({
          aliases,
          credentials: meta.map((m) => ({ alias: m.alias, website: m.website })),
        })),
      ),
    );
  }
  if (method === "GET" && path === "/audit") {
    return run(service.listAudit().pipe(Effect.map((events) => ({ events }))));
  }
  if (method === "GET" && path === "/pending") {
    return run(service.listPendingApprovals().pipe(Effect.map((approvals) => ({ approvals }))));
  }
  if (method === "GET" && path === "/policies") {
    // Schema-validated response: the payload is checked against
    // PoliciesResponseSchema before it leaves the daemon (metadata only).
    return run(
      service
        .listPolicies()
        .pipe(
          Effect.flatMap((policies) => Schema.decodeUnknown(PoliciesResponseSchema)(policies)),
        ),
    );
  }
  if (method === "GET" && path === "/security/posture") {
    return run(service.getSecurityPosture());
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
    const patch: {
      provider?: "none" | "ollama" | "meta-api";
      model?: string;
      effort?: "fast" | "standard" | "deep";
      metaApiBaseUrl?: string;
    } = {};
    if (decoded.provider !== undefined) patch.provider = decoded.provider;
    if (decoded.model !== undefined) patch.model = decoded.model;
    if (decoded.effort !== undefined) patch.effort = decoded.effort;
    if (decoded.metaApiBaseUrl !== undefined) patch.metaApiBaseUrl = decoded.metaApiBaseUrl;
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
    const request: CapabilityRequest = decoded;
    return run(service.requestCapability(request));
  }
  if (method === "POST" && path === "/approve") {
    const decoded = await decode(GrantIdSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    return run(service.approve(decoded.grantId));
  }
  if (method === "POST" && path === "/approve-always") {
    const decoded = await decode(GrantIdSchema, body ?? {});
    if (decoded === null) {
      return BAD_REQUEST;
    }
    return run(service.approveAlways(decoded.grantId));
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
  return { status: 404, body: { error: { _tag: "NotFound", message: "not found" } } };
}

export interface VaultHttpServerOptions {
  readonly daemonToken?: string;
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
        const body: unknown =
          reqMethod === "POST" || reqMethod === "PATCH" || reqMethod === "PUT"
            ? await readBody(req)
            : undefined;
        const header = req.headers[DAEMON_TOKEN_HEADER];
        const authHeader = req.headers["authorization"];
        const bearerToken =
          typeof authHeader === "string" && authHeader.toLowerCase().startsWith("bearer ")
            ? authHeader.slice(7).trim()
            : undefined;
        const providedToken = (Array.isArray(header) ? header[0] : header) ?? bearerToken;
        const out = await handleVaultRequest(service, req.method ?? "GET", url.pathname, body, {
          daemonToken: guardToken,
          ...(providedToken !== undefined ? { providedToken } : {}),
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

export function resolveDaemonMasterKey(): Buffer {
  const fromEnv = process.env["OPENVAULT_MASTER_KEY"];
  if (fromEnv !== undefined && fromEnv !== "") {
    const decoded = Buffer.from(fromEnv, "base64");
    if (decoded.length !== 32) {
      throw new Error("OPENVAULT_MASTER_KEY must be base64-encoded 32 bytes");
    }
    return decoded;
  }
  const fromKeychain = retrieveMasterKey();
  if (fromKeychain !== null) {
    return fromKeychain;
  }
  throw new Error(
    "master key unavailable: set OPENVAULT_MASTER_KEY (base64, 32 bytes) or store it in the OS keychain",
  );
}

export interface VaultDaemonOptions {
  readonly port?: number;
  readonly dbPath?: string;
  readonly masterKey?: Buffer;
  // Dependency-injection seams (tests pass fakes / local presets through
  // these); production defaults are the real layers below.
  readonly connector?: Layer.Layer<Connector>;
  readonly connectorPresets?: ConnectorPresets;
  readonly brain?: Layer.Layer<Brain>;
  readonly daemonToken?: string;
}

export async function startVaultDaemon(options: VaultDaemonOptions = {}): Promise<Server> {
  const masterKey = options.masterKey ?? resolveDaemonMasterKey();
  const port = options.port ?? Number(process.env["OPENVAULT_PORT"] ?? "7077");
  const dbPath = options.dbPath ?? join(process.cwd(), "openvault.db");
  const daemonToken = options.daemonToken ?? resolveDaemonToken(dbPath);
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
                try: () => decryptSecret(masterKey, cred.ciphertext) as string | null,
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
  const storeLayer = VaultStoreLive(dbPath, masterKey);
  const layers = Layer.mergeAll(
    storeLayer,
    options.brain ?? Layer.provide(dynamicBrain, storeLayer),
    connectorLayer,
  );
  const runtime = ManagedRuntime.make(
    Layer.provide(makeVaultServiceLive({ masterKey }), layers),
  );
  const service = await runtime.runPromise(
    Effect.gen(function* () {
      return yield* VaultService;
    }),
  );
  const server = createVaultHttpServer(service, { daemonToken });
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
