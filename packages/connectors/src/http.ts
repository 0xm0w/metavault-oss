import { isCardSecretPayload } from "../../core/src/card.js";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "@effect/platform";
import { Effect, Layer, Stream } from "effect";
import { Connector, type CredentialAuthStyle } from "../../core/src/connector.js";
import { ConnectorFailed } from "../../core/src/errors.js";
import { isWriteScope } from "../../core/src/policy.js";

export { Connector } from "../../core/src/connector.js";
export type { ConnectorService } from "../../core/src/connector.js";
export { ConnectorFailed } from "../../core/src/errors.js";

export interface ExecuteHttpOptions {
  readonly url: string;
  readonly method: string;
  readonly secret: string;
  readonly headerName?: string;
  readonly auth?: CredentialAuthStyle;
  readonly body?: unknown;
}

export interface ExecuteHttpResult {
  readonly status: number;
  readonly data: unknown;
}

export type ConnectorPresets = Readonly<Record<string, string>>;

export const DEFAULT_CONNECTOR_PRESETS: ConnectorPresets = {
  stripe: "https://api.stripe.com/v1/charges",
  github: "https://api.github.com/user/repos",
  cloudflare: "https://api.cloudflare.com/client/v4/user/tokens/verify",
};

// Payload-bearing calls POST to a URL chosen entirely inside this package —
// never from agent input — keyed by `alias:tool`. The preset URL is the
// secret-verification/no-payload endpoint; the route URL is where an
// approved call body (e.g. a GraphQL read) may be sent.
export type ToolRoutes = Readonly<Record<string, string>>;

export const DEFAULT_TOOL_ROUTES: ToolRoutes = {
  "cloudflare:cloudflare-graphql.analytics": "https://api.cloudflare.com/client/v4/graphql",
};

export const DEFAULT_CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4";

export interface ConnectorLiveOptions {
  readonly cloudflareApiBase?: string;
}

const failed = (message: string): ConnectorFailed => new ConnectorFailed({ message });

const REDACTED_SECRET = "[REDACTED]";
// Short tokens still have to be stripped. Four characters is the floor:
// below that, substring replacement mangles ordinary JSON.
const REDACTION_MIN_SECRET_LENGTH = 4;
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

function addRedactionVariants(variants: Set<string>, secret: string): void {
  if (secret.length < REDACTION_MIN_SECRET_LENGTH) return;
  const encoded = Buffer.from(secret, "utf8").toString("base64");
  const encodedUrl = encoded.replace(/\+/g, "-").replace(/\//g, "_");
  const percentUpper = encodeURIComponent(secret);
  const percentLower = percentUpper.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase());
  const jsonEscaped = JSON.stringify(secret).slice(1, -1);
  const jsonSlashEscaped = jsonEscaped.replace(/\//g, "\\/");
  const unicodeEscaped = jsonEscaped
    .replace(/\//g, "\\u002f")
    .replace(/\+/g, "\\u002b")
    .replace(/&/g, "\\u0026")
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/=/g, "\\u003d");
  for (const variant of [secret, percentUpper, percentLower, jsonEscaped, jsonSlashEscaped, unicodeEscaped, encoded, encoded.replace(/=+$/, ""), encodedUrl, encodedUrl.replace(/=+$/, "")]) {
    if (variant.length >= REDACTION_MIN_SECRET_LENGTH) variants.add(variant);
  }
  const bytes = Buffer.from(secret, "utf8");
  for (let pad = 0; pad < 3; pad++) {
    const shifted = Buffer.concat([Buffer.alloc(pad), bytes]).toString("base64");
    const drop = Math.ceil((pad * 8) / 6);
    const sliced = shifted.slice(drop);
    const stripped = sliced.replace(/=+$/, "");
    for (const variant of [sliced, stripped, sliced.replace(/\+/g, "-").replace(/\//g, "_"), stripped.replace(/\+/g, "-").replace(/\//g, "_")]) {
      if (variant.length >= REDACTION_MIN_SECRET_LENGTH) variants.add(variant);
    }
  }
}

/**
 * Replaces every occurrence of the injected credential in a response body
 * with "[REDACTED]" before the body is parsed or returned. Upstream APIs
 * sometimes echo authorization material back (auth-echo verification
 * endpoints, error bodies that repeat headers, token metadata): the calling
 * agent must never receive the secret string it enabled.
 *
 * Variants cover exact text, percent-encoding in both hex cases, JSON string
 * escapes (including \/ , \\u002f, and the Go/Rails \\u0026 \\u003c \\u003e \\u003d
 * forms), Base64 at every 3-byte alignment, and the password half of a
 * basic `user:password` secret. Split/join avoids regex metacharacter surprises.
 */
export function redactSecretFromBody(text: string, secret: string): string {
  if (secret.length < REDACTION_MIN_SECRET_LENGTH) {
    return text;
  }
  const variants = new Set<string>();
  addRedactionVariants(variants, secret);
  const colon = secret.indexOf(":");
  if (colon > 0 && colon < secret.length - 1) {
    addRedactionVariants(variants, secret.slice(colon + 1));
  }
  let out = text;
  for (const variant of variants) {
    out = out.split(variant).join(REDACTED_SECRET);
  }
  return out;
}

export function credentialAuthStyle(publicMeta: string): CredentialAuthStyle {
  if (publicMeta.trim() === "") {
    return "bearer";
  }
  try {
    const parsed = JSON.parse(publicMeta) as { auth?: unknown };
    if (parsed.auth === "api-key" || parsed.auth === "basic" || parsed.auth === "bearer") {
      return parsed.auth;
    }
  } catch {
    // Card public meta and plain website notes stay on bearer.
  }
  return "bearer";
}

function credentialHeader(secret: string, auth: CredentialAuthStyle | undefined, headerName?: string): { readonly name: string; readonly value: string } {
  if (headerName !== undefined) {
    return { name: headerName, value: `Bearer ${secret}` };
  }
  if (auth === "api-key") {
    return { name: "x-api-key", value: secret };
  }
  if (auth === "basic") {
    return { name: "Authorization", value: `Basic ${Buffer.from(secret, "utf8").toString("base64")}` };
  }
  return { name: "Authorization", value: `Bearer ${secret}` };
}

const failedWithStatus = (status: number): ConnectorFailed =>
  new ConnectorFailed({
    status,
    message: `ConnectorFailed: upstream returned HTTP ${String(status)}`,
  });

/**
 * Runs one HTTP call with the secret injected in-daemon.
 *
 * The secret only ever leaves this function as the credential header on the
 * outbound request. Results and `ConnectorFailed` values carry no secret, no
 * headers, and (on failure) no response body. Backed by `@effect/platform`
 * `HttpClient` (fetch), so interruption cancels the in-flight request.
 */
export function executeHttp(
  opts: ExecuteHttpOptions,
): Effect.Effect<ExecuteHttpResult, ConnectorFailed> {
  const program = Effect.gen(function* () {
    yield* Effect.try({
      try: () => new URL(opts.url),
      catch: () => failed("ConnectorFailed: invalid URL"),
    });

    const method = opts.method.toUpperCase();
    let request: HttpClientRequest.HttpClientRequest;
    switch (method) {
      case "GET":
        request = HttpClientRequest.get(opts.url);
        break;
      case "POST":
        request = HttpClientRequest.post(opts.url);
        break;
      case "PUT":
        request = HttpClientRequest.put(opts.url);
        break;
      case "PATCH":
        request = HttpClientRequest.patch(opts.url);
        break;
      case "DELETE":
        request = HttpClientRequest.del(opts.url);
        break;
      case "HEAD":
        request = HttpClientRequest.head(opts.url);
        break;
      case "OPTIONS":
        request = HttpClientRequest.options(opts.url);
        break;
      default:
        return yield* Effect.fail(failed("ConnectorFailed: unsupported method"));
    }

    if (opts.body !== undefined && method !== "GET" && method !== "HEAD") {
      request = yield* HttpClientRequest.bodyJson(opts.body)(request).pipe(
        Effect.mapError(() => failed("ConnectorFailed: request body is not JSON-serializable")),
      );
    }

    const header = credentialHeader(opts.secret, opts.auth, opts.headerName);
    request = request.pipe(HttpClientRequest.setHeader(header.name, header.value));

    const client = yield* HttpClient.HttpClient;
    const response = yield* client.execute(request).pipe(
      Effect.mapError(() => failed("ConnectorFailed: request failed")),
    );
    const status = response.status;
    if (status === 0 || status < 200 || status >= 300) {
      return yield* Effect.fail(failedWithStatus(status));
    }
    const chunks: Uint8Array[] = [];
    let received = 0;
    yield* Stream.runForEach(response.stream, (chunk) => {
      received += chunk.byteLength;
      if (received > MAX_RESPONSE_BYTES) {
        return Effect.fail(failed("ConnectorFailed: response body exceeds 10 MiB"));
      }
      chunks.push(chunk);
      return Effect.void;
    }).pipe(Effect.mapError((err) => (err instanceof ConnectorFailed ? err : failedWithStatus(status))));
    const text = Buffer.concat(chunks).toString("utf8");
    // Redact the credential before parsing: an upstream echo of auth
    // material (headers, token metadata) must not reach the agent.
    const safeText = redactSecretFromBody(text, opts.secret);
    let data: unknown;
    if (safeText === "") {
      data = null;
    } else {
      try {
        data = JSON.parse(safeText) as unknown;
      } catch {
        data = safeText;
      }
    }
    return { status, data };
  });
  return program.pipe(
    Effect.provide(Layer.succeed(FetchHttpClient.RequestInit, { redirect: "manual" })),
    Effect.provide(FetchHttpClient.layer),
  );
}

const DNS_WRITE_MARKERS = [".write", ".create", ".update", ".delete"];
const DNS_ZONE_ID = "[a-f0-9]{32}";
const DNS_PATH = new RegExp(`^/zones(?:/(${DNS_ZONE_ID})(?:/dns_records(?:/(${DNS_ZONE_ID}))?)?)?$`);
const DNS_QUERY_KEYS = new Set(["name", "type", "content", "page", "per_page"]);

function isDnsWriteScope(scope: string): boolean {
  return DNS_WRITE_MARKERS.some((marker) => scope.includes(marker)) || scope.endsWith(":write");
}

interface DnsCall {
  readonly method: string;
  readonly path: string;
  readonly query?: Readonly<Record<string, unknown>>;
  readonly body?: unknown;
}

function parseDnsPayload(payload: unknown): DnsCall | null {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return null;
  }
  const record = payload as Record<string, unknown>;
  if (typeof record["method"] !== "string" || typeof record["path"] !== "string") {
    return null;
  }
  const query = record["query"];
  if (query !== undefined && (typeof query !== "object" || query === null || Array.isArray(query))) {
    return null;
  }
  return {
    method: record["method"],
    path: record["path"],
    ...(query !== undefined ? { query: query as Readonly<Record<string, unknown>> } : {}),
    ...(record["body"] !== undefined ? { body: record["body"] } : {}),
  };
}

// Allowlisted Cloudflare DNS REST call. The host is the connector base,
// never a value from the payload.
function resolveCloudflareDns(
  base: string,
  scope: string,
  payload: unknown,
): { readonly url: string; readonly method: string; readonly body?: unknown } | string {
  const call = parseDnsPayload(payload);
  if (call === null) {
    return "ConnectorFailed: DNS payload must be { method, path, query?, body? }";
  }
  const method = call.method.toUpperCase();
  if (method !== "GET" && method !== "POST" && method !== "PUT" && method !== "PATCH" && method !== "DELETE") {
    return "ConnectorFailed: unsupported DNS method";
  }
  if (
    call.path !== call.path.trim() ||
    !call.path.startsWith("/") ||
    call.path.includes("\\") ||
    call.path.includes("?") ||
    call.path.includes("#") ||
    call.path.includes("://") ||
    call.path.includes("..")
  ) {
    return "ConnectorFailed: DNS path is not allowlisted";
  }
  const match = DNS_PATH.exec(call.path);
  if (match === null) {
    return "ConnectorFailed: DNS path is not allowlisted";
  }
  const recordId = match[2];
  const isRecord = recordId !== undefined;
  const isCollection = call.path.endsWith("/dns_records");
  if (method === "POST" && !isCollection) {
    return "ConnectorFailed: DNS path is not allowlisted";
  }
  if ((method === "PUT" || method === "PATCH" || method === "DELETE") && !isRecord) {
    return "ConnectorFailed: DNS path is not allowlisted";
  }
  if (method !== "GET" && !isDnsWriteScope(scope)) {
    return "ConnectorFailed: DNS write requires a write scope";
  }
  if (call.query !== undefined && method !== "GET") {
    return "ConnectorFailed: DNS query is only allowed on GET";
  }
  const root = base.replace(/\/$/, "");
  let url = `${root}${call.path}`;
  if (call.query !== undefined) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(call.query)) {
      if (!DNS_QUERY_KEYS.has(key) || typeof value !== "string" || value.length === 0 || value.length > 253 || /[\0\r\n&#?]/.test(value)) {
        return "ConnectorFailed: DNS query is not allowlisted";
      }
      params.append(key, value);
    }
    const qs = params.toString();
    if (qs !== "") {
      url = `${url}?${qs}`;
    }
  }
  const sendBody = call.body !== undefined && method !== "GET" && method !== "DELETE";
  return { url, method, ...(sendBody ? { body: call.body } : {}) };
}

const READ_METHODS = new Set(["GET", "HEAD"]);
const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function isReadScope(scope: string): boolean {
  return !isWriteScope(scope) && (scope.includes(".read") || scope.endsWith(":read") || scope === "read");
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "127.0.0.1" || hostname === "localhost" || hostname === "[::1]" || hostname === "::1";
}

function pathIsUnsafe(path: string): boolean {
  if (path !== path.trim() || !path.startsWith("/") || path.startsWith("//")) {
    return true;
  }
  if (
    path.includes("\\") ||
    path.includes("?") ||
    path.includes("#") ||
    path.includes("://") ||
    path.includes("@") ||
    path.includes("..")
  ) {
    return true;
  }
  if (/[\u0000-\u001f\u007f]/.test(path)) {
    return true;
  }
  try {
    const decoded = decodeURIComponent(path);
    if (
      decoded.includes("..") ||
      decoded.includes("\\") ||
      decoded.includes("@") ||
      decoded.includes("://") ||
      /[\u0000-\u001f\u007f]/.test(decoded)
    ) {
      return true;
    }
  } catch {
    return true;
  }
  return false;
}

export interface ScopedRestCall {
  readonly url: string;
  readonly method: string;
  readonly body?: unknown;
}

// Website-pinned REST call. The origin comes from the credential, never
// from the agent. The agent may only choose a path beneath that origin.
export function resolveScopedRest(
  baseUrl: string,
  scope: string,
  payload: unknown,
): ScopedRestCall | string {
  const call = parseDnsPayload(payload);
  if (call === null) {
    return "ConnectorFailed: REST payload must be { method, path, query?, body? }";
  }
  const method = call.method.toUpperCase();
  if (!READ_METHODS.has(method) && !WRITE_METHODS.has(method)) {
    return "ConnectorFailed: unsupported REST method";
  }
  if (pathIsUnsafe(call.path)) {
    return "ConnectorFailed: REST path is not allowed";
  }
  if (READ_METHODS.has(method) && !isReadScope(scope)) {
    return "ConnectorFailed: REST read requires a read scope";
  }
  if (WRITE_METHODS.has(method) && !isWriteScope(scope)) {
    return "ConnectorFailed: REST write requires a write scope";
  }
  let pinned: URL;
  try {
    pinned = new URL(baseUrl);
  } catch {
    return "ConnectorFailed: credential base URL is invalid";
  }
  if (pinned.username !== "" || pinned.password !== "") {
    return "ConnectorFailed: credential base URL is invalid";
  }
  const loopback = isLoopbackHost(pinned.hostname);
  if (pinned.protocol !== "https:" && !(pinned.protocol === "http:" && loopback)) {
    return "ConnectorFailed: credential base URL must be https";
  }
  const rootPath = pinned.pathname.replace(/\/$/, "");
  let next: URL;
  try {
    next = new URL(`${pinned.origin}${rootPath}${call.path}`);
  } catch {
    return "ConnectorFailed: REST path is not allowed";
  }
  if (next.origin !== pinned.origin || !next.pathname.startsWith(rootPath === "" ? "/" : rootPath)) {
    return "ConnectorFailed: REST path is not allowed";
  }
  if (call.query !== undefined) {
    if (!READ_METHODS.has(method)) {
      return "ConnectorFailed: REST query is only allowed on read methods";
    }
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(call.query)) {
      if (!/^[A-Za-z0-9_.-]{1,64}$/.test(key) || typeof value !== "string" || value.length === 0 || value.length > 2000 || /[\u0000-\u001f\u007f]/.test(value)) {
        return "ConnectorFailed: REST query is not allowed";
      }
      params.append(key, value);
    }
    const qs = params.toString();
    if (qs !== "") {
      next.search = qs;
    }
  }
  const sendBody = call.body !== undefined && method !== "GET" && method !== "HEAD" && method !== "DELETE";
  return { url: next.toString(), method, ...(sendBody ? { body: call.body } : {}) };
}

function isRestPayload(payload: unknown): boolean {
  return parseDnsPayload(payload) !== null;
}

function resolveGraphql(
  baseUrl: string,
  scope: string,
  payload: unknown,
): ScopedRestCall | string {
  let text = "";
  try {
    text = JSON.stringify(payload);
  } catch {
    return "ConnectorFailed: GraphQL payload is not JSON";
  }
  const mutating = /\bmutation\b/i.test(text);
  if (mutating && !isWriteScope(scope)) {
    return "ConnectorFailed: GraphQL mutation requires a write scope";
  }
  if (!mutating && !isReadScope(scope)) {
    return "ConnectorFailed: GraphQL query requires a read scope";
  }
  let pinned: URL;
  try {
    pinned = new URL(baseUrl);
  } catch {
    return "ConnectorFailed: credential base URL is invalid";
  }
  if (pinned.username !== "" || pinned.password !== "" || (pinned.protocol !== "https:" && !(pinned.protocol === "http:" && isLoopbackHost(pinned.hostname)))) {
    return "ConnectorFailed: credential base URL must be https";
  }
  if (pinned.pathname === "/" || pinned.pathname === "") {
    pinned.pathname = "/graphql";
  }
  return { url: pinned.toString(), method: "POST", body: payload };
}

export function makeConnectorLive(
  presets: ConnectorPresets = DEFAULT_CONNECTOR_PRESETS,
  toolRoutes: ToolRoutes = DEFAULT_TOOL_ROUTES,
  options: ConnectorLiveOptions = {},
): Layer.Layer<Connector> {
  const cloudflareApiBase = options.cloudflareApiBase ?? DEFAULT_CLOUDFLARE_API_BASE;
  return Layer.succeed(Connector, {
    execute: (alias, scope, secret, payload, tool, route) => {
      // Defense in depth: a payment card is never sent as a bearer token.
      if (isCardSecretPayload(secret)) {
        return Effect.fail(
          new ConnectorFailed({ alias, message: "card credentials cannot be sent by the HTTP connector" }),
        );
      }
      const baseUrl = route?.baseUrl?.trim() ?? "";
      const dynamicTool = tool === "rest.call" || tool === "graphql.call" || (baseUrl !== "" && isRestPayload(payload));
      if (dynamicTool) {
        if (baseUrl === "") {
          return Effect.fail(
            new ConnectorFailed({
              alias,
              message: "NoConnectorRoute: credential has no pinned base URL",
            }),
          );
        }
        const resolved =
          tool === "graphql.call" && !isRestPayload(payload)
            ? resolveGraphql(baseUrl, scope, payload)
            : resolveScopedRest(baseUrl, scope, payload);
        if (typeof resolved === "string") {
          return Effect.fail(new ConnectorFailed({ alias, message: resolved }));
        }
        return executeHttp({
          url: resolved.url,
          method: resolved.method,
          secret,
          ...(route?.auth !== undefined ? { auth: route.auth } : {}),
          ...(resolved.body !== undefined ? { body: resolved.body } : {}),
        }).pipe(
          Effect.mapError(
            (err) =>
              new ConnectorFailed({
                alias,
                ...(err.status !== undefined ? { status: err.status } : {}),
                message: err.message,
              }),
          ),
        );
      }
      const url = presets[alias];
      if (url === undefined) {
        // The core Connector contract admits only ConnectorFailed, so the
        // brief's UnknownAlias surfaces as the alias + message, never a secret.
        return Effect.fail(
          new ConnectorFailed({ alias, message: `UnknownAlias: ${alias}` }),
        );
      }
      if (payload === undefined) {
        return executeHttp({
          url,
          method: "GET",
          secret,
        }).pipe(
          Effect.mapError(
            (err) =>
              new ConnectorFailed({
                alias,
                ...(err.status !== undefined ? { status: err.status } : {}),
                message: err.message,
              }),
          ),
        );
      }
      if (alias === "cloudflare" && tool === "cloudflare.dns") {
        const resolved = resolveCloudflareDns(cloudflareApiBase, scope, payload);
        if (typeof resolved === "string") {
          return Effect.fail(new ConnectorFailed({ alias, message: resolved }));
        }
        return executeHttp({
          url: resolved.url,
          method: resolved.method,
          secret,
          ...(resolved.body !== undefined ? { body: resolved.body } : {}),
        }).pipe(
          Effect.mapError(
            (err) =>
              new ConnectorFailed({
                alias,
                ...(err.status !== undefined ? { status: err.status } : {}),
                message: err.message,
              }),
          ),
        );
      }
      const routeKey = `${alias}:${typeof tool === "string" ? tool : ""}`;
      const fixedRoute = toolRoutes[routeKey];
      if (fixedRoute !== undefined) {
        let serialized = "";
        try {
          serialized = JSON.stringify(payload);
        } catch {
          return Effect.fail(new ConnectorFailed({ alias, message: "ConnectorFailed: GraphQL payload is not JSON" }));
        }
        if (/\bmutation\b/i.test(serialized) && !isWriteScope(scope)) {
          return Effect.fail(new ConnectorFailed({ alias, message: "ConnectorFailed: GraphQL mutation requires a write scope" }));
        }
        return executeHttp({
          url: fixedRoute,
          method: "POST",
          secret,
          ...(route?.auth !== undefined ? { auth: route.auth } : {}),
          body: payload,
        }).pipe(
          Effect.mapError(
            (err) =>
              new ConnectorFailed({
                alias,
                ...(err.status !== undefined ? { status: err.status } : {}),
                message: err.message,
              }),
          ),
        );
      }
      return Effect.fail(
        new ConnectorFailed({
          alias,
          message: `NoConnectorRoute: no payload route is defined for "${routeKey}"`,
        }),
      );
    },
  });
}

export const ConnectorLive: Layer.Layer<Connector> = makeConnectorLive();
