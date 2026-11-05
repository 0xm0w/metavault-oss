import { isCardSecretPayload } from "../../core/src/card.js";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "@effect/platform";
import { Effect, Layer } from "effect";
import { Connector } from "../../core/src/connector.js";
import { ConnectorFailed } from "../../core/src/errors.js";

export { Connector } from "../../core/src/connector.js";
export type { ConnectorService } from "../../core/src/connector.js";
export { ConnectorFailed } from "../../core/src/errors.js";

export interface ExecuteHttpOptions {
  readonly url: string;
  readonly method: string;
  readonly secret: string;
  readonly headerName?: string;
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

    const headerName = opts.headerName ?? "Authorization";
    request = request.pipe(HttpClientRequest.setHeader(headerName, `Bearer ${opts.secret}`));

    const client = yield* HttpClient.HttpClient;
    const response = yield* client.execute(request).pipe(
      Effect.mapError(() => failed("ConnectorFailed: request failed")),
    );
    const status = response.status;
    if (status < 200 || status >= 300) {
      return yield* Effect.fail(failedWithStatus(status));
    }
    const text = yield* response.text.pipe(
      Effect.mapError(() => failedWithStatus(status)),
    );
    let data: unknown;
    if (text === "") {
      data = null;
    } else {
      try {
        data = JSON.parse(text) as unknown;
      } catch {
        data = text;
      }
    }
    return { status, data };
  });
  return program.pipe(Effect.provide(FetchHttpClient.layer));
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

export function makeConnectorLive(
  presets: ConnectorPresets = DEFAULT_CONNECTOR_PRESETS,
  toolRoutes: ToolRoutes = DEFAULT_TOOL_ROUTES,
  options: ConnectorLiveOptions = {},
): Layer.Layer<Connector> {
  const cloudflareApiBase = options.cloudflareApiBase ?? DEFAULT_CLOUDFLARE_API_BASE;
  return Layer.succeed(Connector, {
    execute: (alias, scope, secret, payload, tool) => {
      const url = presets[alias];
      if (url === undefined) {
        // The core Connector contract admits only ConnectorFailed, so the
        // brief's UnknownAlias surfaces as the alias + message, never a secret.
        return Effect.fail(
          new ConnectorFailed({ alias, message: `UnknownAlias: ${alias}` }),
        );
      }
      // Defense in depth: a payment card is never sent as a bearer token.
      if (isCardSecretPayload(secret)) {
        return Effect.fail(
          new ConnectorFailed({ alias, message: "card credentials cannot be sent by the HTTP connector" }),
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
      const route = toolRoutes[routeKey];
      if (route === undefined) {
        return Effect.fail(
          new ConnectorFailed({
            alias,
            message: `NoConnectorRoute: no payload route is defined for "${routeKey}"`,
          }),
        );
      }
      return executeHttp({
        url: route,
        method: "POST",
        secret,
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
    },
  });
}

export const ConnectorLive: Layer.Layer<Connector> = makeConnectorLive();
