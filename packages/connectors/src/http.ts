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
};

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

export function makeConnectorLive(
  presets: ConnectorPresets = DEFAULT_CONNECTOR_PRESETS,
): Layer.Layer<Connector> {
  return Layer.succeed(Connector, {
    execute: (alias, _scope, secret, payload) => {
      const url = presets[alias];
      if (url === undefined) {
        // The core Connector contract admits only ConnectorFailed, so the
        // brief's UnknownAlias surfaces as the alias + message, never a secret.
        return Effect.fail(
          new ConnectorFailed({ alias, message: `UnknownAlias: ${alias}` }),
        );
      }
      return executeHttp({
        url,
        method: "GET",
        secret,
        ...(payload !== undefined ? { body: payload } : {}),
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
