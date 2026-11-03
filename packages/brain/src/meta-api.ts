// Meta Model API warden provider (cloud).
// Verified 2026-11-03 against the official Meta Model API docs,
// https://dev.meta.ai/docs/models : Muse Spark (`muse-spark-1.3`, latest,
// "recommended for new work") and Muse Wonder (`muse-wonder-1.0`) are hosted
// on Meta Model API and served over Chat Completions at
// https://api.meta.ai/v1 (POST /v1/chat/completions answers 401 without a
// key). Model ids are user-editable in Settings (WardenSettings.model); the
// base URL is likewise user-editable (WardenSettings.metaApiBaseUrl) so an
// endpoint change is config, not code.
// The API key is supplied via callback, decrypted in-daemon only, and
// never reaches the prompt, logs, or audit.
import { HttpClient, HttpClientRequest } from "@effect/platform";
import { Effect, Schema } from "effect";
import { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
import type { MarshalDecision } from "../../core/src/types.js";
import { parseMarshalDecision } from "./schema.js";

export const META_API_DOCS_URL = "https://dev.meta.ai/docs/models";
export const DEFAULT_META_API_BASE_URL = "https://api.meta.ai/v1";
export const DEFAULT_META_API_MODEL = "muse-spark-1.3";

const MetaChatResponseSchema = Schema.Struct({
  choices: Schema.NonEmptyArray(
    Schema.Struct({
      message: Schema.Struct({
        content: Schema.String,
      }),
    }),
  ),
});

export interface MetaApiRequest {
  readonly model: string;
  readonly baseUrl: string;
  readonly apiKey: string;
  readonly prompt: string;
}

export function requestMetaApiDecision(
  request: MetaApiRequest,
  timeoutMs: number = 30_000,
): Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput, HttpClient.HttpClient> {
  const base = request.baseUrl.replace(/\/+$/, "");
  const program = Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const httpRequest = HttpClientRequest.post(`${base}/chat/completions`).pipe(
      HttpClientRequest.setHeader("authorization", `Bearer ${request.apiKey}`),
      HttpClientRequest.bodyUnsafeJson({
        model: request.model,
        response_format: { type: "json_object" },
        messages: [{ role: "user", content: request.prompt }],
      }),
    );
    const response = yield* client.execute(httpRequest).pipe(
      Effect.mapError(
        () => new MarshalUnavailable({ message: "MarshalUnavailable: request to Meta API failed" }),
      ),
    );
    if (response.status !== 200) {
      return yield* Effect.fail(
        new MarshalUnavailable({
          message: `MarshalUnavailable: Meta API returned HTTP ${String(response.status)}`,
        }),
      );
    }
    const payload: unknown = yield* response.json.pipe(
      Effect.mapError(
        () => new MarshalInvalidOutput({ message: "MarshalInvalidOutput: Meta API response was not JSON" }),
      ),
    );
    const chat = yield* Schema.decodeUnknown(MetaChatResponseSchema)(payload).pipe(
      Effect.mapError(
        () =>
          new MarshalInvalidOutput({ message: "MarshalInvalidOutput: Meta API response had an unexpected shape" }),
      ),
    );
    return yield* parseMarshalDecision(chat.choices[0].message.content);
  });
  return program.pipe(
    Effect.timeoutFail({
      duration: timeoutMs,
      onTimeout: () => new MarshalUnavailable({ message: "MarshalUnavailable: Meta API request timed out" }),
    }),
  );
}
