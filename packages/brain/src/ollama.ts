// Bring-your-own local warden endpoint. MetaVault does not bundle, download,
// or manage any model: the user points Settings at a server they already run,
// either Ollama (POST {base}/api/chat) or any OpenAI-compatible server
// (POST {base}/chat/completions). A Meta open model such as Muse Glimmer
// (https://ollama.com/library/muse-glimmer) is the suggested choice.
// If the endpoint is unset, unreachable, or answers badly, the request fails
// with MarshalUnavailable / MarshalInvalidOutput and policy asks the human.
import { FetchHttpClient, HttpClient, HttpClientRequest } from "@effect/platform";
import { Effect, Schema } from "effect";
import { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
import type { LocalEndpointApi } from "../../core/src/settings.js";
import type { MarshalDecision } from "../../core/src/types.js";
import { parseMarshalDecision } from "./schema.js";

export const DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434";
export const OLLAMA_CHAT_URL = `${DEFAULT_OLLAMA_BASE_URL}/api/chat`;

// Suggested model for a local endpoint (a Meta open model). Only a
// placeholder: it is never pulled or downloaded by MetaVault.
export const DEFAULT_MARSHAL_MODEL = "muse-glimmer:30b";

// Muse Glimmer reads a "Reasoning strength" line from the system block; other
// models treat it as a plain instruction to answer briefly in JSON.
export const MUSE_GLIMMER_SYSTEM_PROMPT =
  "Reasoning strength: low. Think briefly, then reply with the strict JSON object only.";

export const DEFAULT_OLLAMA_TIMEOUT_MS = 120_000;

export interface LocalEndpoint {
  readonly baseUrl: string;
  readonly api: LocalEndpointApi;
  readonly model: string;
}

const OllamaChatResponseSchema = Schema.Struct({
  message: Schema.Struct({ content: Schema.String }),
});

const OpenAiChatResponseSchema = Schema.Struct({
  choices: Schema.NonEmptyArray(Schema.Struct({ message: Schema.Struct({ content: Schema.String }) })),
});

function trimBase(baseUrl: string): string {
  return baseUrl.trim().replace(/\/+$/, "");
}

function postJson<A, I>(
  label: string,
  url: string,
  body: unknown,
  schema: Schema.Schema<A, I>,
  pick: (a: A) => string,
  timeoutMs: number,
): Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput, HttpClient.HttpClient> {
  const program = Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const request = HttpClientRequest.post(url).pipe(HttpClientRequest.bodyUnsafeJson(body));
    const response = yield* client.execute(request).pipe(
      Effect.mapError(() => new MarshalUnavailable({ message: `MarshalUnavailable: request to ${label} failed` })),
    );
    if (response.status !== 200) {
      return yield* Effect.fail(
        new MarshalUnavailable({ message: `MarshalUnavailable: ${label} returned HTTP ${String(response.status)}` }),
      );
    }
    const payload: unknown = yield* response.json.pipe(
      Effect.mapError(() => new MarshalInvalidOutput({ message: `MarshalInvalidOutput: ${label} response was not JSON` })),
    );
    const decoded = yield* Schema.decodeUnknown(schema)(payload).pipe(
      Effect.mapError(
        () => new MarshalInvalidOutput({ message: `MarshalInvalidOutput: ${label} response had an unexpected shape` }),
      ),
    );
    return yield* parseMarshalDecision(pick(decoded));
  });
  return program.pipe(
    Effect.timeoutFail({
      duration: timeoutMs,
      onTimeout: () => new MarshalUnavailable({ message: `MarshalUnavailable: ${label} request timed out` }),
    }),
  );
}

export function requestOllamaDecision(
  model: string,
  prompt: string,
  timeoutMs: number = DEFAULT_OLLAMA_TIMEOUT_MS,
  baseUrl: string = DEFAULT_OLLAMA_BASE_URL,
): Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput, HttpClient.HttpClient> {
  return postJson(
    "Ollama",
    `${trimBase(baseUrl)}/api/chat`,
    {
      model,
      format: "json",
      stream: false,
      messages: [
        { role: "system", content: MUSE_GLIMMER_SYSTEM_PROMPT },
        { role: "user", content: prompt },
      ],
    },
    OllamaChatResponseSchema,
    (chat) => chat.message.content,
    timeoutMs,
  );
}

export function requestOpenAiCompatibleDecision(
  model: string,
  prompt: string,
  timeoutMs: number,
  baseUrl: string,
): Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput, HttpClient.HttpClient> {
  return postJson(
    "local endpoint",
    `${trimBase(baseUrl)}/chat/completions`,
    {
      model,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: MUSE_GLIMMER_SYSTEM_PROMPT },
        { role: "user", content: prompt },
      ],
    },
    OpenAiChatResponseSchema,
    (chat) => chat.choices[0].message.content,
    timeoutMs,
  );
}

export type LocalInferenceHandler = (
  endpoint: LocalEndpoint,
  prompt: string,
  timeoutMs: number,
) => Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput>;

export const httpLocalHandler: LocalInferenceHandler = (endpoint, prompt, timeoutMs) => {
  if (endpoint.baseUrl.trim() === "" || endpoint.model.trim() === "") {
    return Effect.fail(new MarshalUnavailable({ message: "MarshalUnavailable: local endpoint not configured" }));
  }
  const call =
    endpoint.api === "openai"
      ? requestOpenAiCompatibleDecision(endpoint.model.trim(), prompt, timeoutMs, endpoint.baseUrl)
      : requestOllamaDecision(endpoint.model.trim(), prompt, timeoutMs, endpoint.baseUrl);
  return call.pipe(Effect.provide(FetchHttpClient.layer));
};

let registeredHandler: LocalInferenceHandler = httpLocalHandler;

// Test seam. Passing null restores the HTTP handler.
export function setLocalInferenceHandler(handler: LocalInferenceHandler | null): void {
  registeredHandler = handler ?? httpLocalHandler;
}

export function requestLocalDecision(
  endpoint: LocalEndpoint,
  prompt: string,
  timeoutMs: number = DEFAULT_OLLAMA_TIMEOUT_MS,
): Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput> {
  return registeredHandler(endpoint, prompt, timeoutMs);
}
