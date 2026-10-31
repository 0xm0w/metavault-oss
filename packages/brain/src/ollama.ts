import { HttpClient, HttpClientRequest } from "@effect/platform";
import { Effect, Schema } from "effect";
import { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
import type { MarshalDecision } from "../../core/src/types.js";
import { parseMarshalDecision } from "./schema.js";

export const OLLAMA_CHAT_URL = "http://localhost:11434/api/chat";
export const DEFAULT_MARSHAL_MODEL = "llama3.2:3b";

const OllamaChatResponseSchema = Schema.Struct({
  message: Schema.Struct({
    content: Schema.String,
  }),
});

export function requestOllamaDecision(
  model: string,
  prompt: string,
): Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput, HttpClient.HttpClient> {
  const program = Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const request = HttpClientRequest.post(OLLAMA_CHAT_URL).pipe(
      HttpClientRequest.bodyUnsafeJson({
        model,
        format: "json",
        stream: false,
        messages: [{ role: "user", content: prompt }],
      }),
    );
    const response = yield* client.execute(request).pipe(
      Effect.mapError(
        () => new MarshalUnavailable({ message: "MarshalUnavailable: request to Ollama failed" }),
      ),
    );
    if (response.status !== 200) {
      return yield* Effect.fail(
        new MarshalUnavailable({
          message: `MarshalUnavailable: Ollama returned HTTP ${String(response.status)}`,
        }),
      );
    }
    const payload: unknown = yield* response.json.pipe(
      Effect.mapError(
        () => new MarshalInvalidOutput({ message: "MarshalInvalidOutput: Ollama response was not JSON" }),
      ),
    );
    const chat = yield* Schema.decodeUnknown(OllamaChatResponseSchema)(payload).pipe(
      Effect.mapError(
        () =>
          new MarshalInvalidOutput({ message: "MarshalInvalidOutput: Ollama response had an unexpected shape" }),
      ),
    );
    return yield* parseMarshalDecision(chat.message.content);
  });
  return program.pipe(
    Effect.timeoutFail({
      duration: "10 seconds",
      onTimeout: () => new MarshalUnavailable({ message: "MarshalUnavailable: Ollama request timed out" }),
    }),
  );
}
