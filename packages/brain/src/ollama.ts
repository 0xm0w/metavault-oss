import { MUSE_GLIMMER_IQ3_XXS_TAG } from "../../core/src/settings.js";
import { HttpClient, HttpClientRequest } from "@effect/platform";
import { Effect, Schema } from "effect";
import { metavaultEnv } from "../../core/src/env.js";
import { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
import type { MarshalDecision } from "../../core/src/types.js";
import { parseMarshalDecision } from "./schema.js";

export const DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434";
export const OLLAMA_CHAT_URL = `${DEFAULT_OLLAMA_BASE_URL}/api/chat`;

// METAVAULT_OLLAMA_URL overrides the Ollama base URL (same variable the CLI
// reads for `metavault model pull`).
export function ollamaChatUrl(): string {
  const raw = metavaultEnv("OLLAMA_URL")?.trim();
  const base = raw !== undefined && raw !== "" ? raw.replace(/\/+$/, "") : DEFAULT_OLLAMA_BASE_URL;
  return `${base}/api/chat`;
}
// Local fallback marshal: Meta Muse Glimmer 30B, official Q4_K_M build.
// Ollama library tag (needs Ollama >= 0.32.7): https://ollama.com/library/muse-glimmer
// Source weights (Apache 2.0): https://huggingface.co/meta-models/Muse-Glimmer-30B-GGUF
//   file Muse-Glimmer-30B-KQuant-17GB-Q4_K_M.gguf (16,756,683,904 bytes)
// No official IQ2_XXS build is published, so Q4_K_M is the smallest official quant.
export const DEFAULT_MARSHAL_MODEL = "muse-glimmer:30b";
export const MUSE_GLIMMER_GGUF_REPO = "meta-models/Muse-Glimmer-30B-GGUF";
export const MUSE_GLIMMER_GGUF_FILE = "Muse-Glimmer-30B-KQuant-17GB-Q4_K_M.gguf";
export const MUSE_GLIMMER_QUANT = "Q4_K_M";

// Muse Glimmer always reasons before it answers (the chat template opens the
// thinking channel unconditionally). The template's system block carries a
// "Reasoning strength: <level>." line; we ask for the lowest level so the
// marshal spends as few thinking tokens as possible on a metadata-only check.
export const MUSE_GLIMMER_SYSTEM_PROMPT =
  "Reasoning strength: low. Think briefly, then reply with the strict JSON object only.";

// A 30B reasoning model on consumer hardware needs far more than the 10s the
// old 3B marshal got. Callers normally pass an effort-derived timeout.
export const DEFAULT_OLLAMA_TIMEOUT_MS = 120_000;

export interface OllamaModelInfo {
  readonly id: string;
  readonly tier: "Medium" | "High" | "Maximum-local";
  readonly label: string;
}

export const OLLAMA_MODELS: readonly OllamaModelInfo[] = [
  { id: "muse-glimmer:30b", tier: "High", label: "Muse Glimmer 30B Q4_K_M — local (~18 GB, 24 GB VRAM)" },
  // Optional, not the default: unsloth UD-IQ3_XXS, 13.13 GB file
  // (https://huggingface.co/unsloth/Muse-Glimmer-30B-GGUF). Not yet benchmarked.
  { id: MUSE_GLIMMER_IQ3_XXS_TAG, tier: "Medium", label: "Muse Glimmer 30B UD-IQ3_XXS (unsloth) — local (13.1 GB file, not yet benchmarked)" },
];

const OllamaChatResponseSchema = Schema.Struct({
  message: Schema.Struct({
    content: Schema.String,
  }),
});

export function requestOllamaDecision(
  model: string,
  prompt: string,
  timeoutMs: number = DEFAULT_OLLAMA_TIMEOUT_MS,
): Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput, HttpClient.HttpClient> {
  const program = Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const request = HttpClientRequest.post(ollamaChatUrl()).pipe(
      HttpClientRequest.bodyUnsafeJson({
        model,
        format: "json",
        stream: false,
        messages: [
          { role: "system", content: MUSE_GLIMMER_SYSTEM_PROMPT },
          { role: "user", content: prompt },
        ],
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
      duration: timeoutMs,
      onTimeout: () => new MarshalUnavailable({ message: "MarshalUnavailable: Ollama request timed out" }),
    }),
  );
}
