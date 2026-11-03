import { FetchHttpClient } from "@effect/platform";
import { Effect } from "effect";
import type { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
import type { MarshalDecision } from "../../core/src/types.js";
import { MUSE_GLIMMER_IQ3_XXS_TAG } from "../../core/src/settings.js";
import { DEFAULT_MARSHAL_MODEL, requestOllamaDecision } from "./ollama.js";

// The built-in (on-device) warden runs Meta Muse Glimmer 30B, official
// Q4_K_M build, through the local Ollama runtime
// (https://ollama.com/library/muse-glimmer, weights from
// https://huggingface.co/meta-models/Muse-Glimmer-30B-GGUF). Unless a host
// registers its own engine with setBuiltinInferenceHandler, every built-in
// assessment goes to Ollama. If Ollama is not running or the model is not
// pulled, the request fails closed with MarshalUnavailable and policy asks
// the human.
export const DEFAULT_BUILTIN_MODEL = DEFAULT_MARSHAL_MODEL;

export interface BuiltinModelInfo {
  readonly id: string;
  readonly label: string;
  readonly diskSize: string;
  readonly vramRequired: string;
}

export const BUILTIN_MODELS: readonly BuiltinModelInfo[] = [
  {
    id: "muse-glimmer:30b",
    label: "Muse Glimmer 30B (Q4_K_M GGUF)",
    diskSize: "16.8 GB",
    vramRequired: "24 GB",
  },
  {
    id: MUSE_GLIMMER_IQ3_XXS_TAG,
    label: "Muse Glimmer 30B (unsloth UD-IQ3_XXS GGUF, optional)",
    diskSize: "13.1 GB",
    vramRequired: "not yet measured",
  },
];

export type BuiltinInferenceHandler = (
  model: string,
  prompt: string,
  timeoutMs: number,
) => Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput>;

// Default engine: local Ollama serving Muse Glimmer.
export const ollamaBuiltinHandler: BuiltinInferenceHandler = (model, prompt, timeoutMs) =>
  requestOllamaDecision(model, prompt, timeoutMs).pipe(Effect.provide(FetchHttpClient.layer));

let registeredHandler: BuiltinInferenceHandler = ollamaBuiltinHandler;

// Passing null restores the default Ollama-backed engine.
export function setBuiltinInferenceHandler(handler: BuiltinInferenceHandler | null): void {
  registeredHandler = handler ?? ollamaBuiltinHandler;
}

export function getBuiltinInferenceHandler(): BuiltinInferenceHandler {
  return registeredHandler;
}

export function requestBuiltinDecision(
  model: string,
  prompt: string,
  timeoutMs: number = 120_000,
): Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput> {
  return registeredHandler(model, prompt, timeoutMs);
}
