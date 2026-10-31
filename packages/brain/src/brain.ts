import { FetchHttpClient } from "@effect/platform";
import { Context, Effect, Layer } from "effect";
import type { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
import type { CapabilityRequest, MarshalDecision } from "../../core/src/types.js";
import { DEFAULT_MARSHAL_MODEL, requestOllamaDecision } from "./ollama.js";
import { buildMarshalPrompt, type HistorySummary } from "./prompt.js";

export { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
export { buildMarshalPrompt, type HistorySummary } from "./prompt.js";
export { MarshalDecisionSchema, parseMarshalDecision } from "./schema.js";
export { DEFAULT_MARSHAL_MODEL, OLLAMA_CHAT_URL, requestOllamaDecision } from "./ollama.js";

export interface BrainService {
  readonly assess: (
    req: CapabilityRequest,
    historySummary: HistorySummary,
    policyDigest: string,
  ) => Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput>;
}

export class Brain extends Context.Tag("Brain")<Brain, BrainService>() {}

export function BrainOllamaLive(model: string = DEFAULT_MARSHAL_MODEL): Layer.Layer<Brain> {
  return Layer.succeed(Brain, {
    assess: (req, historySummary, policyDigest) =>
      requestOllamaDecision(model, buildMarshalPrompt(req, historySummary, policyDigest)).pipe(
        Effect.provide(FetchHttpClient.layer),
      ),
  });
}
