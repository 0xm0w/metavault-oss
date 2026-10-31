import { FetchHttpClient } from "@effect/platform";
import { Context, Effect, Layer } from "effect";
import { DEFAULT_MARSHAL_MODEL, requestOllamaDecision } from "./ollama.js";
import { buildMarshalPrompt } from "./prompt.js";
export { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
export { buildMarshalPrompt } from "./prompt.js";
export { MarshalDecisionSchema, parseMarshalDecision } from "./schema.js";
export { DEFAULT_MARSHAL_MODEL, OLLAMA_CHAT_URL, requestOllamaDecision } from "./ollama.js";
export class Brain extends Context.Tag("Brain")() {
}
export function BrainOllamaLive(model = DEFAULT_MARSHAL_MODEL) {
    return Layer.succeed(Brain, {
        assess: (req, historySummary, policyDigest) => requestOllamaDecision(model, buildMarshalPrompt(req, historySummary, policyDigest)).pipe(Effect.provide(FetchHttpClient.layer)),
    });
}
