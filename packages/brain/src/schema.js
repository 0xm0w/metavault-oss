import { Effect, Schema } from "effect";
import { MarshalInvalidOutput } from "../../core/src/errors.js";
export const MarshalDecisionSchema = Schema.Struct({
    risk: Schema.Literal("low", "medium", "high"),
    recommendedScope: Schema.String,
    requireApproval: Schema.Boolean,
    explanation: Schema.String,
});
export function parseMarshalDecision(raw) {
    return Effect.try({
        try: () => JSON.parse(raw),
        catch: () => new MarshalInvalidOutput({ message: "MarshalInvalidOutput: output is not valid JSON" }),
    }).pipe(Effect.flatMap((parsed) => Schema.decodeUnknown(MarshalDecisionSchema)(parsed).pipe(Effect.mapError(() => new MarshalInvalidOutput({ message: "MarshalInvalidOutput: output failed schema validation" })))));
}
