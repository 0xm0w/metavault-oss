import { Effect, Schema } from "effect";
import { MarshalInvalidOutput } from "../../core/src/errors.js";
import type { MarshalDecision } from "../../core/src/types.js";

export const MarshalDecisionSchema: Schema.Schema<MarshalDecision> = Schema.Struct({
  risk: Schema.Literal("low", "medium", "high"),
  recommendedScope: Schema.String,
  requireApproval: Schema.Boolean,
  explanation: Schema.String,
});

export function stripMarkdownFences(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.startsWith("```")) {
    const lines = trimmed.split("\n");
    const start = lines[0]?.startsWith("```") ? 1 : 0;
    const end = lines[lines.length - 1]?.startsWith("```") ? lines.length - 1 : lines.length;
    return lines.slice(start, end).join("\n").trim();
  }
  return trimmed;
}

export function parseMarshalDecision(
  raw: string,
): Effect.Effect<MarshalDecision, MarshalInvalidOutput> {
  return Effect.try({
    try: (): unknown => JSON.parse(stripMarkdownFences(raw)),
    catch: () => new MarshalInvalidOutput({ message: "MarshalInvalidOutput: output is not valid JSON" }),
  }).pipe(
    Effect.flatMap((parsed) =>
      Schema.decodeUnknown(MarshalDecisionSchema)(parsed).pipe(
        Effect.mapError(
          () => new MarshalInvalidOutput({ message: "MarshalInvalidOutput: output failed schema validation" }),
        ),
      ),
    ),
  );
}
