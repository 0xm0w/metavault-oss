import { FetchHttpClient } from "@effect/platform";
import { Context, Effect, Layer } from "effect";
import {
  MarshalInvalidOutput,
  MarshalUnavailable,
  type MarshalInvalidOutput as MarshalInvalidOutputT,
  type MarshalUnavailable as MarshalUnavailableT,
} from "../../core/src/errors.js";
import { isWriteScope } from "../../core/src/policy.js";
import type { WardenSettings } from "../../core/src/settings.js";
import type { CapabilityRequest, MarshalDecision } from "../../core/src/types.js";
import { requestMetaApiDecision } from "./meta-api.js";
import { DEFAULT_MARSHAL_MODEL, requestOllamaDecision } from "./ollama.js";
import { buildMarshalPrompt, type HistorySummary } from "./prompt.js";

export { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
export { buildMarshalPrompt, type HistorySummary } from "./prompt.js";
export { MarshalDecisionSchema, parseMarshalDecision } from "./schema.js";
export {
  DEFAULT_MARSHAL_MODEL,
  OLLAMA_CHAT_URL,
  OLLAMA_MODELS,
  requestOllamaDecision,
  type OllamaModelInfo,
} from "./ollama.js";
export {
  DEFAULT_META_API_BASE_URL,
  META_API_DOCS_URL,
  requestMetaApiDecision,
  type MetaApiRequest,
} from "./meta-api.js";
export type { WardenSettings } from "../../core/src/settings.js";

export interface BrainService {
  readonly assess: (
    req: CapabilityRequest,
    historySummary: HistorySummary,
    policyDigest: string,
  ) => Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput>;
}

export class Brain extends Context.Tag("Brain")<Brain, BrainService>() {}

// Effort semantics (identical across providers): fast = 1 pass / 10s,
// standard = 1 pass / 30s, deep = 2 passes (assess + verify) / 60s.
// Effort never changes policy ceilings.
export const EFFORT_TIMEOUT_MS: Record<WardenSettings["effort"], number> = {
  fast: 10_000,
  standard: 30_000,
  deep: 60_000,
};

export type WardenKeyProvider = () => Effect.Effect<string | null>;

const RISK_RANK: Record<MarshalDecision["risk"], number> = { low: 0, medium: 1, high: 2 };

// Mirrors resourcePrefix in packages/core/src/policy.ts: the resource is
// everything before the final "." or ":" segment.
function resourcePrefix(scope: string): string {
  const index = Math.max(scope.lastIndexOf("."), scope.lastIndexOf(":"));
  return index > 0 ? scope.slice(0, index) : scope;
}

function isExtensionOf(longer: string, shorter: string): boolean {
  return (
    longer.length > shorter.length &&
    longer.startsWith(shorter) &&
    (longer[shorter.length] === "." || longer[shorter.length] === ":")
  );
}

// Narrower is only defined for comparable scopes. A dot/colon-extended
// scope is narrower (more specific) than its prefix; for the same
// resource, a read is narrower than a write (isWriteScope mirrors
// policy.ts). The empty string is never narrower. Incomparable scopes
// have no narrower one, so the first verdict's scope is kept.
export function narrowerScope(a: string, b: string): string {
  if (a === b) return a;
  if (a === "") return b;
  if (b === "") return a;
  if (isExtensionOf(a, b)) return a;
  if (isExtensionOf(b, a)) return b;
  if (resourcePrefix(a) === resourcePrefix(b)) {
    const aWrite = isWriteScope(a);
    const bWrite = isWriteScope(b);
    if (aWrite !== bWrite) return aWrite ? b : a;
  }
  return a;
}

export function buildVerifyPrompt(prompt: string, first: MarshalDecision): string {
  return [
    prompt,
    "",
    "Verify pass: re-check the first marshal verdict below against the request above.",
    "Reply with strict JSON only in the same format if the verdict is correct, or a corrected verdict if it is not.",
    `First verdict: ${JSON.stringify(first)}`,
  ].join("\n");
}

function singlePass(
  settings: WardenSettings,
  getKey: WardenKeyProvider | undefined,
  prompt: string,
  timeoutMs: number,
): Effect.Effect<MarshalDecision, MarshalUnavailableT | MarshalInvalidOutputT> {
  if (settings.provider === "meta-api") {
    return Effect.flatMap(
      getKey === undefined ? Effect.succeed<string | null>(null) : getKey(),
      (key) =>
        key === null || key.trim() === ""
          ? Effect.fail(
              new MarshalUnavailable({ message: "MarshalUnavailable: Meta API key not configured" }),
            )
          : requestMetaApiDecision(
              { model: settings.model, baseUrl: settings.metaApiBaseUrl, apiKey: key, prompt },
              timeoutMs,
            ),
    ).pipe(Effect.provide(FetchHttpClient.layer));
  }
  if (settings.provider === "none") {
    return Effect.fail(
      new MarshalUnavailable({ message: "MarshalUnavailable: marshal provider is none" }),
    );
  }
  return requestOllamaDecision(settings.model, prompt, timeoutMs).pipe(
    Effect.provide(FetchHttpClient.layer),
  );
}

export function assessFromSettings(
  settings: WardenSettings,
  getKey: WardenKeyProvider | undefined,
  req: CapabilityRequest,
  historySummary: HistorySummary,
  policyDigest: string,
): Effect.Effect<MarshalDecision, MarshalUnavailableT | MarshalInvalidOutputT> {
  const prompt = buildMarshalPrompt(req, historySummary, policyDigest);
  const totalMs = EFFORT_TIMEOUT_MS[settings.effort];
  if (settings.effort !== "deep") {
    return singlePass(settings, getKey, prompt, totalMs);
  }
  const perPassMs = Math.floor(totalMs / 2);
  const program = Effect.gen(function* () {
    const first = yield* singlePass(settings, getKey, prompt, perPassMs);
    const second = yield* singlePass(settings, getKey, buildVerifyPrompt(prompt, first), perPassMs);
    const agrees =
      first.risk === second.risk &&
      first.recommendedScope === second.recommendedScope &&
      first.requireApproval === second.requireApproval;
    if (agrees) return first;
    const risk = RISK_RANK[first.risk] >= RISK_RANK[second.risk] ? first.risk : second.risk;
    return {
      risk,
      recommendedScope: narrowerScope(first.recommendedScope, second.recommendedScope),
      requireApproval: true,
      explanation: `deep verify disagreement; escalated. first: ${first.explanation}; verify: ${second.explanation}`,
    } satisfies MarshalDecision;
  });
  return program.pipe(
    Effect.timeoutFail({
      duration: totalMs,
      onTimeout: () =>
        new MarshalUnavailable({ message: "MarshalUnavailable: deep marshal timed out" }),
    }),
  );
}

export function BrainFromSettings(
  settings: WardenSettings,
  getKey?: WardenKeyProvider,
): Layer.Layer<Brain> {
  return Layer.succeed(Brain, {
    assess: (req, historySummary, policyDigest) =>
      assessFromSettings(settings, getKey, req, historySummary, policyDigest),
  });
}

export function BrainOllamaLive(model: string = DEFAULT_MARSHAL_MODEL): Layer.Layer<Brain> {
  return Layer.succeed(Brain, {
    assess: (req, historySummary, policyDigest) =>
      requestOllamaDecision(model, buildMarshalPrompt(req, historySummary, policyDigest)).pipe(
        Effect.provide(FetchHttpClient.layer),
      ),
  });
}
