import { FetchHttpClient } from "@effect/platform";
import { Context, Effect, Layer } from "effect";
import {
  MarshalInvalidOutput,
  MarshalUnavailable,
  type MarshalInvalidOutput as MarshalInvalidOutputT,
  type MarshalUnavailable as MarshalUnavailableT,
} from "../../core/src/errors.js";
import type { WardenSettings } from "../../core/src/settings.js";
import type { CapabilityRequest, MarshalDecision } from "../../core/src/types.js";
import { assessBftQuorum } from "./bft.js";
import { enforceScopeSafety, narrowerScope } from "./scope-safety.js";
import { requestMetaApiDecision } from "./meta-api.js";
import { DEFAULT_MARSHAL_MODEL, requestLocalDecision, requestOllamaDecision } from "./ollama.js";
import { buildMarshalPrompt, type HistorySummary } from "./prompt.js";

export { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
export { buildMarshalPrompt, type HistorySummary } from "./prompt.js";
export { MarshalDecisionSchema, parseMarshalDecision } from "./schema.js";
export { enforceScopeSafety, narrowerScope } from "./scope-safety.js";
export {
  DEFAULT_MARSHAL_MODEL,
  DEFAULT_OLLAMA_BASE_URL,
  DEFAULT_OLLAMA_TIMEOUT_MS,
  MUSE_GLIMMER_SYSTEM_PROMPT,
  OLLAMA_CHAT_URL,
  httpLocalHandler,
  requestLocalDecision,
  requestOllamaDecision,
  requestOpenAiCompatibleDecision,
  setLocalInferenceHandler,
  type LocalEndpoint,
  type LocalInferenceHandler,
} from "./ollama.js";
export {
  DEFAULT_META_API_BASE_URL,
  DEFAULT_META_API_MODEL,
  META_API_DOCS_URL,
  requestMetaApiDecision,
  type MetaApiRequest,
} from "./meta-api.js";
export {
  assessBftQuorum,
  type BftConsensusDecision,
  type BftExecutionOptions,
  type BftWardenVerdict,
} from "./bft.js";
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

// A bring-your-own local endpoint usually runs on the user's own machine,
// where one pass can take far longer than a hosted API, so the local
// provider gets a longer budget per effort level. Cloud budgets are
// unchanged. Effort still never changes policy ceilings.
export const LOCAL_EFFORT_TIMEOUT_MS: Record<WardenSettings["effort"], number> = {
  fast: 60_000,
  standard: 120_000,
  deep: 240_000,
};

export function effortTimeoutMs(settings: Pick<WardenSettings, "provider" | "effort">): number {
  return settings.provider === "local"
    ? LOCAL_EFFORT_TIMEOUT_MS[settings.effort]
    : EFFORT_TIMEOUT_MS[settings.effort];
}

export type WardenKeyProvider = () => Effect.Effect<string | null>;

const RISK_RANK: Record<MarshalDecision["risk"], number> = { low: 0, medium: 1, high: 2 };



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
  if (settings.provider === "bft") {
    return Effect.fail(
      new MarshalUnavailable({ message: "MarshalUnavailable: BFT provider evaluates via assessBftQuorum" }),
    );
  }
  if (settings.provider === "none") {
    return Effect.fail(
      new MarshalUnavailable({ message: "MarshalUnavailable: marshal provider is none" }),
    );
  }
  return requestLocalDecision(
    { baseUrl: settings.localBaseUrl, api: settings.localApi, model: settings.localModel },
    prompt,
    timeoutMs,
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
  const totalMs = effortTimeoutMs(settings);
  if (settings.provider === "bft") {
    return Effect.flatMap(
      getKey === undefined ? Effect.succeed<string | null>(null) : getKey(),
      (key) =>
        assessBftQuorum(req, historySummary, policyDigest, {
          metaApiKey: key,
          metaApiBaseUrl: settings.metaApiBaseUrl,
          metaModel: settings.model,
          timeoutMs: totalMs,
          localTimeoutMs: LOCAL_EFFORT_TIMEOUT_MS[settings.effort],
          localEndpoint: { baseUrl: settings.localBaseUrl, api: settings.localApi, model: settings.localModel },
        }),
    ).pipe(Effect.provide(FetchHttpClient.layer));
  }
  if (settings.effort !== "deep") {
    return singlePass(settings, getKey, prompt, totalMs).pipe(
      Effect.map((dec) => enforceScopeSafety(dec, req.requestedScope, req.reason)),
    );
  }
  const perPassMs = Math.floor(totalMs / 2);
  const program = Effect.gen(function* () {
    const first = yield* singlePass(settings, getKey, prompt, perPassMs);
    const second = yield* singlePass(settings, getKey, buildVerifyPrompt(prompt, first), perPassMs);
    const agrees =
      first.risk === second.risk &&
      first.recommendedScope === second.recommendedScope &&
      first.requireApproval === second.requireApproval;
    if (agrees) return enforceScopeSafety(first, req.requestedScope, req.reason);
    const risk = RISK_RANK[first.risk] >= RISK_RANK[second.risk] ? first.risk : second.risk;
    return enforceScopeSafety(
      {
        risk,
        recommendedScope: narrowerScope(first.recommendedScope, second.recommendedScope),
        requireApproval: true,
        explanation: `deep verify disagreement; escalated. first: ${first.explanation}; verify: ${second.explanation}`,
      },
      req.requestedScope,
      req.reason,
    );
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

export function BrainOllamaLive(model: string = DEFAULT_MARSHAL_MODEL, baseUrl?: string): Layer.Layer<Brain> {
  return Layer.succeed(Brain, {
    assess: (req, historySummary, policyDigest) =>
      requestOllamaDecision(model, buildMarshalPrompt(req, historySummary, policyDigest), undefined, baseUrl).pipe(
        Effect.map((dec) => enforceScopeSafety(dec, req.requestedScope)),
        Effect.provide(FetchHttpClient.layer),
      ),
  });
}
