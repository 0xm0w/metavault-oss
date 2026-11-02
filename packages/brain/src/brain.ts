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
import { requestBuiltinDecision } from "./builtin.js";
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
export {
  BUILTIN_MODELS,
  DEFAULT_BUILTIN_MODEL,
  getBuiltinInferenceHandler,
  requestBuiltinDecision,
  setBuiltinInferenceHandler,
  type BuiltinInferenceHandler,
  type BuiltinModelInfo,
} from "./builtin.js";
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

/**
 * OWASP LLM02 & LLM08 defense:
 * Enforces that a warden's recommendedScope is strictly an exact match or a narrower sub-scope
 * of the requestedScope. Any attempt to widen scope (e.g. wildcards, root, cross-resource)
 * or to demote a write scope to auto-approved read is clamped to requestedScope, escalated to
 * 'high' risk, and forces human approval.
 */
export function enforceScopeSafety(
  decision: MarshalDecision,
  requestedScope: string,
  reason?: string,
): MarshalDecision {
  const isSafe =
    decision.recommendedScope === requestedScope ||
    isExtensionOf(decision.recommendedScope, requestedScope);

  if (!isSafe || decision.recommendedScope.includes("*")) {
    return {
      risk: "high",
      recommendedScope: requestedScope,
      requireApproval: true,
      explanation: `Warden proposed scope '${decision.recommendedScope}' does not narrow '${requestedScope}'; clamped to requested scope and escalated to high risk.`,
    };
  }

  if (isWriteScope(requestedScope) && !decision.requireApproval) {
    return {
      ...decision,
      requireApproval: true,
      explanation: `Write capability '${requestedScope}' strictly requires approval. ${decision.explanation}`,
    };
  }

  if (reason !== undefined && reason.trim() !== "") {
    const isAdversarial =
      /(?:classify|mark|set|return|rate)\s+(?:this|operation|request)?\s*(?:as)?\s*(?:risk)?\s*low/i.test(reason) ||
      /(?:requireapproval|require_approval)\s*(?:false|no|none)/i.test(reason) ||
      /(?:ignore\s+(?:all\s+)?(?:previous\s+)?instructions|system\s+override|developer\s+mode)/i.test(reason) ||
      /(?:approve|grant|execute)\s+[\w.:-]*write/i.test(reason) ||
      /https?:\/\/[^\s"'>]+/i.test(reason) ||
      /\|\s*(?:bash|sh|zsh|pwsh|powershell|cmd)\b/i.test(reason) ||
      /(?:\/etc\/(?:shadow|passwd)|\.ssh\/id_|\.aws\/credentials)/i.test(reason);

    if (isAdversarial && decision.risk !== "high") {
      return {
        risk: "high",
        recommendedScope: requestedScope,
        requireApproval: true,
        explanation: `Adversarial pattern or policy override attempt detected in request reason; escalated to high risk. ${decision.explanation}`,
      };
    }
  }

  return decision;
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
  if (settings.provider === "builtin") {
    return requestBuiltinDecision(settings.model, prompt, timeoutMs);
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

export function BrainOllamaLive(model: string = DEFAULT_MARSHAL_MODEL): Layer.Layer<Brain> {
  return Layer.succeed(Brain, {
    assess: (req, historySummary, policyDigest) =>
      requestOllamaDecision(model, buildMarshalPrompt(req, historySummary, policyDigest)).pipe(
        Effect.map((dec) => enforceScopeSafety(dec, req.requestedScope)),
        Effect.provide(FetchHttpClient.layer),
      ),
  });
}
