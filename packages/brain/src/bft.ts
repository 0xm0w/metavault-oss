import { FetchHttpClient } from "@effect/platform";
import { Effect } from "effect";
import { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
import type { CapabilityRequest, MarshalDecision } from "../../core/src/types.js";
import { DEFAULT_BUILTIN_MODEL, requestBuiltinDecision } from "./builtin.js";
import { DEFAULT_META_API_BASE_URL, DEFAULT_META_API_MODEL, requestMetaApiDecision } from "./meta-api.js";
import { buildMarshalPrompt, type HistorySummary } from "./prompt.js";
import { enforceScopeSafety, narrowerScope } from "./scope-safety.js";

const RISK_RANK: Record<MarshalDecision["risk"], number> = { low: 0, medium: 1, high: 2 };

export interface BftWardenVerdict {
  readonly name: string;
  readonly role: string;
  readonly decision: MarshalDecision;
}

export interface BftConsensusDecision extends MarshalDecision {
  readonly quorumCount: number;
  readonly totalWardens: number;
  readonly verdicts: readonly BftWardenVerdict[];
}

export interface BftExecutionOptions {
  readonly metaApiKey?: string | null;
  readonly metaApiBaseUrl?: string;
  readonly metaModel?: string;
  readonly timeoutMs?: number;
  // Budget for the on-device Muse Glimmer leg (defaults to timeoutMs).
  readonly localTimeoutMs?: number;
}

/**
 * Assesses a capability request using the Meta BFT Consensus Engine:
 * 1. Meta Model API (Cloud Chief Justice) — Muse Spark 1.3 by default
 * 2. Meta Local Fallback (On-Device Co-Auditor) — Muse Glimmer 30B Q4_K_M
 *
 * Byzantine fault-tolerant consensus between cloud and local edge models.
 */
export function assessBftQuorum(
  req: CapabilityRequest,
  historySummary: HistorySummary,
  policyDigest: string,
  options: BftExecutionOptions = {},
): Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput> {
  const timeoutMs = options.timeoutMs ?? 30_000;
  const prompt = buildMarshalPrompt(req, historySummary, policyDigest);

  return Effect.gen(function* () {
    const verdicts: BftWardenVerdict[] = [];

    // 1. Primary Cloud Warden: Meta API (Any Meta AI model)
    // Ollama tags (e.g. "muse-glimmer:30b") are local ids, never Meta Model
    // API ids; fall back to the verified cloud default for those.
    const requestedCloud = options.metaModel?.trim() ?? "";
    const cloudModel = requestedCloud !== "" && !requestedCloud.includes(":") ? requestedCloud : DEFAULT_META_API_MODEL;
    const metaKey = options.metaApiKey?.trim();
    if (metaKey !== undefined && metaKey !== "") {
      const metaApiResult = yield* Effect.either(
        requestMetaApiDecision(
          {
            model: cloudModel,
            baseUrl: options.metaApiBaseUrl ?? DEFAULT_META_API_BASE_URL,
            apiKey: metaKey,
            prompt,
          },
          timeoutMs,
        ).pipe(Effect.provide(FetchHttpClient.layer)),
      );
      if (metaApiResult._tag === "Right") {
        const metaVerdict = enforceScopeSafety(metaApiResult.right, req.requestedScope, req.reason);
        verdicts.push({
          name: "Meta Family of AIs",
          role: `Chief Warden (Meta API: ${cloudModel})`,
          decision: metaVerdict,
        });
      }
    }

    // 2. Local Fallback / Edge Co-Auditor: Meta Muse Glimmer 30B (Q4_K_M)
    const builtinResult = yield* Effect.either(
      requestBuiltinDecision(DEFAULT_BUILTIN_MODEL, prompt, options.localTimeoutMs ?? timeoutMs),
    );
    if (builtinResult._tag === "Right") {
      const builtinVerdict = enforceScopeSafety(builtinResult.right, req.requestedScope, req.reason);
      verdicts.push({
        name: "Meta Family of AIs",
        role: "Local Co-Auditor (Muse Glimmer 30B On-Device Fallback)",
        decision: builtinVerdict,
      });
    }

    // If no wardens returned a decision, fail with MarshalUnavailable
    if (verdicts.length === 0) {
      return yield* Effect.fail(
        new MarshalUnavailable({
          message:
            "MarshalUnavailable: No BFT wardens available (Meta API unreachable and local Muse Glimmer offline)",
        }),
      );
    }

    // If only 1 warden participated (e.g. cloud unreachable or local Ollama offline), return its verdict
    if (verdicts.length === 1) {
      const single = verdicts[0];
      if (single === undefined) {
        return yield* Effect.fail(new MarshalUnavailable({ message: "No verdicts" }));
      }
      return {
        ...single.decision,
        explanation: `[${single.name} · ${single.role}] ${single.decision.explanation}`,
      };
    }

    // Dual-Warden BFT Quorum Synthesis
    // A) Risk: Escalates to highest risk reported by any participating warden
    let highestRisk: MarshalDecision["risk"] = "low";
    for (const v of verdicts) {
      if (RISK_RANK[v.decision.risk] > RISK_RANK[highestRisk]) {
        highestRisk = v.decision.risk;
      }
    }

    // B) Scope: Clamp to narrowest scope across all verdicts
    let finalScope = req.requestedScope;
    for (const v of verdicts) {
      finalScope = narrowerScope(finalScope, v.decision.recommendedScope);
    }

    // C) Approval: If ANY warden requests approval, enforce approval
    const requireApproval = verdicts.some((v) => v.decision.requireApproval);

    // D) Detect consensus vs divergence
    const firstVerdict = verdicts[0];
    const isUnanimous =
      firstVerdict !== undefined &&
      verdicts.every((v) => v.decision.risk === firstVerdict.decision.risk) &&
      verdicts.every((v) => v.decision.recommendedScope === firstVerdict.decision.recommendedScope) &&
      verdicts.every((v) => v.decision.requireApproval === firstVerdict.decision.requireApproval);

    const breakdown = verdicts
      .map((v) => `${v.role}: ${v.decision.recommendedScope} (${v.decision.risk})`)
      .join(" · ");

    let explanation: string;
    if (isUnanimous) {
      explanation = `[Meta BFT Quorum ${String(verdicts.length)}/${String(verdicts.length)} Unanimous] ${breakdown}. Cross-verified across Cloud & Local Muse Glimmer.`;
    } else {
      explanation = `[Meta BFT Consensus Divergence] ${breakdown}. Clamped to narrowest scope '${finalScope}' and escalated risk to '${highestRisk}'.`;
    }

    return enforceScopeSafety(
      {
        risk: highestRisk,
        recommendedScope: finalScope,
        requireApproval,
        explanation,
      },
      req.requestedScope,
      req.reason,
    );
  });
}
