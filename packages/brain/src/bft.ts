import { FetchHttpClient } from "@effect/platform";
import { Effect } from "effect";
import { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
import type { CapabilityRequest, MarshalDecision } from "../../core/src/types.js";
import { requestBuiltinDecision } from "./builtin.js";
import { requestGeminiNanoDecision, isGeminiNanoAvailable } from "./gemini-nano.js";
import { requestMetaApiDecision } from "./meta-api.js";
import { requestPhiSilicaDecision, isPhiSilicaAvailable } from "./phi-silica.js";
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
}

/**
 * Assesses a capability request using the Tri-Warden BFT Consensus Engine:
 * 1. Meta Family of AIs (Chief Warden) — Meta API with automatic Llama 3.2 1B fallback
 * 2. Microsoft Phi Silica (Hardware Co-Auditor) — Windows NPU
 * 3. Google Gemini Nano (Browser Co-Auditor) — Chrome Prompt API
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

    // 1. Chief Warden: Meta Family of AIs
    // First try Meta API if configured; if unavailable, fallback to local Llama 3.2 1B (builtin)
    let metaVerdict: MarshalDecision | null = null;
    const metaKey = options.metaApiKey?.trim();
    if (metaKey !== undefined && metaKey !== "") {
      const metaApiResult = yield* Effect.either(
        requestMetaApiDecision(
          {
            model: options.metaModel ?? "llama-3.3-70b-instruct",
            baseUrl: options.metaApiBaseUrl ?? "https://api.llama.com/v1",
            apiKey: metaKey,
            prompt,
          },
          timeoutMs,
        ).pipe(Effect.provide(FetchHttpClient.layer)),
      );
      if (metaApiResult._tag === "Right") {
        metaVerdict = enforceScopeSafety(metaApiResult.right, req.requestedScope, req.reason);
        verdicts.push({
          name: "Meta Family of AIs",
          role: "Chief Warden (Meta API)",
          decision: metaVerdict,
        });
      }
    }

    if (metaVerdict === null) {
      // Fallback to on-device Meta Llama 3.2 1B
      const builtinResult = yield* Effect.either(
        requestBuiltinDecision("llama3.2:1b", prompt, timeoutMs),
      );
      if (builtinResult._tag === "Right") {
        metaVerdict = enforceScopeSafety(builtinResult.right, req.requestedScope, req.reason);
        verdicts.push({
          name: "Meta Family of AIs",
          role: "Chief Warden (Llama 3.2 1B Offline Fallback)",
          decision: metaVerdict,
        });
      }
    }

    // 2. Co-Auditor 1: Microsoft Phi Silica (NPU)
    if (isPhiSilicaAvailable()) {
      const phiResult = yield* Effect.either(
        requestPhiSilicaDecision(prompt, timeoutMs),
      );
      if (phiResult._tag === "Right") {
        const phiVerdict = enforceScopeSafety(phiResult.right, req.requestedScope, req.reason);
        verdicts.push({
          name: "Microsoft Phi Silica",
          role: "Hardware Co-Auditor (Windows NPU)",
          decision: phiVerdict,
        });
      }
    }

    // 3. Co-Auditor 2: Google Gemini Nano (Chrome Prompt API)
    if (isGeminiNanoAvailable()) {
      const geminiResult = yield* Effect.either(
        requestGeminiNanoDecision(prompt, timeoutMs),
      );
      if (geminiResult._tag === "Right") {
        const geminiVerdict = enforceScopeSafety(geminiResult.right, req.requestedScope, req.reason);
        verdicts.push({
          name: "Google Gemini Nano",
          role: "Browser Co-Auditor (Chrome Built-in AI)",
          decision: geminiVerdict,
        });
      }
    }

    // If no wardens returned a decision, fail with MarshalUnavailable
    if (verdicts.length === 0) {
      return yield* Effect.fail(
        new MarshalUnavailable({
          message:
            "MarshalUnavailable: No BFT wardens available (Meta API/Llama offline, Phi Silica not registered, Gemini Nano not connected)",
        }),
      );
    }

    // If only 1 warden participated, return its verdict
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

    // Multi-Warden Quorum Synthesis
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

    // D) Detect divergence
    const firstVerdict = verdicts[0];
    const isUnanimous =
      firstVerdict !== undefined &&
      verdicts.every((v) => v.decision.risk === firstVerdict.decision.risk) &&
      verdicts.every((v) => v.decision.recommendedScope === firstVerdict.decision.recommendedScope) &&
      verdicts.every((v) => v.decision.requireApproval === firstVerdict.decision.requireApproval);

    const breakdown = verdicts
      .map((v) => `${v.name}: ${v.decision.recommendedScope} (${v.decision.risk})`)
      .join(" · ");

    let explanation: string;
    if (isUnanimous) {
      explanation = `[BFT Quorum ${String(verdicts.length)}/${String(verdicts.length)} Unanimous] ${breakdown}. Intent verified across multi-model consensus.`;
    } else {
      explanation = `[BFT Consensus Divergence] ${breakdown}. Clamped to narrowest scope '${finalScope}' and escalated risk to '${highestRisk}'.`;
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
