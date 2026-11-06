import { FetchHttpClient } from "@effect/platform";
import { Effect } from "effect";
import { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
import type { CapabilityRequest, MarshalDecision } from "../../core/src/types.js";
import { requestLocalDecision, type LocalEndpoint } from "./ollama.js";
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
  // Budget for the local-endpoint leg (defaults to timeoutMs).
  readonly localTimeoutMs?: number;
  // The user's own local endpoint. Unset means the local leg is skipped.
  readonly localEndpoint?: LocalEndpoint;
}

/**
 * Assesses a capability request using the Meta BFT Consensus Engine:
 * 1. Meta Model API (Cloud Chief Justice) — Muse Spark 1.3 by default
 * 2. Local Co-Auditor — the user's own local endpoint (a Meta open model
 *    such as Muse Glimmer is suggested), when configured
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
    const metaConfigured = metaKey !== undefined && metaKey !== "";
    if (metaConfigured) {
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
        const metaVerdict = enforceScopeSafety(metaApiResult.right, req.requestedScope, req.reason, {
          tool: req.tool,
          payload: req.payload,
        });
        verdicts.push({
          name: "Meta Family of AIs",
          role: `Chief Warden (Meta API: ${cloudModel})`,
          decision: metaVerdict,
        });
      }
    }

    // 2. Local Co-Auditor: the user's own local endpoint, if configured.
    const local = options.localEndpoint;
    const localConfigured = local !== undefined && local.baseUrl.trim() !== "" && local.model.trim() !== "";
    if (localConfigured) {
      const localResult = yield* Effect.either(
        requestLocalDecision(local, prompt, options.localTimeoutMs ?? timeoutMs),
      );
      if (localResult._tag === "Right") {
        const localVerdict = enforceScopeSafety(localResult.right, req.requestedScope, req.reason, {
          tool: req.tool,
          payload: req.payload,
        });
        verdicts.push({
          name: "Meta Family of AIs",
          role: `Local Co-Auditor (${local.model.trim()} via your endpoint)`,
          decision: localVerdict,
        });
      }
    }

    // If no wardens returned a decision, fail with MarshalUnavailable
    if (verdicts.length === 0) {
      return yield* Effect.fail(
        new MarshalUnavailable({
          message:
            "MarshalUnavailable: No BFT wardens available (Meta API unreachable and local endpoint unavailable)",
        }),
      );
    }

    // One verdict is only proof when nothing else was ever configured. With
    // both wardens configured, a single response means the other one failed
    // (or was pushed offline): accepting it would silently drop Byzantine
    // fault tolerance exactly when a cloud outage is attacker-triggerable.
    // Fail closed instead — the daemon routes a warden failure to a human
    // decision, which is the escalation the BFT contract promises.
    if (verdicts.length === 1 && metaConfigured && localConfigured) {
      return yield* Effect.fail(
        new MarshalUnavailable({
          message:
            `MarshalUnavailable: BFT quorum not met (1 of 2 wardens responded); requesting a human decision`,
        }),
      );
    }

    // A single warden is accepted only when it is the only configured one
    // (e.g. no Meta API key, so the local endpoint is the sole source).
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
      explanation = `[Meta BFT Quorum ${String(verdicts.length)}/${String(verdicts.length)} Unanimous] ${breakdown}. Cross-verified across the Meta API and your local endpoint.`;
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
      { tool: req.tool, payload: req.payload },
    );
  });
}
