import { Effect } from "effect";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  assessBftQuorum,
  assessFromSettings,
  setBuiltinInferenceHandler,
  setGeminiNanoHandler,
  setPhiSilicaHandler,
} from "../src/brain.js";
import type { CapabilityRequest, MarshalDecision } from "../../core/src/types.js";
import type { WardenSettings } from "../../core/src/settings.js";

const testRequest: CapabilityRequest = {
  agentId: "cursor-agent",
  ide: "Cursor",
  tool: "http",
  alias: "stripe",
  requestedScope: "charges.read",
  reason: "read past customer charges for invoice table",
};

const historySummary = { requests24h: 3, denials24h: 0 };
const policyDigest = "stripe ceiling=charges.read";

describe("Tri-Warden BFT Consensus Engine", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    setBuiltinInferenceHandler(null);
    setPhiSilicaHandler(null);
    setGeminiNanoHandler(null);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    setBuiltinInferenceHandler(null);
    setPhiSilicaHandler(null);
    setGeminiNanoHandler(null);
  });

  it("fails with MarshalUnavailable when no wardens are available", async () => {
    const result = await Effect.runPromiseExit(
      assessBftQuorum(testRequest, historySummary, policyDigest, { metaApiKey: null }),
    );
    expect(result._tag).toBe("Failure");
  });

  it("succeeds with Meta Llama 1B offline fallback as sole warden", async () => {
    const metaDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "Safe read operation",
    };

    setBuiltinInferenceHandler(() => Effect.succeed(metaDecision));

    const decision = await Effect.runPromise(
      assessBftQuorum(testRequest, historySummary, policyDigest, { metaApiKey: null }),
    );

    expect(decision.risk).toBe("low");
    expect(decision.recommendedScope).toBe("charges.read");
    expect(decision.explanation).toContain("Meta Family of AIs");
  });

  it("uses Meta API when valid key is provided in BFT options", async () => {
    const metaResponseJson = JSON.stringify({
      choices: [
        {
          message: {
            role: "assistant",
            content: JSON.stringify({
              risk: "low",
              recommendedScope: "charges.read",
              requireApproval: false,
              explanation: "Meta API verified charges.read",
            }),
          },
        },
      ],
    });

    vi.spyOn(globalThis, "fetch").mockImplementationOnce(() =>
      Promise.resolve(
        new Response(metaResponseJson, {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      ),
    );

    const decision = await Effect.runPromise(
      assessBftQuorum(testRequest, historySummary, policyDigest, {
        metaApiKey: "test-meta-key-12345",
      }),
    );

    expect(decision.risk).toBe("low");
    expect(decision.recommendedScope).toBe("charges.read");
    expect(decision.explanation).toContain("Chief Warden (Meta API)");
  });

  it("achieves unanimous 3/3 BFT quorum across Meta, Microsoft, and Google", async () => {
    const metaDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "Meta verified charges.read",
    };
    const msftDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "Microsoft Phi Silica NPU verified charges.read",
    };
    const googleDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "Google Gemini Nano tab context confirmed charges.read",
    };

    setBuiltinInferenceHandler(() => Effect.succeed(metaDecision));
    setPhiSilicaHandler(() => Effect.succeed(msftDecision));
    setGeminiNanoHandler(() => Effect.succeed(googleDecision));

    const decision = await Effect.runPromise(
      assessBftQuorum(testRequest, historySummary, policyDigest, { metaApiKey: null }),
    );

    expect(decision.risk).toBe("low");
    expect(decision.recommendedScope).toBe("charges.read");
    expect(decision.requireApproval).toBe(false);
    expect(decision.explanation).toContain("[BFT Quorum 3/3 Unanimous]");
    expect(decision.explanation).toContain("Meta Family of AIs");
    expect(decision.explanation).toContain("Microsoft Phi Silica");
    expect(decision.explanation).toContain("Google Gemini Nano");
  });

  it("escalates risk and clamps scope when divergence is detected", async () => {
    const metaDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "Meta deemed low risk",
    };
    const msftDecision: MarshalDecision = {
      risk: "high",
      recommendedScope: "charges.read",
      requireApproval: true,
      explanation: "Suspicious parameter pattern detected on NPU",
    };
    const googleDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "Tab context matches",
    };

    setBuiltinInferenceHandler(() => Effect.succeed(metaDecision));
    setPhiSilicaHandler(() => Effect.succeed(msftDecision));
    setGeminiNanoHandler(() => Effect.succeed(googleDecision));

    const decision = await Effect.runPromise(
      assessBftQuorum(testRequest, historySummary, policyDigest, { metaApiKey: null }),
    );

    expect(decision.risk).toBe("high");
    expect(decision.requireApproval).toBe(true);
    expect(decision.explanation).toContain("[BFT Consensus Divergence]");
  });

  it("integrates seamlessly into assessFromSettings when provider='bft'", async () => {
    const settings: WardenSettings = {
      provider: "bft",
      model: "llama-3.3-70b-instruct",
      effort: "standard",
      metaApiBaseUrl: "https://api.llama.com/v1",
    };

    const mockDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "BFT verified",
    };

    setBuiltinInferenceHandler(() => Effect.succeed(mockDecision));
    setPhiSilicaHandler(() => Effect.succeed(mockDecision));

    const decision = await Effect.runPromise(
      assessFromSettings(settings, () => Effect.succeed(null), testRequest, historySummary, policyDigest),
    );

    expect(decision.recommendedScope).toBe("charges.read");
    expect(decision.explanation).toContain("BFT");
  });
});
