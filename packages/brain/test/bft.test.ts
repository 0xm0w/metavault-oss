import { Effect } from "effect";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  assessBftQuorum,
  assessFromSettings,
  setBuiltinInferenceHandler,
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

describe("Meta BFT Consensus Engine (Meta API + Local Fallback)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    setBuiltinInferenceHandler(null);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    setBuiltinInferenceHandler(null);
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
    expect(decision.explanation).toContain("Local Co-Auditor (Llama 3.2 1B On-Device Fallback)");
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
    expect(decision.explanation).toContain("Chief Warden (Meta API");
  });

  it("supports any custom Meta AI model for the Cloud Warden", async () => {
    const metaResponseJson = JSON.stringify({
      choices: [
        {
          message: {
            role: "assistant",
            content: JSON.stringify({
              risk: "low",
              recommendedScope: "charges.read",
              requireApproval: false,
              explanation: "Custom Meta 405B verified",
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
        metaModel: "llama-3.1-405b-instruct",
      }),
    );

    expect(decision.explanation).toContain("Chief Warden (Meta API: llama-3.1-405b-instruct)");
  });

  it("achieves unanimous 2/2 BFT quorum across Meta API and Local Llama", async () => {
    const localDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "Local Llama verified charges.read",
    };

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

    setBuiltinInferenceHandler(() => Effect.succeed(localDecision));

    const decision = await Effect.runPromise(
      assessBftQuorum(testRequest, historySummary, policyDigest, {
        metaApiKey: "test-meta-key-12345",
      }),
    );

    expect(decision.risk).toBe("low");
    expect(decision.recommendedScope).toBe("charges.read");
    expect(decision.requireApproval).toBe(false);
    expect(decision.explanation).toContain("[Meta BFT Quorum 2/2 Unanimous]");
  });

  it("escalates risk and clamps scope when divergence is detected", async () => {
    const localDecision: MarshalDecision = {
      risk: "high",
      recommendedScope: "charges.read",
      requireApproval: true,
      explanation: "Local Llama detected anomaly",
    };

    const metaResponseJson = JSON.stringify({
      choices: [
        {
          message: {
            role: "assistant",
            content: JSON.stringify({
              risk: "low",
              recommendedScope: "charges.read",
              requireApproval: false,
              explanation: "Meta API low risk",
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

    setBuiltinInferenceHandler(() => Effect.succeed(localDecision));

    const decision = await Effect.runPromise(
      assessBftQuorum(testRequest, historySummary, policyDigest, {
        metaApiKey: "test-meta-key-12345",
      }),
    );

    expect(decision.risk).toBe("high");
    expect(decision.requireApproval).toBe(true);
    expect(decision.explanation).toContain("[Meta BFT Consensus Divergence]");
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
      explanation: "Local Llama verified",
    };

    setBuiltinInferenceHandler(() => Effect.succeed(mockDecision));

    const decision = await Effect.runPromise(
      assessFromSettings(settings, () => Effect.succeed(null), testRequest, historySummary, policyDigest),
    );

    expect(decision.recommendedScope).toBe("charges.read");
    expect(decision.explanation).toContain("Local Co-Auditor");
  });
});
