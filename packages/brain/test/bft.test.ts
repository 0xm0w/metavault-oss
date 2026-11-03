import { Effect } from "effect";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  assessBftQuorum,
  assessFromSettings,
  setLocalInferenceHandler,
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
const localEndpoint = { baseUrl: "http://127.0.0.1:11434", api: "ollama" as const, model: "muse-glimmer:30b" };

describe("Meta BFT Consensus Engine (Meta API + Local Fallback)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    setLocalInferenceHandler(null);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    setLocalInferenceHandler(null);
  });

  it("fails with MarshalUnavailable when no local endpoint is configured and there is no key", async () => {
    const fetchMock = vi.fn<typeof fetch>(() => Promise.reject(new Error("ECONNREFUSED")));
    vi.stubGlobal("fetch", fetchMock);
    const result = await Effect.runPromiseExit(
      assessBftQuorum(testRequest, historySummary, policyDigest, { metaApiKey: null }),
    );
    expect(result._tag).toBe("Failure");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("fails with MarshalUnavailable when no wardens are reachable", async () => {
    // No Meta API key, and the user's local endpoint is down.
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() => Promise.reject(new Error("ECONNREFUSED"))),
    );
    const result = await Effect.runPromiseExit(
      assessBftQuorum(testRequest, historySummary, policyDigest, { metaApiKey: null, localEndpoint }),
    );
    expect(result._tag).toBe("Failure");
  });

  it("succeeds with your local endpoint as sole warden", async () => {
    const metaDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "Safe read operation",
    };

    setLocalInferenceHandler(() => Effect.succeed(metaDecision));

    const decision = await Effect.runPromise(
      assessBftQuorum(testRequest, historySummary, policyDigest, { metaApiKey: null, localEndpoint }),
    );

    expect(decision.risk).toBe("low");
    expect(decision.recommendedScope).toBe("charges.read");
    expect(decision.explanation).toContain("Local Co-Auditor (muse-glimmer:30b via your endpoint)");
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
        localEndpoint,
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
        metaModel: "muse-spark-1.2",
      }),
    );

    expect(decision.explanation).toContain("Chief Warden (Meta API: muse-spark-1.2)");
  });

  it("achieves unanimous 2/2 BFT quorum across Meta API and local Muse Glimmer", async () => {
    const localDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "Local Muse Glimmer verified charges.read",
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

    setLocalInferenceHandler(() => Effect.succeed(localDecision));

    const decision = await Effect.runPromise(
      assessBftQuorum(testRequest, historySummary, policyDigest, {
        metaApiKey: "test-meta-key-12345",
        localEndpoint,
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
      explanation: "Local Muse Glimmer detected anomaly",
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

    setLocalInferenceHandler(() => Effect.succeed(localDecision));

    const decision = await Effect.runPromise(
      assessBftQuorum(testRequest, historySummary, policyDigest, {
        metaApiKey: "test-meta-key-12345",
        localEndpoint,
      }),
    );

    expect(decision.risk).toBe("high");
    expect(decision.requireApproval).toBe(true);
    expect(decision.explanation).toContain("[Meta BFT Consensus Divergence]");
  });

  it("integrates seamlessly into assessFromSettings when provider='bft'", async () => {
    const settings: WardenSettings = {
      provider: "bft",
      model: "muse-spark-1.3",
      effort: "standard",
      metaApiBaseUrl: "https://api.meta.ai/v1",
      localBaseUrl: localEndpoint.baseUrl,
      localApi: "ollama",
      localModel: localEndpoint.model,
    };

    const mockDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "Local Muse Glimmer verified",
    };

    setLocalInferenceHandler(() => Effect.succeed(mockDecision));

    const decision = await Effect.runPromise(
      assessFromSettings(settings, () => Effect.succeed(null), testRequest, historySummary, policyDigest),
    );

    expect(decision.recommendedScope).toBe("charges.read");
    expect(decision.explanation).toContain("Local Co-Auditor");
  });
});
