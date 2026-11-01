import { Effect } from "effect";
import { describe, expect, it } from "vitest";
import {
  assessFromSettings,
  BUILTIN_MODELS,
  DEFAULT_BUILTIN_MODEL,
  requestBuiltinDecision,
  setBuiltinInferenceHandler,
} from "../src/brain.js";
import type { CapabilityRequest, MarshalDecision } from "../../core/src/types.js";
import type { WardenSettings } from "../../core/src/settings.js";

const testRequest: CapabilityRequest = {
  agentId: "test-agent",
  ide: "Cursor",
  tool: "http",
  alias: "stripe",
  requestedScope: "charges.read",
  reason: "read past charges",
};

const historySummary = { requests24h: 1, denials24h: 0 };
const policyDigest = "stripe ceiling=charges.read";

describe("Built-in WebGPU Brain Provider", () => {
  it("defines default built-in model and model list", () => {
    expect(DEFAULT_BUILTIN_MODEL).toBe("llama3.2:1b");
    expect(BUILTIN_MODELS.length).toBeGreaterThanOrEqual(2);
    expect(BUILTIN_MODELS[0]?.id).toBe("llama3.2:1b");
    expect(BUILTIN_MODELS[0]?.diskSize).toBe("680 MB");
  });

  it("fails with MarshalUnavailable when no inference handler is registered", async () => {
    setBuiltinInferenceHandler(null);
    const result = await Effect.runPromiseExit(requestBuiltinDecision("llama3.2:1b", "test prompt"));
    expect(result._tag).toBe("Failure");
  });

  it("successfully invokes registered handler and returns decision", async () => {
    const mockDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "Safe read operation verified by built-in AI",
    };

    setBuiltinInferenceHandler((model, prompt) => {
      expect(model).toBe("llama3.2:1b");
      expect(prompt).toContain("charges.read");
      return Effect.succeed(mockDecision);
    });

    const decision = await Effect.runPromise(
      requestBuiltinDecision("llama3.2:1b", "prompt with charges.read"),
    );
    expect(decision).toEqual(mockDecision);
    setBuiltinInferenceHandler(null);
  });

  it("integrates seamlessly into assessFromSettings for provider='builtin'", async () => {
    const settings: WardenSettings = {
      provider: "builtin",
      model: "llama3.2:1b",
      effort: "standard",
      metaApiBaseUrl: "https://api.llama.com/v1",
    };

    const mockDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: true,
      explanation: "Standard approval required",
    };

    setBuiltinInferenceHandler(() => Effect.succeed(mockDecision));

    const result = await Effect.runPromise(
      assessFromSettings(settings, undefined, testRequest, historySummary, policyDigest),
    );
    expect(result.risk).toBe("low");
    expect(result.recommendedScope).toBe("charges.read");
    expect(result.explanation).toContain("Standard approval required");

    setBuiltinInferenceHandler(null);
  });

  it("enforces scope clamping if built-in model hallucinates an escalated scope", async () => {
    const settings: WardenSettings = {
      provider: "builtin",
      model: "llama3.2:1b",
      effort: "fast",
      metaApiBaseUrl: "",
    };

    const escalatedDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "*", // Hallucinated wildcard escalation
      requireApproval: false,
      explanation: "Escalated",
    };

    setBuiltinInferenceHandler(() => Effect.succeed(escalatedDecision));

    const result = await Effect.runPromise(
      assessFromSettings(settings, undefined, testRequest, historySummary, policyDigest),
    );
    // Must be clamped back to requestedScope
    expect(result.recommendedScope).toBe("charges.read");

    setBuiltinInferenceHandler(null);
  });
});
