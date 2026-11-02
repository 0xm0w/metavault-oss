import { Effect } from "effect";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_PHI_SILICA_MODEL,
  PHI_SILICA_INFO,
  getPhiSilicaHandler,
  isPhiSilicaAvailable,
  requestPhiSilicaDecision,
  setPhiSilicaHandler,
} from "../src/brain.js";
import type { MarshalDecision } from "../../core/src/types.js";

describe("Microsoft Phi Silica Provider", () => {
  it("defines default model info and metadata", () => {
    expect(DEFAULT_PHI_SILICA_MODEL).toBe("microsoft:phi-silica");
    expect(PHI_SILICA_INFO.id).toBe("microsoft:phi-silica");
    expect(PHI_SILICA_INFO.provider).toBe("microsoft");
    expect(PHI_SILICA_INFO.hardware).toContain("NPU");
  });

  it("reports unavailable when no handler is registered", async () => {
    setPhiSilicaHandler(null);
    expect(isPhiSilicaAvailable()).toBe(false);
    expect(getPhiSilicaHandler()).toBeNull();

    const result = await Effect.runPromiseExit(requestPhiSilicaDecision("test prompt"));
    expect(result._tag).toBe("Failure");
  });

  it("invokes registered handler and returns decision", async () => {
    const mockDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "Verified by Microsoft Phi Silica on NPU",
    };

    setPhiSilicaHandler((prompt) => {
      expect(prompt).toContain("charges.read");
      return Effect.succeed(mockDecision);
    });

    expect(isPhiSilicaAvailable()).toBe(true);
    expect(getPhiSilicaHandler()).not.toBeNull();

    const decision = await Effect.runPromise(
      requestPhiSilicaDecision("prompt with charges.read"),
    );
    expect(decision).toEqual(mockDecision);
    setPhiSilicaHandler(null);
  });
});
