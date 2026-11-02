import { Effect } from "effect";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_GEMINI_NANO_MODEL,
  GEMINI_NANO_INFO,
  getGeminiNanoHandler,
  isGeminiNanoAvailable,
  requestGeminiNanoDecision,
  setGeminiNanoHandler,
} from "../src/brain.js";
import type { MarshalDecision } from "../../core/src/types.js";

describe("Google Gemini Nano Provider", () => {
  it("defines default model info and metadata", () => {
    expect(DEFAULT_GEMINI_NANO_MODEL).toBe("google:gemini-nano");
    expect(GEMINI_NANO_INFO.id).toBe("google:gemini-nano");
    expect(GEMINI_NANO_INFO.provider).toBe("google");
    expect(GEMINI_NANO_INFO.runtime).toContain("window.ai");
  });

  it("reports unavailable when no handler is registered", async () => {
    setGeminiNanoHandler(null);
    expect(isGeminiNanoAvailable()).toBe(false);
    expect(getGeminiNanoHandler()).toBeNull();

    const result = await Effect.runPromiseExit(requestGeminiNanoDecision("test prompt"));
    expect(result._tag).toBe("Failure");
  });

  it("invokes registered handler and returns decision", async () => {
    const mockDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "Verified by Google Gemini Nano via Chrome Prompt API",
    };

    setGeminiNanoHandler((prompt) => {
      expect(prompt).toContain("charges.read");
      return Effect.succeed(mockDecision);
    });

    expect(isGeminiNanoAvailable()).toBe(true);
    expect(getGeminiNanoHandler()).not.toBeNull();

    const decision = await Effect.runPromise(
      requestGeminiNanoDecision("prompt with charges.read"),
    );
    expect(decision).toEqual(mockDecision);
    setGeminiNanoHandler(null);
  });
});
