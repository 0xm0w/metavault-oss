import { Effect } from "effect";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  assessFromSettings,
  BrainFromSettings,
  Brain,
  MUSE_GLIMMER_SYSTEM_PROMPT,
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

const ollamaChatResponse = (content: string): Response =>
  new Response(
    JSON.stringify({ model: "muse-glimmer:30b", message: { role: "assistant", content }, done: true }),
    { status: 200, headers: { "content-type": "application/json" } },
  );

const bodyOf = (init: RequestInit | undefined): {
  model: string;
  format: string;
  messages: { role: string; content: string }[];
} => {
  const raw = init?.body;
  const text = raw instanceof Uint8Array ? new TextDecoder().decode(raw) : typeof raw === "string" ? raw : "";
  return JSON.parse(text) as { model: string; format: string; messages: { role: string; content: string }[] };
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  setBuiltinInferenceHandler(null);
});

describe("On-device (builtin) warden: Muse Glimmer via Ollama", () => {
  it("defines the Muse Glimmer 30B Q4_K_M default and model list", () => {
    expect(DEFAULT_BUILTIN_MODEL).toBe("muse-glimmer:30b");
    expect(BUILTIN_MODELS.map((m) => m.id)).toEqual(["muse-glimmer:30b", "hf.co/unsloth/Muse-Glimmer-30B-GGUF:UD-IQ3_XXS"]);
  });

  it("fails closed with MarshalUnavailable when local Ollama is unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() => Promise.reject(new Error("ECONNREFUSED"))),
    );
    const result = await Effect.runPromiseExit(requestBuiltinDecision("muse-glimmer:30b", "test prompt"));
    expect(result._tag).toBe("Failure");
    expect(JSON.stringify(result)).toContain("MarshalUnavailable");
  });

  it("default settings route a real request to Ollama and the model's decision scores it", async () => {
    const fetchMock = vi.fn<typeof fetch>(() =>
      Promise.resolve(
        ollamaChatResponse(
          '{"risk":"medium","recommendedScope":"charges.read","requireApproval":true,"explanation":"Muse Glimmer: read of payment data, ask the human"}',
        ),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const settings: WardenSettings = {
      provider: "builtin",
      model: "muse-glimmer:30b",
      effort: "standard",
      metaApiBaseUrl: "https://api.meta.ai/v1",
    };
    const decision = await Effect.runPromise(
      Effect.gen(function* () {
        const brain = yield* Brain;
        return yield* brain.assess(testRequest, historySummary, policyDigest);
      }).pipe(Effect.provide(BrainFromSettings(settings))),
    );
    expect(decision).toEqual({
      risk: "medium",
      recommendedScope: "charges.read",
      requireApproval: true,
      explanation: "Muse Glimmer: read of payment data, ask the human",
    });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url instanceof URL ? url.href : url).toBe("http://localhost:11434/api/chat");
    const body = bodyOf(init);
    expect(body.model).toBe("muse-glimmer:30b");
    expect(body.format).toBe("json");
    expect(body.messages[0]).toEqual({ role: "system", content: MUSE_GLIMMER_SYSTEM_PROMPT });
    expect(body.messages[1]?.content).toContain("charges.read");
  });

  it("honours METAVAULT_OLLAMA_URL for the on-device warden", async () => {
    vi.stubEnv("METAVAULT_OLLAMA_URL", "http://10.0.0.5:11434/");
    const fetchMock = vi.fn<typeof fetch>(() =>
      Promise.resolve(
        ollamaChatResponse('{"risk":"low","recommendedScope":"charges.read","requireApproval":false,"explanation":"ok"}'),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    await Effect.runPromise(requestBuiltinDecision("muse-glimmer:30b", "prompt charges.read"));
    const [url] = fetchMock.mock.calls[0] ?? [];
    expect(url instanceof URL ? url.href : url).toBe("http://10.0.0.5:11434/api/chat");
  });

  it("rejects malformed model output as MarshalInvalidOutput (never auto-approves)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() => Promise.resolve(ollamaChatResponse("Sure, approved!"))),
    );
    const result = await Effect.runPromiseExit(requestBuiltinDecision("muse-glimmer:30b", "prompt"));
    expect(result._tag).toBe("Failure");
    expect(JSON.stringify(result)).toContain("MarshalInvalidOutput");
  });

  it("successfully invokes registered handler and returns decision", async () => {
    const mockDecision: MarshalDecision = {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "Safe read operation verified by built-in AI",
    };

    setBuiltinInferenceHandler((model, prompt) => {
      expect(model).toBe("muse-glimmer:30b");
      expect(prompt).toContain("charges.read");
      return Effect.succeed(mockDecision);
    });

    const decision = await Effect.runPromise(
      requestBuiltinDecision("muse-glimmer:30b", "prompt with charges.read"),
    );
    expect(decision).toEqual(mockDecision);
    setBuiltinInferenceHandler(null);
  });

  it("integrates seamlessly into assessFromSettings for provider='builtin'", async () => {
    const settings: WardenSettings = {
      provider: "builtin",
      model: "muse-glimmer:30b",
      effort: "standard",
      metaApiBaseUrl: "https://api.meta.ai/v1",
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
      model: "muse-glimmer:30b",
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
