import { FetchHttpClient } from "@effect/platform";
import { Effect } from "effect";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_JEV_BASE_URL,
  DEFAULT_JEV_MODEL,
  requestJevDecision,
} from "../src/jev.js";

const req = {
  agentId: "cursor",
  ide: "Cursor",
  tool: "http",
  alias: "stripe",
  requestedScope: "payment_methods.read",
  reason: "Look up the cardholder name, full number and expiry for order 5512",
};
const history = { requests24h: 4, denials24h: 0 };
const KEY = "jev-test-key-1234567890";

type Flags = { exfil: number; injection: number; mutating: number };

const jevResponse = (
  choice: string,
  probabilities: Record<string, number>,
  confidence: number,
  approval: number,
  flags: Flags = { exfil: 0.01, injection: 0.02, mutating: 0.1 },
): Response =>
  new Response(
    JSON.stringify({
      model: "jev-1.14.0",
      answers: {
        risk: { type: "choice", choice, confidence, probabilities },
        needs_approval: { type: "noul", noul: approval },
        exfil: { type: "noul", noul: flags.exfil },
        injection: { type: "noul", noul: flags.injection },
        mutating: { type: "noul", noul: flags.mutating },
      },
      usage: { input_tokens: 436, output_tokens: 58 },
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );

const decide = (input = {}) =>
  Effect.runPromise(
    requestJevDecision({
      model: DEFAULT_JEV_MODEL,
      baseUrl: DEFAULT_JEV_BASE_URL,
      apiKey: KEY,
      req,
      history,
      policyDigest: "stripe ceiling=payment_methods.read",
      ...input,
    }).pipe(Effect.provide(FetchHttpClient.layer)),
  );

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("Jev System One provider (fake fetch)", () => {
  it("posts typed questions to /v1/systemone with the Bearer key, and the key never enters the request body", async () => {
    const fetchMock = vi.fn<typeof fetch>(() =>
      Promise.resolve(
        jevResponse("low", { low: 0.9, medium: 0.08, high: 0.02 }, 0.8, 0.15),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const decision = await decide();
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url instanceof URL ? url.href : url).toBe(
      "https://api.typesafe.ai/v1/systemone",
    );
    expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${KEY}`);
    const rawBody = init?.body;
    const body = JSON.parse(
      rawBody instanceof Uint8Array
        ? new TextDecoder().decode(rawBody)
        : typeof rawBody === "string"
          ? rawBody
          : "",
    ) as {
      model: string;
      state: Record<string, unknown>;
      questions: Record<string, { type: string }>;
    };
    expect(body.model).toBe("jev-1.14.0");
    expect(body.state["requestedScope"]).toBe("payment_methods.read");
    expect(body.state["reason"]).toBe(req.reason);
    expect(body.questions["risk"]?.type).toBe("choice");
    expect(body.questions["needs_approval"]?.type).toBe("noul");
    expect(JSON.stringify(body)).not.toContain(KEY);
    expect(decision.risk).toBe("low");
    expect(decision.recommendedScope).toBe("payment_methods.read");
    expect(decision.requireApproval).toBe(false);
    expect(decision.explanation).toContain("jev:");
  });

  it("keeps a high choice as high risk and records the probabilities in the explanation", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(
          jevResponse("high", { low: 0.01, medium: 0.05, high: 0.94 }, 0.91, 0.94),
        ),
      ),
    );
    const decision = await decide();
    expect(decision.risk).toBe("high");
    expect(decision.requireApproval).toBe(true);
    expect(decision.explanation).toContain("0.94");
  });

  it("escalates a low choice to high when a specific safety signal is strong", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(
          jevResponse("low", { low: 0.7, medium: 0.25, high: 0.05 }, 0.6, 0.4, {
            exfil: 0.85,
            injection: 0.01,
            mutating: 0.0,
          }),
        ),
      ),
    );
    const decision = await decide();
    expect(decision.risk).toBe("high");
    expect(decision.explanation).toContain("exfil=0.85");
  });

  it("raises a borderline safety signal to at least medium risk", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(
          jevResponse("low", { low: 0.8, medium: 0.15, high: 0.05 }, 0.7, 0.3, {
            exfil: 0.01,
            injection: 0.02,
            mutating: 0.5,
          }),
        ),
      ),
    );
    const decision = await decide();
    expect(decision.risk).toBe("medium");
    expect(decision.requireApproval).toBe(true);
  });

  it("requires approval when the approval question leans yes even at low risk", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(
          jevResponse("low", { low: 0.9, medium: 0.08, high: 0.02 }, 0.8, 0.62),
        ),
      ),
    );
    const decision = await decide();
    expect(decision.risk).toBe("low");
    expect(decision.requireApproval).toBe(true);
  });

  it("maps HTTP 401 to MarshalUnavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(new Response("unauthorized", { status: 401 })),
      ),
    );
    await expect(decide()).rejects.toThrow(/MarshalUnavailable/);
  });

  it("maps a malformed envelope to MarshalInvalidOutput", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(new Response(JSON.stringify({ nope: 1 }), { status: 200 })),
      ),
    );
    await expect(decide()).rejects.toThrow(/MarshalInvalidOutput/);
  });

  it("maps network failure to MarshalUnavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() => Promise.reject(new Error("ECONNREFUSED"))),
    );
    await expect(decide()).rejects.toThrow(/MarshalUnavailable/);
  });
});

describe("Jev defaults", () => {
  it("pins Jev 1.14 on the TypeSafe API host", () => {
    expect(DEFAULT_JEV_MODEL).toBe("jev-1.14.0");
    expect(DEFAULT_JEV_BASE_URL).toBe("https://api.typesafe.ai");
  });

  it("routes assessFromSettings with provider=jev through Jev decision logic", async () => {
    const { assessFromSettings } = await import("../src/brain.js");
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(
          jevResponse("low", { low: 0.95, medium: 0.04, high: 0.01 }, 0.9, 0.1),
        ),
      ),
    );
    const decision = await Effect.runPromise(
      assessFromSettings(
        {
          provider: "jev",
          model: "jev-1.14.0",
          effort: "fast",
          metaApiBaseUrl: "",
          localBaseUrl: "",
          localApi: "ollama",
          localModel: "",
          jevBaseUrl: DEFAULT_JEV_BASE_URL,
          jevModel: DEFAULT_JEV_MODEL,
        },
        () => Effect.succeed("test-jev-key"),
        req,
        history,
        "policy digest",
      ),
    );
    expect(decision.risk).toBe("low");
    expect(decision.requireApproval).toBe(false);
  });
});
