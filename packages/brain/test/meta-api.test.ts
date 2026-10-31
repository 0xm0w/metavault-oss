import { Effect, Fiber, TestClock, TestContext } from "effect";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  Brain,
  BrainFromSettings,
  EFFORT_TIMEOUT_MS,
  OLLAMA_MODELS,
  type WardenSettings,
} from "../src/brain.js";

const req = {
  agentId: "cursor",
  ide: "Cursor",
  tool: "http",
  alias: "stripe",
  requestedScope: "charges.read",
  reason: "List last 5 failed charges",
};
const history = { requests24h: 3, denials24h: 0 };
const META_KEY = "meta-test-key-1234567890";
const settings = {
  provider: "meta-api" as const,
  model: "Llama-4-Maverick-17B-128E-Instruct-FP8",
  effort: "standard" as const,
  metaApiBaseUrl: "https://api.llama.com/v1",
};
const getKey = () => Effect.succeed<string | null>(META_KEY);

const metaResponse = (content: string): Response =>
  new Response(
    JSON.stringify({ choices: [{ message: { role: "assistant", content } }] }),
    { status: 200, headers: { "content-type": "application/json" } },
  );

const assessMeta = (s: WardenSettings = settings, key = getKey) =>
  Effect.runPromise(
    Effect.gen(function* () {
      const brain = yield* Brain;
      return yield* brain.assess(req, history, "stripe ceiling=charges.read");
    }).pipe(Effect.provide(BrainFromSettings(s, key))),
  );

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("Meta API brain provider (fake fetch)", () => {
  it("parses a decision and sends Bearer key + json response_format to {baseUrl}/chat/completions", async () => {
    const fetchMock = vi.fn<typeof fetch>(() =>
      Promise.resolve(
        metaResponse(
          '{"risk":"low","recommendedScope":"charges.read","requireApproval":false,"explanation":"read-only"}',
        ),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const decision = await assessMeta();
    expect(decision.risk).toBe("low");
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url instanceof URL ? url.href : url).toBe(
      "https://api.llama.com/v1/chat/completions",
    );
    const headers = new Headers(init?.headers);
    expect(headers.get("authorization")).toBe(`Bearer ${META_KEY}`);
    const rawBody = init?.body;
    const bodyText =
      rawBody instanceof Uint8Array
        ? new TextDecoder().decode(rawBody)
        : typeof rawBody === "string"
          ? rawBody
          : "";
    const body = JSON.parse(bodyText) as {
      model: string;
      response_format: unknown;
      messages: { content: string }[];
    };
    expect(body.model).toBe(settings.model);
    expect(body.response_format).toEqual({ type: "json_object" });
    expect(body.messages[0]?.content).toContain("charges.read");
    expect(body.messages[0]?.content).not.toContain(META_KEY);
  });

  it("maps bad JSON content to MarshalInvalidOutput", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() => Promise.resolve(metaResponse("looks fine"))),
    );
    await expect(assessMeta()).rejects.toThrow(/MarshalInvalidOutput/);
  });

  it("maps a malformed envelope to MarshalInvalidOutput", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(new Response(JSON.stringify({ nope: 1 }), { status: 200 })),
      ),
    );
    await expect(assessMeta()).rejects.toThrow(/MarshalInvalidOutput/);
  });

  it("maps HTTP 401 to MarshalUnavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(new Response("unauthorized", { status: 401 })),
      ),
    );
    await expect(assessMeta()).rejects.toThrow(/MarshalUnavailable/);
  });

  it("maps network failure to MarshalUnavailable and missing key to MarshalUnavailable without calling fetch", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() => Promise.reject(new Error("ECONNREFUSED"))),
    );
    await expect(assessMeta()).rejects.toThrow(/MarshalUnavailable/);

    const fetchMock = vi.fn<typeof fetch>(() =>
      Promise.resolve(metaResponse("{}")),
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      assessMeta(settings, () => Effect.succeed(null)),
    ).rejects.toThrow(/MarshalUnavailable/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("effort levels", () => {
  it("exposes fast=10s standard=30s deep=60s timeouts", () => {
    expect(EFFORT_TIMEOUT_MS).toEqual({ fast: 10_000, standard: 30_000, deep: 60_000 });
  });

  it("fast effort times out at 10s as MarshalUnavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() => new Promise<Response>(() => undefined)),
    );
    const program = Effect.gen(function* () {
      const brain = yield* Brain;
      const fiber = yield* Effect.fork(
        brain.assess(req, history, "stripe ceiling=charges.read"),
      );
      yield* TestClock.adjust("10 seconds");
      return yield* Fiber.join(fiber);
    }).pipe(
      Effect.provide(BrainFromSettings({ ...settings, effort: "fast" }, getKey)),
      Effect.provide(TestContext.TestContext),
    );
    await expect(Effect.runPromise(program)).rejects.toThrow(/MarshalUnavailable/);
  });

  it("deep effort: disagreement escalates approval and keeps the narrower scope", async () => {
    const contents = [
      '{"risk":"low","recommendedScope":"charges.write","requireApproval":false,"explanation":"first"}',
      '{"risk":"high","recommendedScope":"charges.read","requireApproval":true,"explanation":"verify"}',
    ];
    let call = 0;
    const fetchMock = vi.fn<typeof fetch>(() =>
      Promise.resolve(metaResponse(contents[call++] ?? contents[0] ?? "{}")),
    );
    vi.stubGlobal("fetch", fetchMock);
    const decision = await assessMeta({ ...settings, effort: "deep" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(decision.requireApproval).toBe(true);
    expect(decision.recommendedScope).toBe("charges.read");
    expect(decision.risk).toBe("high");
  });

  it("deep effort: agreement returns the verdict after two passes", async () => {
    const content =
      '{"risk":"low","recommendedScope":"charges.read","requireApproval":false,"explanation":"ok"}';
    const fetchMock = vi.fn<typeof fetch>(() =>
      Promise.resolve(metaResponse(content)),
    );
    vi.stubGlobal("fetch", fetchMock);
    const decision = await assessMeta({ ...settings, effort: "deep" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(decision).toEqual({
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "ok",
    });
  });
});

describe("OLLAMA_MODELS catalogue", () => {
  it("lists llama3.2:3b / llama3.1:8b / llama3.3:70b with tiers", () => {
    expect(OLLAMA_MODELS.map((m) => m.id)).toEqual([
      "llama3.2:3b",
      "llama3.1:8b",
      "llama3.3:70b",
    ]);
    expect(OLLAMA_MODELS.map((m) => m.tier)).toEqual([
      "Medium",
      "High",
      "Maximum-local",
    ]);
  });
});
