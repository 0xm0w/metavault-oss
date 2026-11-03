import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { costOf, openAICompatWarden, type Pricing } from "../eval/openai-compat.js";
import { META_PRICING, main, parseThesisCases } from "../eval/run-thesis.js";

const cases = parseThesisCases(
  JSON.parse(readFileSync(new URL("../eval/thesis/heldout.json", import.meta.url), "utf8")) as unknown,
);
const first = cases[0];
const second = cases[1];
if (first === undefined || second === undefined) throw new Error("held-out set is empty");

const pricing: Pricing = { inputPerMTok: 1, outputPerMTok: 2, url: "https://example.test/pricing" };
const decision = (scope: string) =>
  JSON.stringify({ risk: "low", recommendedScope: scope, requireApproval: false, explanation: "routine read" });
const chat = (content: string, usage?: object) =>
  new Response(JSON.stringify({ choices: [{ message: { content } }], ...(usage ? { usage } : {}) }), { status: 200 });
const noSleep = () => Promise.resolve();

describe("openai-compatible thesis warden", () => {
  it("prices tokens per 1M, with cached input at its own rate", () => {
    expect(costOf(pricing, 1_000_000, 500_000)).toBeCloseTo(2, 10);
    expect(costOf({ ...pricing, cachedInputPerMTok: 0.1 }, 1_000_000, 0, 500_000)).toBeCloseTo(0.55, 10);
    expect(costOf(META_PRICING, 1000, 100)).toBeCloseTo((1000 * 1.25 + 100 * 4.25) / 1e6, 12);
  });

  it("retries a 429 (honouring Retry-After), logs usage and cost, never sends the key anywhere but the header", async () => {
    const seen: { url: string; auth: string | null; body: string }[] = [];
    const waits: number[] = [];
    let n = 0;
    const fetchFn = ((url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      seen.push({ url, auth: headers.get("authorization"), body: typeof init?.body === "string" ? init.body : "" });
      n += 1;
      if (n === 1) return Promise.resolve(new Response("{}", { status: 429, headers: { "retry-after": "2" } }));
      return Promise.resolve(chat(decision(first.request.requestedScope), { prompt_tokens: 1000, completion_tokens: 50, total_tokens: 1050 }));
    }) as unknown as typeof fetch;
    const run = openAICompatWarden({
      baseUrl: "https://api.example.test/v1/",
      model: "m",
      apiKey: "sk-test-secret",
      pricing,
      budgetUsd: 1,
      fetchFn,
      sleep: (ms) => {
        waits.push(ms);
        return Promise.resolve();
      },
      minIntervalMs: 0,
    });
    const out = await run.warden(first);
    expect(out?.risk).toBeDefined();
    expect(seen).toHaveLength(2);
    expect(seen[0]?.url).toBe("https://api.example.test/v1/chat/completions");
    expect(seen[0]?.auth).toBe("Bearer sk-test-secret");
    expect(seen[0]?.body).not.toContain("sk-test-secret");
    expect(waits.some((w) => w >= 2000)).toBe(true);
    expect(run.calls[0]).toMatchObject({ ok: true, attempts: 2, promptTokens: 1000, completionTokens: 50, totalTokens: 1050 });
    const s = run.summary();
    expect(s.costUsd).toBeCloseTo((1000 * 1 + 50 * 2) / 1e6, 12);
    expect(s.tokensPerGatedRequest).toBe(1050);
    expect(s.dollarsPerGatedRequest).toBeCloseTo(0.0011, 12);
    expect(JSON.stringify(run.calls)).not.toContain("sk-test-secret");
  });

  it("stops sending after a quota refusal and records the failures", async () => {
    let n = 0;
    const fetchFn = (() => {
      n += 1;
      return Promise.resolve(
        new Response(JSON.stringify({ type: "error", error: { type: "FreeUsageLimitError", message: "Free usage limit reached." } }), {
          status: 429,
        }),
      );
    }) as typeof fetch;
    const run = openAICompatWarden({ baseUrl: "https://x.test/v1", model: "m", apiKey: "k", pricing, budgetUsd: 1, fetchFn, sleep: noSleep, minIntervalMs: 0 });
    expect(await run.warden(first)).toBeNull();
    expect(await run.warden(second)).toBeNull();
    expect(n).toBe(1);
    expect(run.calls[0]?.error).toContain("FreeUsageLimitError");
    expect(run.calls[1]?.error).toContain("not sent");
    expect(run.summary()).toMatchObject({ failed: 2, succeeded: 0, abortedReason: expect.stringContaining("HTTP 429") as unknown });
  });

  it("enforces the budget cap before any request is sent", async () => {
    let n = 0;
    const fetchFn = (() => {
      n += 1;
      return Promise.resolve(chat(decision(first.request.requestedScope)));
    }) as typeof fetch;
    const run = openAICompatWarden({
      baseUrl: "https://x.test/v1",
      model: "m",
      apiKey: "k",
      pricing: { inputPerMTok: 1000, outputPerMTok: 1000, url: "u" },
      budgetUsd: 0.5,
      fetchFn,
      sleep: noSleep,
      minIntervalMs: 0,
    });
    expect(await run.warden(first)).toBeNull();
    expect(n).toBe(0);
    expect(run.calls[0]?.error).toContain("budget cap");
  });

  it("invalid model output is a failure (null -> human), not a decision", async () => {
    const fetchFn = (() => Promise.resolve(chat("not json", { prompt_tokens: 10, completion_tokens: 2 }))) as typeof fetch;
    const run = openAICompatWarden({ baseUrl: "https://x.test/v1", model: "m", apiKey: "k", pricing, budgetUsd: 1, fetchFn, sleep: noSleep, minIntervalMs: 0 });
    expect(await run.warden(first)).toBeNull();
    expect(run.calls[0]).toMatchObject({ ok: false, totalTokens: 12 });
  });

  it("meta-api mode will not run without META_API_KEY", async () => {
    const saved = process.env["META_API_KEY"];
    delete process.env["META_API_KEY"];
    try {
      expect(await main(["--live", "--provider", "meta-api"])).toBe(3);
    } finally {
      if (saved !== undefined) process.env["META_API_KEY"] = saved;
    }
  });

  it("openai-compat mode refuses to run without published prices", async () => {
    expect(await main(["--live", "--provider", "openai-compat", "--model", "m", "--base-url", "https://x.test/v1"])).toBe(2);
  });
});
