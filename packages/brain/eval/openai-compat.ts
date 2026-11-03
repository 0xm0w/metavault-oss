import { performance } from "node:perf_hooks";
import { Effect } from "effect";
import type { MarshalDecision } from "../../core/src/types.js";
import { buildMarshalPrompt, enforceScopeSafety, parseMarshalDecision } from "../src/brain.js";
import type { ThesisCase, WardenFn } from "./run-thesis.js";

// OpenAI-compatible warden transport for the thesis benchmark (research only;
// the shipped warden is configured in Settings). It sends the same prompt the
// daemon sends (buildMarshalPrompt), parses with the same schema
// (parseMarshalDecision) and applies the same clamp (enforceScopeSafety).
// It also records, per gated request, the HTTP outcome and the token counts
// the provider returned in `usage`, and converts those to dollars with
// published per-token prices. The API key is only ever placed in the
// Authorization header; it is never logged or written to a report.

// Published prices, USD per 1M tokens. `url` is the page they were read from.
export interface Pricing {
  readonly inputPerMTok: number;
  readonly outputPerMTok: number;
  readonly cachedInputPerMTok?: number;
  readonly url: string;
}

export interface CallLog {
  readonly caseId: string;
  readonly attempts: number;
  readonly status: number | null;
  readonly ok: boolean;
  readonly promptTokens: number | null;
  readonly completionTokens: number | null;
  readonly cachedTokens: number | null;
  readonly totalTokens: number | null;
  readonly costUsd: number | null;
  readonly latencyMs: number;
  readonly error: string | null;
}

export interface OpenAICompatOptions {
  readonly baseUrl: string;
  readonly model: string;
  readonly apiKey: string;
  readonly pricing: Pricing;
  // Hard cap: a request is refused (recorded as a failure, no HTTP call) when
  // spent + the worst-case cost of that request would exceed it.
  readonly budgetUsd: number;
  readonly minIntervalMs?: number;
  readonly maxRetries?: number;
  readonly timeoutMs?: number;
  readonly maxOutputTokens?: number;
  readonly jsonMode?: boolean;
  readonly fetchFn?: typeof fetch;
  readonly sleep?: (ms: number) => Promise<void>;
}

export interface CostSummary {
  readonly gatedRequests: number;
  readonly succeeded: number;
  readonly failed: number;
  readonly requestsWithUsage: number;
  readonly promptTokens: number;
  readonly completionTokens: number;
  readonly totalTokens: number;
  readonly tokensPerGatedRequest: number | null;
  readonly costUsd: number;
  readonly dollarsPerGatedRequest: number | null;
  readonly budgetUsd: number;
  readonly pricing: Pricing;
  readonly abortedReason: string | null;
}

export interface OpenAICompatRun {
  readonly warden: WardenFn;
  readonly calls: CallLog[];
  readonly summary: () => CostSummary;
}

export function costOf(
  pricing: Pricing,
  promptTokens: number,
  completionTokens: number,
  cachedTokens = 0,
): number {
  const cached = Math.min(Math.max(0, cachedTokens), promptTokens);
  const cachedRate = pricing.cachedInputPerMTok ?? pricing.inputPerMTok;
  return ((promptTokens - cached) * pricing.inputPerMTok + cached * cachedRate + completionTokens * pricing.outputPerMTok) / 1_000_000;
}

// Upper bound on one request's cost, used only for the budget gate. Prompt
// tokens are over-estimated at one token per 2 characters.
export function worstCaseCost(pricing: Pricing, prompt: string, maxOutputTokens: number): number {
  return costOf(pricing, Math.ceil(prompt.length / 2), maxOutputTokens);
}

interface UsageShape {
  prompt_tokens?: unknown;
  completion_tokens?: unknown;
  total_tokens?: unknown;
  prompt_tokens_details?: { cached_tokens?: unknown };
}

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

// Errors that more requests cannot fix: auth, and quota refusals that say so.
function isFatal(status: number, body: string): boolean {
  if (status === 401 || status === 403) return true;
  return status === 429 && /FreeUsageLimitError|insufficient_quota|quota/i.test(body);
}

function errorSummary(status: number, body: string): string {
  try {
    const parsed = JSON.parse(body) as { error?: { type?: unknown; code?: unknown; message?: unknown } };
    const e = parsed.error;
    const kind = typeof e?.type === "string" ? e.type : typeof e?.code === "string" ? e.code : "";
    const message = typeof e?.message === "string" ? e.message : "";
    return `HTTP ${String(status)}${kind ? ` ${kind}` : ""}${message ? `: ${message.slice(0, 200)}` : ""}`;
  } catch {
    return `HTTP ${String(status)}`;
  }
}

export function openAICompatWarden(opts: OpenAICompatOptions): OpenAICompatRun {
  const base = opts.baseUrl.replace(/\/+$/, "");
  const fetchFn = opts.fetchFn ?? fetch;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const minIntervalMs = opts.minIntervalMs ?? 1500;
  const maxRetries = opts.maxRetries ?? 4;
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const maxOutputTokens = opts.maxOutputTokens ?? 2048;
  const jsonMode = opts.jsonMode ?? true;
  const calls: CallLog[] = [];
  let spent = 0;
  let lastStart = Number.NEGATIVE_INFINITY;
  let aborted: string | null = null;

  const record = (log: CallLog): null => {
    calls.push(log);
    return null;
  };

  const warden: WardenFn = async (c: ThesisCase): Promise<MarshalDecision | null> => {
    const t0 = performance.now();
    const blank = { promptTokens: null, completionTokens: null, cachedTokens: null, totalTokens: null, costUsd: null };
    if (aborted !== null) {
      return record({ caseId: c.id, attempts: 0, status: null, ok: false, ...blank, latencyMs: 0, error: `not sent: run aborted (${aborted})` });
    }
    const prompt = buildMarshalPrompt(c.request, c.history, `${c.request.alias} ceiling=${c.ceiling}`);
    const worst = worstCaseCost(opts.pricing, prompt, maxOutputTokens);
    if (spent + worst > opts.budgetUsd) {
      return record({
        caseId: c.id, attempts: 0, status: null, ok: false, ...blank, latencyMs: 0,
        error: `not sent: budget cap $${opts.budgetUsd.toFixed(2)} (spent $${spent.toFixed(6)}, worst case next $${worst.toFixed(6)})`,
      });
    }
    const body = JSON.stringify({
      model: opts.model,
      messages: [{ role: "user", content: prompt }],
      max_tokens: maxOutputTokens,
      ...(jsonMode ? { response_format: { type: "json_object" } } : {}),
    });
    let attempts = 0;
    let status: number | null = null;
    let text = "";
    let lastError: string | null = null;
    for (;;) {
      const wait = lastStart + minIntervalMs - performance.now();
      if (wait > 0) await sleep(wait);
      lastStart = performance.now();
      attempts += 1;
      let retryAfterMs = 0;
      try {
        const response = await fetchFn(`${base}/chat/completions`, {
          method: "POST",
          headers: { authorization: `Bearer ${opts.apiKey}`, "content-type": "application/json" },
          body,
          signal: AbortSignal.timeout(timeoutMs),
        });
        status = response.status;
        text = await response.text();
        if (status === 200) break;
        lastError = errorSummary(status, text);
        if (isFatal(status, text)) {
          aborted = lastError;
          break;
        }
        if (status !== 429 && status < 500) break;
        const retryAfter = Number.parseFloat(response.headers.get("retry-after") ?? "");
        retryAfterMs = Number.isFinite(retryAfter) ? retryAfter * 1000 : 0;
      } catch (error) {
        status = null;
        lastError = error instanceof Error ? `${error.name}: ${error.message}` : "request failed";
      }
      if (attempts > maxRetries) break;
      const backoff = 500 * 2 ** (attempts - 1) + Math.floor(Math.random() * 250);
      await sleep(Math.min(30_000, Math.max(backoff, retryAfterMs)));
    }
    const latencyMs = performance.now() - t0;
    if (status !== 200) {
      return record({ caseId: c.id, attempts, status, ok: false, ...blank, latencyMs, error: lastError });
    }
    let content: string | null = null;
    let usage: UsageShape | undefined;
    try {
      const parsed = JSON.parse(text) as { choices?: { message?: { content?: unknown } }[]; usage?: UsageShape };
      const raw = parsed.choices?.[0]?.message?.content;
      content = typeof raw === "string" ? raw : null;
      usage = parsed.usage;
    } catch {
      content = null;
    }
    const promptTokens = num(usage?.prompt_tokens);
    const completionTokens = num(usage?.completion_tokens);
    const cachedTokens = num(usage?.prompt_tokens_details?.cached_tokens);
    const totalTokens =
      num(usage?.total_tokens) ?? (promptTokens !== null && completionTokens !== null ? promptTokens + completionTokens : null);
    let costUsd: number | null = null;
    if (promptTokens !== null && completionTokens !== null) {
      costUsd = costOf(opts.pricing, promptTokens, completionTokens, cachedTokens ?? 0);
      spent += costUsd;
    } else {
      // No usage reported: charge the worst case so the cap stays a cap.
      spent += worst;
    }
    const usageFields = { promptTokens, completionTokens, cachedTokens, totalTokens, costUsd };
    if (content === null) {
      return record({ caseId: c.id, attempts, status, ok: false, ...usageFields, latencyMs, error: "response had no message content" });
    }
    const decoded = await Effect.runPromise(Effect.either(parseMarshalDecision(content)));
    if (decoded._tag === "Left") {
      return record({ caseId: c.id, attempts, status, ok: false, ...usageFields, latencyMs, error: decoded.left.message });
    }
    calls.push({ caseId: c.id, attempts, status, ok: true, ...usageFields, latencyMs, error: null });
    return enforceScopeSafety(decoded.right, c.request.requestedScope, c.request.reason);
  };

  const summary = (): CostSummary => {
    const withUsage = calls.filter((x) => x.totalTokens !== null);
    const promptTokens = withUsage.reduce((s, x) => s + (x.promptTokens ?? 0), 0);
    const completionTokens = withUsage.reduce((s, x) => s + (x.completionTokens ?? 0), 0);
    const totalTokens = withUsage.reduce((s, x) => s + (x.totalTokens ?? 0), 0);
    const succeeded = calls.filter((x) => x.ok).length;
    return {
      gatedRequests: calls.length,
      succeeded,
      failed: calls.length - succeeded,
      requestsWithUsage: withUsage.length,
      promptTokens,
      completionTokens,
      totalTokens,
      tokensPerGatedRequest: withUsage.length === 0 ? null : totalTokens / withUsage.length,
      costUsd: spent,
      dollarsPerGatedRequest: withUsage.length === 0 ? null : spent / withUsage.length,
      budgetUsd: opts.budgetUsd,
      pricing: opts.pricing,
      abortedReason: aborted,
    };
  };
  return { warden, calls, summary };
}
