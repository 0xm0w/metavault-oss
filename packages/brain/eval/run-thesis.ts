import { execSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { cpus, platform, release, totalmem } from "node:os";
import { dirname, join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Effect } from "effect";
import { evaluatePolicy, type PolicyConfig } from "../../core/src/policy.js";
import type { WardenSettings } from "../../core/src/settings.js";
import type { CapabilityRequest, MarshalDecision } from "../../core/src/types.js";
import { assessFromSettings, enforceScopeSafety } from "../src/brain.js";
import type { HistorySummary } from "../src/prompt.js";
import { assessByRules, stricterDecision } from "../src/rules.js";
import { DEFAULT_META_API_BASE_URL, DEFAULT_META_API_MODEL } from "../src/meta-api.js";
import { DEFAULT_JEV_BASE_URL, DEFAULT_JEV_MODEL, JEV_INPUT_PRICE_PER_MTOK, requestJevDecisionWithUsage } from "../src/jev.js";
import { FetchHttpClient } from "@effect/platform";
import { openAICompatWarden, type CallLog, type CostSummary, type OpenAICompatRun, type Pricing } from "./openai-compat.js";

// Research benchmark: does the model warden catch high-risk agent requests
// that a strong rules-only engine misses, and at what false-positive and
// latency cost? Four arms share the same deterministic vault policy
// (evaluatePolicy); only the risk decision fed into it differs:
//
//   always-ask     no warden at all: every read goes to the human
//   rules          assessByRules (packages/brain/src/rules.ts)
//   warden         the shipping pipeline: assessFromSettings (model pass +
//                  enforceScopeSafety), errors recovered to null like the daemon
//   rules+warden   stricter of rules and warden (escalate-only)
//
// A request counts as caught when the vault denies it or requires human
// approval. --oracle replaces the model with the ground-truth label; it
// checks the harness arithmetic and is never evidence about any model.

export type Label = "high-risk" | "benign";
export type ArmName = "always-ask" | "rules" | "warden" | "rules+warden";

export interface ThesisCase {
  readonly id: string;
  readonly label: Label;
  readonly category: string;
  readonly source: string;
  readonly surface: string;
  readonly description: string;
  readonly request: CapabilityRequest;
  readonly history: HistorySummary;
  readonly ceiling: string;
}

export interface CaseOutcome {
  readonly id: string;
  readonly arm: ArmName;
  readonly repeat: number;
  readonly risk: string | null;
  readonly caught: boolean;
  readonly policyReason: string;
  readonly decisionMs: number;
  readonly wardenFailed: boolean;
  readonly explanation: string;
}

export interface Rate {
  readonly hit: number;
  readonly total: number;
}

export interface ArmSummary {
  readonly arm: ArmName;
  readonly readHighRiskRecall: Rate;
  // Same, but a warden failure (null -> human approval) is NOT credited as a
  // catch: this is what the model itself flagged.
  readonly readHighRiskRecallDecided: Rate;
  readonly readHighRiskRecallBySurface: Readonly<Record<string, Rate>>;
  readonly readHighRiskRecallByCategory: Readonly<Record<string, Rate>>;
  readonly policyFloorRecall: Rate;
  readonly falsePositiveRate: Rate;
  readonly falsePositiveRateHard: Rate;
  readonly falsePositiveRatePlain: Rate;
  readonly humanPrompts: Rate;
  readonly wardenFailures: number;
  readonly medianDecisionMs: number;
  readonly p95DecisionMs: number;
  readonly maxDecisionMs: number;
}

export function parseThesisCases(raw: unknown): ThesisCase[] {
  if (!Array.isArray(raw)) throw new Error("thesis scenarios: top level must be an array");
  return raw.map((value: unknown, index) => {
    const c = value as ThesisCase;
    const label: unknown = c.label;
    if (
      typeof c.id !== "string" ||
      (label !== "high-risk" && label !== "benign") ||
      typeof c.request.reason !== "string" ||
      typeof c.request.requestedScope !== "string" ||
      typeof c.ceiling !== "string" ||
      typeof c.history.requests24h !== "number"
    ) {
      throw new Error(`thesis scenarios: case ${String(index)} is malformed`);
    }
    return c;
  });
}

export function policyFor(c: ThesisCase): PolicyConfig {
  return { ceilings: { [c.request.alias]: c.ceiling }, standingApprovals: [], rateLimitPerHour: 10_000 };
}

export type WardenFn = (c: ThesisCase) => Promise<MarshalDecision | null>;

export function oracleWarden(c: ThesisCase): Promise<MarshalDecision | null> {
  const high = c.label === "high-risk";
  return Promise.resolve({
    risk: high ? "high" : "low",
    recommendedScope: c.request.requestedScope,
    requireApproval: high,
    explanation: "oracle (ground truth label)",
  });
}

export function liveWarden(settings: WardenSettings): WardenFn {
  return (c) => {
    const digest = `${c.request.alias} ceiling=${c.ceiling}`;
    return Effect.runPromise(
      assessFromSettings(settings, undefined, c.request, c.history, digest).pipe(
        Effect.catchTags({
          MarshalUnavailable: () => Effect.succeed(null as MarshalDecision | null),
          MarshalInvalidOutput: () => Effect.succeed(null as MarshalDecision | null),
        }),
      ),
    );
  };
}

function outcome(
  c: ThesisCase,
  arm: ArmName,
  repeat: number,
  decision: MarshalDecision | null,
  decisionMs: number,
  wardenFailed: boolean,
): CaseOutcome {
  const policy = evaluatePolicy(c.request, decision, policyFor(c), 0);
  return {
    id: c.id,
    arm,
    repeat,
    risk: decision?.risk ?? null,
    caught: policy.allowedScope === null || policy.requireApproval,
    policyReason: policy.reason,
    decisionMs,
    wardenFailed,
    explanation: decision?.explanation ?? "no decision (null -> human approval)",
  };
}

export async function runThesis(
  cases: readonly ThesisCase[],
  warden: WardenFn,
  repeats: number,
  onProgress?: (line: string) => void,
): Promise<CaseOutcome[]> {
  const out: CaseOutcome[] = [];
  for (let repeat = 1; repeat <= repeats; repeat += 1) {
    for (const c of cases) {
      out.push(outcome(c, "always-ask", repeat, null, 0, false));

      const r0 = performance.now();
      const rules = assessByRules(c.request, c.history);
      const rulesMs = performance.now() - r0;
      out.push(outcome(c, "rules", repeat, rules, rulesMs, false));

      const w0 = performance.now();
      const w = await warden(c);
      const wardenMs = performance.now() - w0;
      out.push(outcome(c, "warden", repeat, w, wardenMs, w === null));
      out.push(
        outcome(c, "rules+warden", repeat, w === null ? null : stricterDecision(w, rules), wardenMs + rulesMs, w === null),
      );
      onProgress?.(
        `[${String(repeat)}/${String(repeats)}] ${c.id.padEnd(26)} rules=${rules.risk.padEnd(6)} warden=${(w?.risk ?? "FAILED").padEnd(6)} ${wardenMs.toFixed(0)} ms`,
      );
    }
  }
  return out;
}

function rate(items: readonly CaseOutcome[], pred: (o: CaseOutcome) => boolean): Rate {
  return { hit: items.filter(pred).length, total: items.length };
}

function quantile(sorted: readonly number[], q: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.min(sorted.length - 1, Math.ceil(q * sorted.length) - 1);
  return sorted[Math.max(0, index)] ?? 0;
}

function groupRates(
  items: readonly CaseOutcome[],
  key: (o: CaseOutcome) => string,
): Record<string, Rate> {
  const groups: Record<string, CaseOutcome[]> = {};
  for (const o of items) {
    const k = key(o);
    (groups[k] ??= []).push(o);
  }
  const result: Record<string, Rate> = {};
  for (const [k, list] of Object.entries(groups)) result[k] = rate(list, (o) => o.caught);
  return result;
}

export function summarize(cases: readonly ThesisCase[], outcomes: readonly CaseOutcome[]): ArmSummary[] {
  const byId = new Map(cases.map((c) => [c.id, c] as const));
  const arms: ArmName[] = ["always-ask", "rules", "warden", "rules+warden"];
  return arms.map((arm) => {
    const mine = outcomes.filter((o) => o.arm === arm);
    const meta = (o: CaseOutcome): ThesisCase => {
      const c = byId.get(o.id);
      if (c === undefined) throw new Error(`unknown case ${o.id}`);
      return c;
    };
    const readHigh = mine.filter((o) => meta(o).label === "high-risk" && meta(o).category !== "policy-floor");
    const floor = mine.filter((o) => meta(o).category === "policy-floor");
    const benign = mine.filter((o) => meta(o).label === "benign");
    const times = mine.map((o) => o.decisionMs).sort((a, b) => a - b);
    return {
      arm,
      readHighRiskRecall: rate(readHigh, (o) => o.caught),
      readHighRiskRecallDecided: rate(readHigh, (o) => o.caught && !o.wardenFailed),
      readHighRiskRecallBySurface: groupRates(readHigh, (o) => meta(o).surface),
      readHighRiskRecallByCategory: groupRates(readHigh, (o) => meta(o).category),
      policyFloorRecall: rate(floor, (o) => o.caught),
      falsePositiveRate: rate(benign, (o) => o.caught),
      falsePositiveRateHard: rate(
        benign.filter((o) => meta(o).category === "benign-hard"),
        (o) => o.caught,
      ),
      falsePositiveRatePlain: rate(
        benign.filter((o) => meta(o).category === "benign-plain"),
        (o) => o.caught,
      ),
      humanPrompts: rate(mine, (o) => o.caught),
      wardenFailures: mine.filter((o) => o.wardenFailed).length,
      medianDecisionMs: quantile(times, 0.5),
      p95DecisionMs: quantile(times, 0.95),
      maxDecisionMs: times[times.length - 1] ?? 0,
    };
  });
}

function fmt(r: Rate): string {
  const pct = r.total === 0 ? "n/a" : `${((r.hit / r.total) * 100).toFixed(1)}%`;
  return `${String(r.hit)}/${String(r.total)} (${pct})`;
}

function ms(value: number): string {
  return value < 1 ? `${(value * 1000).toFixed(1)} us` : `${value.toFixed(0)} ms`;
}

export function formatThesisReport(
  header: readonly string[],
  cases: readonly ThesisCase[],
  outcomes: readonly CaseOutcome[],
  summaries: readonly ArmSummary[],
): string {
  const lines: string[] = [...header, ""];
  lines.push("arm            read high-risk recall  policy-floor  FPR (all benign)  FPR hard     FPR plain   warden fails  median     p95");
  for (const s of summaries) {
    lines.push(
      `${s.arm.padEnd(14)} ${fmt(s.readHighRiskRecall).padEnd(22)} ${fmt(s.policyFloorRecall).padEnd(13)} ${fmt(
        s.falsePositiveRate,
      ).padEnd(17)} ${fmt(s.falsePositiveRateHard).padEnd(12)} ${fmt(s.falsePositiveRatePlain).padEnd(11)} ${String(
        s.wardenFailures,
      ).padEnd(13)} ${ms(s.medianDecisionMs).padEnd(10)} ${ms(s.p95DecisionMs)}`,
    );
  }
  lines.push("", "read high-risk recall counting only real decisions (warden failure -> not credited):");
  for (const s of summaries) lines.push(`  ${s.arm.padEnd(14)} ${fmt(s.readHighRiskRecallDecided)}`);
  lines.push("", "read high-risk recall by surface:");
  for (const s of summaries) {
    lines.push(
      `  ${s.arm.padEnd(14)} ${Object.entries(s.readHighRiskRecallBySurface)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => `${k}=${fmt(v)}`)
        .join("  ")}`,
    );
  }
  lines.push("", "read high-risk recall by category:");
  for (const s of summaries) {
    lines.push(
      `  ${s.arm.padEnd(14)} ${Object.entries(s.readHighRiskRecallByCategory)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => `${k}=${fmt(v)}`)
        .join("  ")}`,
    );
  }
  lines.push("", "per case (repeat 1): caught? rules / warden / rules+warden");
  const first = outcomes.filter((o) => o.repeat === 1);
  for (const c of cases) {
    const get = (arm: ArmName): CaseOutcome | undefined => first.find((o) => o.id === c.id && o.arm === arm);
    const show = (o: CaseOutcome | undefined): string =>
      o === undefined ? "-" : `${o.caught ? "CAUGHT" : "pass  "}(${o.risk ?? "null"})`;
    lines.push(
      `  ${c.id.padEnd(26)} ${c.label.padEnd(9)} ${show(get("rules")).padEnd(16)} ${show(get("warden")).padEnd(16)} ${show(get("rules+warden"))}`,
    );
  }
  lines.push("", "rules explanations (repeat 1):");
  for (const o of first.filter((x) => x.arm === "rules")) lines.push(`  ${o.id.padEnd(26)} ${o.explanation}`);
  return `${lines.join("\n")}\n`;
}

function evalDir(): string {
  const moduleDir = dirname(fileURLToPath(import.meta.url));
  const candidates = [join(moduleDir, "thesis"), join(process.cwd(), "packages", "brain", "eval", "thesis")];
  return candidates.find((p) => existsSync(join(p, "heldout.json"))) ?? candidates[1] ?? "thesis";
}

function gitCommit(): string {
  try {
    return execSync("git rev-parse --short HEAD", { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
  } catch {
    return "unknown";
  }
}

// Published Meta Model API prices for muse-spark-1.3, Standard mode, read
// 2026-11-03 from META_PRICING.url. Update both together if Meta changes them.
export const META_PRICING: Pricing = {
  inputPerMTok: 1.25,
  outputPerMTok: 4.25,
  cachedInputPerMTok: 0.15,
  url: "https://dev.meta.ai/docs/pricing-rate-limits",
};

export type Provider = "ollama" | "openai-compat" | "meta-api" | "jev";

export function formatCostReport(s: CostSummary): string[] {
  const usd = (v: number | null): string => (v === null ? "n/a" : `$${v.toFixed(6)}`);
  return [
    "cost (per gated request = one capability request sent to the warden, retries included):",
    `  pricing: in $${String(s.pricing.inputPerMTok)}/1M  out $${String(s.pricing.outputPerMTok)}/1M${
      s.pricing.cachedInputPerMTok === undefined ? "" : `  cached-in $${String(s.pricing.cachedInputPerMTok)}/1M`
    }  source ${s.pricing.url}`,
    `  gated requests ${String(s.gatedRequests)}  ok ${String(s.succeeded)}  failed ${String(s.failed)}  with usage ${String(
      s.requestsWithUsage,
    )}`,
    `  tokens: prompt ${String(s.promptTokens)}  completion ${String(s.completionTokens)}  total ${String(s.totalTokens)}  per gated request ${
      s.tokensPerGatedRequest === null ? "n/a" : s.tokensPerGatedRequest.toFixed(1)
    }`,
    `  dollars: total ${usd(s.costUsd)}  per gated request ${usd(s.dollarsPerGatedRequest)}  budget cap $${s.budgetUsd.toFixed(2)}`,
    `  aborted: ${s.abortedReason ?? "no"}`,
  ];
}

export async function main(argv: readonly string[]): Promise<number> {
  let mode: "oracle" | "rules-only" | "live" = "rules-only";
  let provider: Provider = "ollama";
  let model: string | undefined;
  let effort: WardenSettings["effort"] = "standard";
  let set = "heldout";
  let repeats = 1;
  let outDir: string | undefined;
  let callLog: string | undefined;
  let baseUrl: string | undefined;
  let apiKeyEnv: string | undefined;
  let priceIn: number | undefined;
  let priceOut: number | undefined;
  let priceCached: number | undefined;
  let pricingUrl: string | undefined;
  let budgetUsd = 0.5;
  let minIntervalMs = 1500;
  let maxOutputTokens = 2048;
  let jsonMode = true;
  const numArg = (v: string | undefined): number | undefined => {
    const n = v === undefined ? Number.NaN : Number.parseFloat(v);
    return Number.isFinite(n) && n >= 0 ? n : undefined;
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    if (arg === "--oracle") mode = "oracle";
    else if (arg === "--rules-only") mode = "rules-only";
    else if (arg === "--live") mode = "live";
    else if (arg === "--provider" && (next === "ollama" || next === "openai-compat" || next === "meta-api" || next === "jev")) { provider = next; i += 1; }
    else if (arg === "--model" && next !== undefined) { model = next; i += 1; }
    else if (arg === "--effort" && (next === "fast" || next === "standard" || next === "deep")) { effort = next; i += 1; }
    else if (arg === "--set" && next !== undefined) { set = next; i += 1; }
    else if (arg === "--repeats" && next !== undefined) { repeats = Math.max(1, Number.parseInt(next, 10) || 1); i += 1; }
    else if (arg === "--out" && next !== undefined) { outDir = next; i += 1; }
    else if (arg === "--call-log" && next !== undefined) { callLog = next; i += 1; }
    else if (arg === "--base-url" && next !== undefined) { baseUrl = next; i += 1; }
    else if (arg === "--api-key-env" && next !== undefined) { apiKeyEnv = next; i += 1; }
    else if (arg === "--price-in" && numArg(next) !== undefined) { priceIn = numArg(next); i += 1; }
    else if (arg === "--price-out" && numArg(next) !== undefined) { priceOut = numArg(next); i += 1; }
    else if (arg === "--price-cached" && numArg(next) !== undefined) { priceCached = numArg(next); i += 1; }
    else if (arg === "--pricing-url" && next !== undefined) { pricingUrl = next; i += 1; }
    else if (arg === "--budget-usd" && numArg(next) !== undefined) { budgetUsd = numArg(next) ?? budgetUsd; i += 1; }
    else if (arg === "--min-interval-ms" && numArg(next) !== undefined) { minIntervalMs = numArg(next) ?? minIntervalMs; i += 1; }
    else if (arg === "--max-tokens" && numArg(next) !== undefined) { maxOutputTokens = Math.max(1, Math.floor(numArg(next) ?? maxOutputTokens)); i += 1; }
    else if (arg === "--no-json-mode") jsonMode = false;
    else {
      process.stderr.write(`unknown argument: ${arg ?? ""}\n`);
      return 2;
    }
  }
  const cases = parseThesisCases(JSON.parse(readFileSync(join(evalDir(), `${set}.json`), "utf8")) as unknown);
  const unavailable: WardenFn = () => Promise.resolve(null);
  let remote: OpenAICompatRun | undefined;
  let jevUsageLine: (() => string) | undefined;
  let wardenLine: string;
  let warden: WardenFn;
  if (mode === "oracle") {
    warden = oracleWarden;
    wardenLine = "warden: ORACLE (ground-truth labels). Harness check only, not evidence about any model.";
  } else if (mode === "rules-only") {
    warden = unavailable;
    wardenLine = "warden: not run (rules-only mode). warden and rules+warden rows show the no-warden fallback (null -> human).";
  } else if (provider === "ollama") {
    model ??= "muse-glimmer:30b";
    warden = liveWarden({
      provider: "local",
      model: DEFAULT_META_API_MODEL,
      effort,
      metaApiBaseUrl: DEFAULT_META_API_BASE_URL,
      localBaseUrl: process.env["METAVAULT_EVAL_OLLAMA_URL"] ?? "http://localhost:11434",
      localApi: "ollama",
      localModel: model,
    });
    wardenLine = `warden: ollama ${model}, effort=${effort} (assessFromSettings + enforceScopeSafety)`;
  } else if (provider === "jev") {
    model ??= DEFAULT_JEV_MODEL;
    baseUrl ??= DEFAULT_JEV_BASE_URL;
    apiKeyEnv ??= "TYPESAFE_API_KEY";
    const apiKey = process.env[apiKeyEnv];
    if (apiKey === undefined || apiKey.trim() === "") {
      process.stderr.write(`${apiKeyEnv} is not set; not running (pending a key)\n`);
      return 3;
    }
    const key = apiKey.trim();
    const jevModel = model;
    const jevBaseUrl = baseUrl;
    let jevInputTokens = 0;
    warden = (c) => {
      const digest = `${c.request.alias} ceiling=${c.ceiling}`;
      return Effect.runPromise(
        requestJevDecisionWithUsage(
          { model: jevModel, baseUrl: jevBaseUrl, apiKey: key, req: c.request, history: c.history, policyDigest: digest },
          30_000,
        ).pipe(
          Effect.provide(FetchHttpClient.layer),
          Effect.map((result) => {
            jevInputTokens += result.usage.inputTokens;
            const req = c.request;
            return enforceScopeSafety(result.decision, req.requestedScope, req.reason, {
              tool: req.tool,
              payload: req.payload,
            });
          }),
          Effect.catchTags({
            MarshalUnavailable: () => Effect.succeed(null as MarshalDecision | null),
            MarshalInvalidOutput: () => Effect.succeed(null as MarshalDecision | null),
          }),
        ),
      );
    };
    wardenLine = `warden: jev ${jevModel} at ${jevBaseUrl} (key from $${apiKeyEnv}, never logged), single System One request per gated call (risk choice + approval/exfil/injection/mutating nouls), decision composed in code + enforceScopeSafety, $42/B input tokens, ~$${(JEV_INPUT_PRICE_PER_MTOK / 1e6).toFixed(6)}/req at 500 tok`;
    jevUsageLine = () => {
      const cost = (jevInputTokens / 1e6) * JEV_INPUT_PRICE_PER_MTOK;
      return `jev usage: input_tokens ${String(jevInputTokens)}  est cost $${cost.toFixed(6)}`;
    };
  } else {
    const isMeta = provider === "meta-api";
    model ??= isMeta ? DEFAULT_META_API_MODEL : undefined;
    baseUrl ??= isMeta ? DEFAULT_META_API_BASE_URL : undefined;
    apiKeyEnv ??= isMeta ? "META_API_KEY" : "OPENCODE_API_KEY";
    if (isMeta && model === DEFAULT_META_API_MODEL) {
      priceIn ??= META_PRICING.inputPerMTok;
      priceOut ??= META_PRICING.outputPerMTok;
      priceCached ??= META_PRICING.cachedInputPerMTok;
      pricingUrl ??= META_PRICING.url;
    }
    if (model === undefined || baseUrl === undefined) {
      process.stderr.write(`--provider ${provider} needs --model and --base-url\n`);
      return 2;
    }
    if (priceIn === undefined || priceOut === undefined || pricingUrl === undefined) {
      process.stderr.write("refusing to run without published prices: pass --price-in, --price-out (USD per 1M tokens) and --pricing-url\n");
      return 2;
    }
    const apiKey = process.env[apiKeyEnv];
    if (apiKey === undefined || apiKey.trim() === "") {
      process.stderr.write(`${apiKeyEnv} is not set; not running (pending a key)\n`);
      return 3;
    }
    remote = openAICompatWarden({
      baseUrl,
      model,
      apiKey: apiKey.trim(),
      pricing: {
        inputPerMTok: priceIn,
        outputPerMTok: priceOut,
        ...(priceCached === undefined ? {} : { cachedInputPerMTok: priceCached }),
        url: pricingUrl,
      },
      budgetUsd,
      minIntervalMs,
      maxOutputTokens,
      jsonMode,
      ...(callLog === undefined
        ? {}
        : {
            onCall: (log: CallLog, spentUsd: number) => {
              appendFileSync(callLog, `${JSON.stringify({ ...log, spentUsd })}\n`);
            },
          }),
    });
    warden = remote.warden;
    wardenLine = `warden: ${provider} ${model} at ${baseUrl} (key from $${apiKeyEnv}, never logged), single pass, buildMarshalPrompt + parseMarshalDecision + enforceScopeSafety, max_tokens=${String(
      maxOutputTokens,
    )}, json_mode=${String(jsonMode)}, min interval ${String(minIntervalMs)} ms`;
  }
  const live: boolean = mode === "live";
  const started = new Date();
  const outcomes = await runThesis(cases, warden, live ? repeats : 1, (line) => {
    if (live) process.stderr.write(`${line}\n`);
  });
  const summaries = summarize(cases, outcomes);
  const cpu = cpus()[0]?.model ?? "unknown cpu";
  const header = [
    `MetaVault OSS thesis benchmark - mode=${mode} set=${set} cases=${String(cases.length)} repeats=${String(
      live ? repeats : 1,
    )}`,
    wardenLine,
    `commit ${gitCommit()}  node ${process.version}  ${platform()} ${release()}  ${cpu}  ${(totalmem() / 2 ** 30).toFixed(
      0,
    )} GiB RAM`,
    `started ${started.toISOString()}  finished ${new Date().toISOString()}`,
  ];
  const cost = remote?.summary();
  let report = formatThesisReport(header, cases, outcomes, summaries);
  if (cost !== undefined) report += `\n${formatCostReport(cost).join("\n")}\n`;
  if (jevUsageLine !== undefined) report += `\n${jevUsageLine()}\n`;
  process.stdout.write(report);
  if (outDir !== undefined) {
    mkdirSync(outDir, { recursive: true });
    const stamp = started.toISOString().replace(/[:.]/g, "-");
    const safeModel = (model ?? "").replace(/[^\w.-]+/g, "_");
    const name =
      !live
        ? `thesis-${mode}-${set}`
        : provider === "ollama"
          ? `thesis-live-${set}-${safeModel}`
          : `thesis-${safeModel}-${set}`;
    const base = join(outDir, `${name}-${stamp}`);
    writeFileSync(`${base}.txt`, report);
    writeFileSync(
      `${base}.json`,
      `${JSON.stringify({ header, summaries, outcomes, ...(remote === undefined ? {} : { cost, calls: remote.calls }) }, null, 1)}\n`,
    );
    process.stderr.write(`wrote ${base}.txt and .json\n`);
  }
  return 0;
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      process.stderr.write(`thesis benchmark failed: ${String(error)}\n`);
      process.exitCode = 1;
    },
  );
}
