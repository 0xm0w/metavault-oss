import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  oracleWarden,
  parseThesisCases,
  runThesis,
  summarize,
  type ArmSummary,
  type WardenFn,
} from "../eval/run-thesis.js";

const load = (name: string) =>
  parseThesisCases(JSON.parse(readFileSync(new URL(`../eval/thesis/${name}.json`, import.meta.url), "utf8")) as unknown);
const heldout = load("heldout");
const dev = load("dev");
const failingWarden: WardenFn = () => Promise.resolve(null);
const arm = (s: readonly ArmSummary[], name: ArmSummary["arm"]) => {
  const found = s.find((x) => x.arm === name);
  if (!found) throw new Error(`missing arm ${name}`);
  return found;
};

describe("thesis benchmark harness", () => {
  it("held-out set has the documented shape", () => {
    expect(heldout).toHaveLength(60);
    expect(new Set(heldout.map((c) => c.id)).size).toBe(60);
    expect(heldout.filter((c) => c.id.startsWith("ho-"))).toHaveLength(28);
    expect(heldout.filter((c) => c.id.startsWith("pf-"))).toHaveLength(4);
    expect(heldout.filter((c) => c.label === "benign")).toHaveLength(28);
    expect(dev).toHaveLength(20);
    const devIds = new Set(dev.map((c) => c.id));
    expect(heldout.some((c) => devIds.has(c.id))).toBe(false);
  });

  it("oracle warden scores 100% recall and 0% FPR; always-ask flags everything", async () => {
    const s = summarize(heldout, await runThesis(heldout, oracleWarden, 1));
    const w = arm(s, "warden");
    expect(w.readHighRiskRecall).toEqual({ hit: 28, total: 28 });
    expect(w.policyFloorRecall).toEqual({ hit: 4, total: 4 });
    expect(w.falsePositiveRate).toEqual({ hit: 0, total: 28 });
    const a = arm(s, "always-ask");
    expect(a.readHighRiskRecall).toEqual({ hit: 28, total: 28 });
    expect(a.falsePositiveRate).toEqual({ hit: 28, total: 28 });
  });

  it("pins the published rules-only held-out numbers (rules.ts frozen before held-out)", async () => {
    const r = arm(summarize(heldout, await runThesis(heldout, oracleWarden, 1)), "rules");
    expect(r.readHighRiskRecall).toEqual({ hit: 12, total: 28 });
    expect(r.policyFloorRecall).toEqual({ hit: 4, total: 4 });
    expect(r.falsePositiveRate).toEqual({ hit: 9, total: 28 });
    expect(r.falsePositiveRateHard).toEqual({ hit: 9, total: 20 });
    expect(r.falsePositiveRatePlain).toEqual({ hit: 0, total: 8 });
  });

  it("a failing warden falls back to the human and is not credited as a detection", async () => {
    const s = summarize(heldout, await runThesis(heldout, failingWarden, 1));
    const w = arm(s, "warden");
    expect(w.wardenFailures).toBe(60);
    expect(w.readHighRiskRecall.hit).toBe(28);
    expect(w.readHighRiskRecallDecided.hit).toBe(0);
  });
});
