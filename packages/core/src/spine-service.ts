// Jevault Coding Nervous System — Spine Execution Service.
//
// Coordinates deterministic Policy Floors (Phase A) and batched TypeSafe Jev
// probability signals (Phase B). Always fail-closed on critical floor invariants.

import { Effect, Layer } from "effect";
import {
  Spine,
  type FloorOutcome,
  type JevaultPlugin,
  type PluginFinding,
  type ProjectRecord,
  type SpinePulseReport,
  type SpineService,
  type SpineSignal,
} from "./spine.js";

export interface SpineExecutionOptions {
  readonly jevEvaluator?: (
    state: Record<string, unknown>,
    questions: Record<string, unknown>,
  ) => Effect.Effect<Record<string, unknown>>;
}

export function makeSpineService(options: SpineExecutionOptions = {}): SpineService {
  const plugins = new Map<string, JevaultPlugin>();

  return {
    registerPlugin: (plugin: JevaultPlugin) => {
      plugins.set(plugin.manifest.id, plugin);
    },
    unregisterPlugin: (pluginId: string) => {
      plugins.delete(pluginId);
    },
    listActivePlugins: () => Array.from(plugins.values()),
    evaluateSignal: (signal: SpineSignal, project: ProjectRecord) =>
      Effect.gen(function* () {
        const subscribed = Array.from(plugins.values()).filter((p) =>
          p.manifest.subscribesTo.includes(signal.type),
        );

        const findings: PluginFinding[] = [];
        const inspectRequests: {
          plugin: JevaultPlugin;
          outcome: Extract<FloorOutcome, { tag: "inspect" }>;
        }[] = [];

        // Phase A: Deterministic Policy Floor (< 1 ms, 0 tokens)
        for (const plugin of subscribed) {
          const outcome = yield* plugin.executeFloor(signal, project).pipe(
            Effect.catchAll((err) =>
              Effect.succeed<FloorOutcome>({
                tag: "deny",
                code: "plugin_execution_failed",
                summary: `Plugin execution threw error: ${String(err)}`,
              }),
            ),
          );
          if (outcome.tag === "deny") {
            findings.push({
              pluginId: plugin.manifest.id,
              severity: "deny",
              code: outcome.code,
              message: outcome.summary,
              ...(outcome.locations ? { locations: outcome.locations } : {}),
            });
          } else if (outcome.tag === "inspect") {
            inspectRequests.push({ plugin, outcome });
          }
        }

        // Phase B: Batched Jev Signals (Single call across all inspecting plugins)
        if (inspectRequests.length > 0 && options.jevEvaluator) {
          const batchedState: Record<string, unknown> = {
            signal: {
              type: signal.type,
              projectId: signal.projectId,
              agentId: signal.agentId,
              ide: signal.ide,
              ts: signal.ts,
            },
            slices: {},
          };

          const batchedQuestions: Record<string, unknown> = {};

          for (const item of inspectRequests) {
            const pId = item.plugin.manifest.id;
            (batchedState["slices"] as Record<string, unknown>)[pId] = item.outcome.stateSlice;
            for (const [qKey, qSpec] of Object.entries(item.plugin.manifest.jevQuestions)) {
              batchedQuestions[`${pId}__${qKey}`] = qSpec;
            }
          }

          if (Object.keys(batchedQuestions).length > 0) {
            try {
              const rawAnswers = yield* options.jevEvaluator(batchedState, batchedQuestions);

              for (const item of inspectRequests) {
                const pId = item.plugin.manifest.id;
                const pluginAnswers: Record<string, unknown> = {};

                for (const [batchedKey, ans] of Object.entries(rawAnswers)) {
                  if (batchedKey.startsWith(`${pId}__`)) {
                    const localKey = batchedKey.slice(pId.length + 2);
                    pluginAnswers[localKey] = ans;
                  }
                }

                // If plugin implements custom answer evaluator, run it
                if (item.plugin.evaluateJevAnswers) {
                  const customFindings = yield* item.plugin
                    .evaluateJevAnswers(pluginAnswers, signal, project)
                    .pipe(
                      Effect.catchAll(() =>
                        Effect.succeed<readonly PluginFinding[]>([]),
                      ),
                    );
                  findings.push(...customFindings);
                } else {
                  // Standard threshold rule evaluation
                  for (const rule of item.plugin.manifest.thresholds) {
                    const ans = pluginAnswers[rule.questionKey];
                    if (ans && typeof ans === "object") {
                      const prob = extractProbability(ans as Record<string, unknown>);
                      if (prob !== null) {
                        if (rule.blockAt !== undefined && prob >= rule.blockAt) {
                          findings.push({
                            pluginId: pId,
                            severity: "deny",
                            code: `${rule.questionKey}_threshold_exceeded`,
                            message: `Jev probability for ${rule.questionKey} (${prob.toFixed(2)}) reached block threshold (${rule.blockAt.toFixed(2)})`,
                          });
                        } else if (rule.warnAt !== undefined && prob >= rule.warnAt) {
                          findings.push({
                            pluginId: pId,
                            severity: "warn",
                            code: `${rule.questionKey}_warning`,
                            message: `Jev probability for ${rule.questionKey} (${prob.toFixed(2)}) reached warning threshold (${rule.warnAt.toFixed(2)})`,
                          });
                        }
                      }
                    }
                  }
                }
              }
            } catch {
              // If Jev fails, fail-closed for any rules configured with failClosed: true
              for (const item of inspectRequests) {
                for (const rule of item.plugin.manifest.thresholds) {
                  if (rule.failClosed) {
                    findings.push({
                      pluginId: item.plugin.manifest.id,
                      severity: "deny",
                      code: "jev_offline_fail_closed",
                      message: `Warden signal offline; fail-closed on required safety check '${rule.questionKey}'`,
                    });
                  }
                }
              }
            }
          }
        }

        const hasDeny = findings.some((f) => f.severity === "deny");
        const hasWarn = findings.some((f) => f.severity === "warn");
        const status = hasDeny ? "block" : hasWarn ? "warn" : "pass";

        const report: SpinePulseReport = {
          projectId: project.id,
          status,
          findings,
          evaluatedPlugins: subscribed.map((p) => p.manifest.id),
          timestamp: new Date().toISOString(),
        };

        return report;
      }),
  };
}

function extractProbability(answer: Record<string, unknown>): number | null {
  if (typeof answer["noul"] === "number") {
    return answer["noul"];
  }
  if (typeof answer["score"] === "number") {
    return answer["score"];
  }
  if (typeof answer["probabilities"] === "object" && answer["probabilities"] !== null) {
    const probs = answer["probabilities"] as Record<string, unknown>;
    const choice = answer["choice"];
    if (typeof choice === "string" && typeof probs[choice] === "number") {
      return probs[choice];
    }
  }
  return null;
}

export function SpineLive(options: SpineExecutionOptions = {}): Layer.Layer<Spine> {
  return Layer.succeed(Spine, makeSpineService(options));
}
