// Plugin #2: @jevault/cross-repo-radar
//
// Detects when API, schema, or .env changes in one project break linked consumers
// across the multi-project graph.

import { Effect } from "effect";
import type {
  FloorOutcome,
  JevaultPlugin,
  JevaultPluginManifest,
  SpineSignal,
} from "../../core/src/spine.js";

export interface CrossRepoSignalFacts {
  readonly touchedFiles?: readonly string[];
  readonly removedExportedSymbols?: readonly string[];
  readonly removedEnvKeys?: readonly string[];
  readonly linkedConsumers?: readonly {
    readonly projectId: string;
    readonly references: readonly string[];
  }[];
}

export const CROSS_REPO_RADAR_MANIFEST: JevaultPluginManifest = {
  id: "@jevault/cross-repo-radar",
  version: "0.1.0",
  name: "Cross-Repo Contract Radar",
  description: "Alerts when API response fields, schemas, or env vars break linked projects",
  subscribesTo: ["diff.mutated", "contract.changed", "pr.preflight"],
  jevQuestions: {
    breaking_consumer_contract: {
      type: "noul",
      instructions:
        "Will the linked consumer projects break at compile time or runtime given this modified contract?",
    },
    semantic_behavior_drift: {
      type: "noul",
      instructions:
        "Did units, pagination semantics, nullability, or error codes change in a way that causes silent failures in consumers?",
    },
  },
  thresholds: [
    { questionKey: "breaking_consumer_contract", blockAt: 0.75, warnAt: 0.45 },
    { questionKey: "semantic_behavior_drift", warnAt: 0.5 },
  ],
};

export const createCrossRepoRadarPlugin = (): JevaultPlugin => ({
  manifest: CROSS_REPO_RADAR_MANIFEST,
  executeFloor: (signal: SpineSignal): Effect.Effect<FloorOutcome> =>
    Effect.sync(() => {
      const facts = signal.facts as CrossRepoSignalFacts | undefined;
      const removedExports = facts?.removedExportedSymbols ?? [];
      const removedEnvs = facts?.removedEnvKeys ?? [];
      const consumers = facts?.linkedConsumers ?? [];

      const brokenReferences: string[] = [];

      for (const consumer of consumers) {
        for (const exp of removedExports) {
          if (consumer.references.includes(exp)) {
            brokenReferences.push(`${consumer.projectId} depends on removed symbol '${exp}'`);
          }
        }
        for (const envKey of removedEnvs) {
          if (consumer.references.includes(envKey)) {
            brokenReferences.push(`${consumer.projectId} depends on removed env key '${envKey}'`);
          }
        }
      }

      if (brokenReferences.length > 0) {
        return {
          tag: "deny",
          code: "cross_repo_contract_violation",
          summary: `Contract changes break linked repos: ${brokenReferences.join("; ")}`,
        };
      }

      if (removedExports.length > 0 || removedEnvs.length > 0 || consumers.length > 0) {
        return {
          tag: "inspect",
          stateSlice: {
            removedExports,
            removedEnvs,
            consumerCount: consumers.length,
          },
        };
      }

      return { tag: "allow", summary: "Cross-repo contracts intact" };
    }),
});
