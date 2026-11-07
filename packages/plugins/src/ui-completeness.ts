// Plugin #4: @jevault/ui-completeness
//
// Enforces the 5-State UI Contract on async components (Loading, Error, Empty,
// Partial/Edge, and Mutating disabled states).

import { Effect } from "effect";
import type {
  FloorOutcome,
  JevaultPlugin,
  JevaultPluginManifest,
  SpineSignal,
} from "../../core/src/spine.js";

export interface ComponentFileFact {
  readonly path: string;
  readonly content: string;
  readonly isAsyncUI: boolean;
  readonly hasLoadingState: boolean;
  readonly hasErrorState: boolean;
  readonly hasEmptyState: boolean;
  readonly hasMutationGuard: boolean;
}

export interface UICompletenessSignalFacts {
  readonly components?: readonly ComponentFileFact[];
}

export const UI_COMPLETENESS_MANIFEST: JevaultPluginManifest = {
  id: "@jevault/ui-completeness",
  version: "0.1.0",
  name: "5-State UI Completeness Guard",
  description: "Ensures stateful UI components handle loading, error, empty, and double-submit states",
  subscribesTo: ["diff.mutated", "pr.preflight"],
  jevQuestions: {
    handles_loading_cleanly: {
      type: "noul",
      instructions:
        "Does this component render a clear loading or skeleton state without layout thrashing?",
    },
    handles_empty_state: {
      type: "noul",
      instructions:
        "When the fetched list or dataset is empty, does the component render a meaningful zero-state rather than empty space?",
    },
    handles_error_actionably: {
      type: "noul",
      instructions:
        "Does the error branch provide actionable feedback or retry options instead of silent swallowing?",
    },
    double_submit_safe: {
      type: "noul",
      instructions:
        "Are mutation trigger buttons properly disabled during in-flight submissions to prevent double-submits?",
    },
  },
  thresholds: [
    { questionKey: "handles_loading_cleanly", warnAt: 0.5 },
    { questionKey: "handles_empty_state", warnAt: 0.5 },
    { questionKey: "handles_error_actionably", warnAt: 0.45 },
    { questionKey: "double_submit_safe", blockAt: 0.7, warnAt: 0.4 },
  ],
};

export const createUICompletenessPlugin = (): JevaultPlugin => ({
  manifest: UI_COMPLETENESS_MANIFEST,
  executeFloor: (signal: SpineSignal): Effect.Effect<FloorOutcome> =>
    Effect.sync(() => {
      const facts = signal.facts as UICompletenessSignalFacts | undefined;
      const components = facts?.components ?? [];

      const incompleteComponents: { path: string; missing: string[] }[] = [];

      for (const comp of components) {
        if (!comp.isAsyncUI) continue;

        const missing: string[] = [];
        if (!comp.hasLoadingState) missing.push("loading state");
        if (!comp.hasErrorState) missing.push("error fallback");
        if (!comp.hasMutationGuard) missing.push("mutation in-flight guard");

        if (missing.length >= 2) {
          incompleteComponents.push({ path: comp.path, missing });
        }
      }

      if (incompleteComponents.length > 0) {
        const summary = incompleteComponents
          .map((c) => `${c.path} (missing: ${c.missing.join(", ")})`)
          .join("; ");
        return {
          tag: "deny",
          code: "component_state_incomplete",
          summary: `UI component completeness check failed: ${summary}`,
          locations: incompleteComponents.map((c) => ({ path: c.path })),
        };
      }

      if (components.some((c) => c.isAsyncUI)) {
        return {
          tag: "inspect",
          stateSlice: {
            asyncComponentCount: components.filter((c) => c.isAsyncUI).length,
            paths: components.map((c) => c.path),
          },
        };
      }

      return { tag: "allow", summary: "UI completeness checks passed" };
    }),
});
