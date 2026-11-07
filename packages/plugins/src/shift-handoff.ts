// Plugin #3: @jevault/shift-handoff
//
// Maintains cross-IDE branch context and session continuity across Claude Code,
// Cursor, Antigravity, VS Code, and Codex.

import { Effect } from "effect";
import type {
  FloorOutcome,
  JevaultPlugin,
  JevaultPluginManifest,
  ProjectRecord,
  ShiftHandoffRecord,
  SpineSignal,
} from "../../core/src/spine.js";
import type { VaultStoreService } from "../../core/src/storage.js";

export const SHIFT_HANDOFF_MANIFEST: JevaultPluginManifest = {
  id: "@jevault/shift-handoff",
  version: "0.1.0",
  name: "Cross-IDE Shift Handoff",
  description: "Preserves zero-secret branch continuity and architectural context across coding agents",
  subscribesTo: ["agent.session_changed", "diff.mutated", "git.pre_commit"],
  jevQuestions: {
    handoff_readiness: {
      type: "noul",
      instructions:
        "Is the current branch state sufficiently documented with remaining blockers for another coding agent to take over?",
    },
  },
  thresholds: [{ questionKey: "handoff_readiness", warnAt: 0.5 }],
};

export interface ShiftHandoffSignalFacts {
  readonly branch?: string;
  readonly summary?: string;
  readonly details?: Record<string, unknown>;
}

export function formatHandoffBrief(
  handoff: ShiftHandoffRecord | undefined,
  projectName: string,
): string {
  if (!handoff) {
    return `# Jevault Shift Handoff — ${projectName}\nNo prior shift checkpoint recorded on this branch.\n`;
  }

  return [
    `# Jevault Shift Handoff — ${projectName}`,
    `Branch: ${handoff.branch} | Last Agent: ${handoff.agentId} (${handoff.ide}) | Recorded: ${handoff.createdAt}`,
    `Checkpoint Type: ${handoff.checkpointType}`,
    "",
    "## Summary of Previous Shift",
    handoff.summary,
    "",
    "## Flight Ledger Details",
    "```json",
    JSON.stringify(handoff.details, null, 2),
    "```",
  ].join("\n");
}

export const createShiftHandoffPlugin = (vaultStore?: VaultStoreService): JevaultPlugin => ({
  manifest: SHIFT_HANDOFF_MANIFEST,
  executeFloor: (signal: SpineSignal, project: ProjectRecord): Effect.Effect<FloorOutcome, unknown> =>
    Effect.gen(function* () {
      const facts = signal.facts as ShiftHandoffSignalFacts | undefined;
      const branch = facts?.branch ?? "main";

      if (signal.type === "agent.session_changed" && vaultStore) {
        // Record new session presence
        yield* vaultStore.recordShiftHandoff({
          projectId: project.id,
          branch,
          agentId: signal.agentId ?? "unknown-agent",
          ide: signal.ide ?? "Unknown IDE",
          checkpointType: "shift_change",
          summary: facts?.summary ?? `Agent ${signal.agentId ?? "unknown"} connected from ${signal.ide ?? "IDE"}`,
          details: facts?.details ?? {},
        });
      }

      return {
        tag: "allow",
        summary: `Shift handoff recorded for branch ${branch}`,
      };
    }),
});
