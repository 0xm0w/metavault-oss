import { describe, expect } from "vitest";
import { it } from "@effect/vitest";
import { Effect } from "effect";
import { VaultStore, VaultStoreTest } from "../../core/src/storage.js";
import { makeSpineService } from "../../core/src/spine-service.js";
import type { ProjectRecord, SpineSignal } from "../../core/src/spine.js";
import {
  createAgentAntiCheatPlugin,
  createCrossRepoRadarPlugin,
  createShiftHandoffPlugin,
  createUICompletenessPlugin,
  createShipPreflightPlugin,
  generatePreflightReport,
  formatHandoffBrief,
} from "../src/index.js";

describe("Jevault Spine & Plugin Suite", () => {
  const masterKey = Buffer.alloc(32, 99);

  const mockProject: ProjectRecord = {
    id: "proj_metavault",
    slug: "metavault",
    name: "MetaVault OSS",
    rootPath: "/workspaces/metavault",
    stackTags: ["nextjs", "effect", "sqlite"],
    createdAt: new Date().toISOString(),
  };

  it.effect("Plugin #1 (@jevault/agent-anti-cheat): enforces assertion and type integrity", () =>
    Effect.gen(function* () {
      const antiCheat = createAgentAntiCheatPlugin();

      // Case A: Hard-block .skip() in test files
      const skipSignal: SpineSignal = {
        id: "sig_1",
        type: "git.pre_commit",
        ts: new Date().toISOString(),
        projectId: mockProject.id,
        facts: {
          diffs: [
            {
              path: "packages/core/test/auth.test.ts",
              addedLines: ["it.skip('bypasses real verification', () => {})"],
              removedLines: [],
            },
          ],
        },
      };

      const outcomeA = yield* antiCheat.executeFloor(skipSignal, mockProject);
      expect(outcomeA.tag).toBe("deny");
      if (outcomeA.tag === "deny") {
        expect(outcomeA.code).toBe("test_skip_forbidden");
      }

      // Case B: Hard-block @ts-ignore in security paths
      const typeBypassSignal: SpineSignal = {
        id: "sig_2",
        type: "diff.mutated",
        ts: new Date().toISOString(),
        projectId: mockProject.id,
        facts: {
          diffs: [
            {
              path: "packages/core/src/auth-guard.ts",
              addedLines: ["// @ts-ignore", "const bypass = req.user as any;"],
              removedLines: [],
            },
          ],
        },
      };

      const outcomeB = yield* antiCheat.executeFloor(typeBypassSignal, mockProject);
      expect(outcomeB.tag).toBe("deny");
      if (outcomeB.tag === "deny") {
        expect(outcomeB.code).toBe("critical_type_bypass_forbidden");
      }

      // Case C: Clean test diff passes to inspect
      const cleanSignal: SpineSignal = {
        id: "sig_3",
        type: "diff.mutated",
        ts: new Date().toISOString(),
        projectId: mockProject.id,
        facts: {
          diffs: [
            {
              path: "packages/core/test/feature.test.ts",
              addedLines: ["expect(result).toBe(true);"],
              removedLines: ["expect(result).toBe(false);"],
            },
          ],
        },
      };

      const outcomeC = yield* antiCheat.executeFloor(cleanSignal, mockProject);
      expect(outcomeC.tag).toBe("inspect");
    }));

  it.effect("Plugin #2 (@jevault/cross-repo-radar): detects breaking changes for linked consumers", () =>
    Effect.gen(function* () {
      const radar = createCrossRepoRadarPlugin();

      const breakingSignal: SpineSignal = {
        id: "sig_radar_1",
        type: "contract.changed",
        ts: new Date().toISOString(),
        projectId: "proj_api",
        facts: {
          removedExportedSymbols: ["UserSessionResponse"],
          removedEnvKeys: ["API_SIGNING_SECRET"],
          linkedConsumers: [
            {
              projectId: "proj_web",
              references: ["UserSessionResponse"],
            },
          ],
        },
      };

      const outcome = yield* radar.executeFloor(breakingSignal, mockProject);
      expect(outcome.tag).toBe("deny");
      if (outcome.tag === "deny") {
        expect(outcome.code).toBe("cross_repo_contract_violation");
        expect(outcome.summary).toContain("proj_web depends on removed symbol 'UserSessionResponse'");
      }
    }));

  it.effect("Plugin #3 (@jevault/shift-handoff): records session handoff and formats brief", () =>
    Effect.gen(function* () {
      const store = yield* VaultStore;
      const handoffPlugin = createShiftHandoffPlugin(store);

      const sessionSignal: SpineSignal = {
        id: "sig_handoff_1",
        type: "agent.session_changed",
        ts: new Date().toISOString(),
        projectId: mockProject.id,
        agentId: "cursor",
        ide: "Cursor",
        facts: {
          branch: "feat/anti-cheat",
          summary: "Added anti-cheat plugin and test suites",
          details: { testsPassing: 890 },
        },
      };

      const outcome = yield* handoffPlugin.executeFloor(sessionSignal, mockProject);
      expect(outcome.tag).toBe("allow");

      const latest = yield* store.getLatestShiftHandoff(mockProject.id, "feat/anti-cheat");
      expect(latest?.agentId).toBe("cursor");

      const brief = formatHandoffBrief(latest, mockProject.name);
      expect(brief).toContain("Jevault Shift Handoff");
      expect(brief).toContain("feat/anti-cheat");
      expect(brief).toContain("cursor");
    }).pipe(Effect.provide(VaultStoreTest(masterKey))));

  it.effect("Plugin #4 (@jevault/ui-completeness): enforces 5-state UI contract", () =>
    Effect.gen(function* () {
      const uiPlugin = createUICompletenessPlugin();

      // Case A: Missing loading state and error state in async UI
      const incompleteSignal: SpineSignal = {
        id: "sig_ui_1",
        type: "diff.mutated",
        ts: new Date().toISOString(),
        projectId: mockProject.id,
        facts: {
          components: [
            {
              path: "src/components/PaymentModal.tsx",
              content: "export function PaymentModal() { return <div>Buy</div>; }",
              isAsyncUI: true,
              hasLoadingState: false,
              hasErrorState: false,
              hasEmptyState: true,
              hasMutationGuard: false,
            },
          ],
        },
      };

      const outcomeA = yield* uiPlugin.executeFloor(incompleteSignal, mockProject);
      expect(outcomeA.tag).toBe("deny");
      if (outcomeA.tag === "deny") {
        expect(outcomeA.code).toBe("component_state_incomplete");
      }

      // Case B: Complete async UI component
      const completeSignal: SpineSignal = {
        id: "sig_ui_2",
        type: "diff.mutated",
        ts: new Date().toISOString(),
        projectId: mockProject.id,
        facts: {
          components: [
            {
              path: "src/components/PaymentModal.tsx",
              content: "export function PaymentModal() { return <div>Complete</div>; }",
              isAsyncUI: true,
              hasLoadingState: true,
              hasErrorState: true,
              hasEmptyState: true,
              hasMutationGuard: true,
            },
          ],
        },
      };

      const outcomeB = yield* uiPlugin.executeFloor(completeSignal, mockProject);
      expect(outcomeB.tag).toBe("inspect");
    }));

  it.effect("Plugin #5 (@jevault/ship-preflight): checks vault parity and destructive SQL", () =>
    Effect.gen(function* () {
      const store = yield* VaultStore;
      const preflightPlugin = createShipPreflightPlugin(store);

      // Seed project env requirement
      yield* store.upsertProjectEnvRequirement({
        projectId: mockProject.id,
        env: "prod",
        alias: "STRIPE_PRODUCTION_SECRET",
        required: true,
        scopeCeiling: "charges.write",
        description: "Stripe key for production",
      });

      // Case A: Missing secret in vault for prod
      const missingSecretSignal: SpineSignal = {
        id: "sig_preflight_1",
        type: "pr.preflight",
        ts: new Date().toISOString(),
        projectId: mockProject.id,
        facts: {
          targetEnv: "prod",
          migrationFiles: [],
        },
      };

      const outcomeA = yield* preflightPlugin.executeFloor(missingSecretSignal, mockProject);
      expect(outcomeA.tag).toBe("deny");
      if (outcomeA.tag === "deny") {
        expect(outcomeA.code).toBe("missing_env_secrets_in_vault");
      }

      // Case B: Destructive migration detected
      const destructiveSignal: SpineSignal = {
        id: "sig_preflight_2",
        type: "pr.preflight",
        ts: new Date().toISOString(),
        projectId: mockProject.id,
        facts: {
          targetEnv: "dev",
          migrationFiles: [
            {
              path: "migrations/0002_drop_users.sql",
              sql: "DROP TABLE users;",
            },
          ],
        },
      };

      const outcomeB = yield* preflightPlugin.executeFloor(destructiveSignal, mockProject);
      expect(outcomeB.tag).toBe("deny");
      if (outcomeB.tag === "deny") {
        expect(outcomeB.code).toBe("destructive_migration_unapproved");
      }

      // Case C: Preflight report generation with signed receipt
      const report = generatePreflightReport(
        mockProject,
        "staging",
        ["NEXT_PUBLIC_URL", "DATABASE_URL"],
        ["NEXT_PUBLIC_URL", "DATABASE_URL"],
        [],
      );
      expect(report.status).toBe("ready");
      expect(report.receipt.digest).toBeDefined();
      expect(report.receipt.verifiedBy).toBe("jevault-vaultd-spine");
    }).pipe(Effect.provide(VaultStoreTest(masterKey))));

  it.effect("Spine Coordinator: batches Jev questions across multiple plugins", () =>
    Effect.gen(function* () {
      let batchedQuestionsCount = 0;

      const mockJevEvaluator = (
        _state: Record<string, unknown>,
        questions: Record<string, unknown>,
      ) => {
        batchedQuestionsCount = Object.keys(questions).length;
        const answers: Record<string, unknown> = {};
        for (const key of Object.keys(questions)) {
          answers[key] = { noul: 0.1 }; // low risk / safe
        }
        return Effect.succeed(answers);
      };

      const spine = makeSpineService({ jevEvaluator: mockJevEvaluator });
      spine.registerPlugin(createAgentAntiCheatPlugin());
      spine.registerPlugin(createUICompletenessPlugin());

      const signal: SpineSignal = {
        id: "sig_batched_1",
        type: "diff.mutated",
        ts: new Date().toISOString(),
        projectId: mockProject.id,
        facts: {
          diffs: [
            {
              path: "src/button.ts",
              addedLines: ["export const b = 1;"],
              removedLines: [],
            },
          ],
          components: [
            {
              path: "src/button.tsx",
              content: "<button />",
              isAsyncUI: true,
              hasLoadingState: true,
              hasErrorState: true,
              hasEmptyState: true,
              hasMutationGuard: true,
            },
          ],
        },
      };

      const report = yield* spine.evaluateSignal(signal, mockProject);
      expect(report.status).toBe("pass");
      expect(report.evaluatedPlugins).toContain("@jevault/agent-anti-cheat");
      expect(report.evaluatedPlugins).toContain("@jevault/ui-completeness");
      // Batched questions: 3 from anti-cheat + 4 from ui-completeness = 7 total in ONE call!
      expect(batchedQuestionsCount).toBe(7);
    }));
});
