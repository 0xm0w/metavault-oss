// Jevault Coding Nervous System — Spine Primitives & Types.
//
// The Spine coordinates deterministic Policy Floors (Phase A) and batched
// TypeSafe Jev probability signals (Phase B) across multi-project workspaces.
// Zero secrets are ever carried in Spine signals, state slices, or handoffs.

import { Context, type Effect } from "effect";

export type SpineSignalType =
  | "secret.requested"
  | "diff.mutated"
  | "git.pre_commit"
  | "contract.changed"
  | "agent.session_changed"
  | "pr.preflight"
  | "postmortem.recorded";

export interface SpineSignal<T = Record<string, unknown>> {
  readonly id: string;
  readonly type: SpineSignalType;
  readonly ts: string;
  readonly projectId: string;
  readonly agentId?: string;
  readonly ide?: string;
  readonly facts: T;
}

export interface ProjectRecord {
  readonly id: string;
  readonly slug: string;
  readonly name: string;
  readonly rootPath: string;
  readonly stackTags: readonly string[];
  readonly createdAt: string;
}

export type ProjectEnvironment = "dev" | "staging" | "prod" | "preview";

export interface ProjectEnvironmentRecord {
  readonly projectId: string;
  readonly env: ProjectEnvironment;
  readonly requireApprovalForReads: boolean;
  readonly allowAgentWrites: boolean;
}

export type ProjectLinkKind = "api-consumer" | "shared-env" | "shared-schema" | "monorepo-pkg";

export interface ProjectLinkRecord {
  readonly id: string;
  readonly sourceProjectId: string;
  readonly targetProjectId: string;
  readonly kind: ProjectLinkKind;
  readonly contractPaths: readonly string[];
}

export interface ProjectEnvRequirementRecord {
  readonly id: string;
  readonly projectId: string;
  readonly env: string;
  readonly alias: string;
  readonly required: boolean;
  readonly scopeCeiling: string;
  readonly description: string;
}

export interface ProjectPluginRecord {
  readonly projectId: string;
  readonly pluginId: string;
  readonly enabled: boolean;
  readonly config: Record<string, unknown>;
}

export type ShiftHandoffType = "pulse" | "preflight" | "shift_change" | "postmortem";

export interface ShiftHandoffRecord {
  readonly id: string;
  readonly projectId: string;
  readonly branch: string;
  readonly agentId: string;
  readonly ide: string;
  readonly checkpointType: ShiftHandoffType;
  readonly summary: string;
  readonly details: Record<string, unknown>;
  readonly createdAt: string;
}

export interface CodeLocation {
  readonly path: string;
  readonly line?: number;
  readonly column?: number;
}

export type FloorOutcome =
  | { readonly tag: "allow"; readonly summary: string }
  | {
      readonly tag: "deny";
      readonly code: string;
      readonly summary: string;
      readonly locations?: readonly CodeLocation[];
    }
  | { readonly tag: "inspect"; readonly stateSlice: Record<string, unknown> };

export type JevQuestionSpec =
  | { readonly type: "noul"; readonly instructions: string }
  | {
      readonly type: "choice";
      readonly instructions: string;
      readonly criteria: Record<string, string>;
    }
  | {
      readonly type: "score";
      readonly instructions: string;
      readonly min?: number;
      readonly max?: number;
    };

export interface ThresholdRule {
  readonly questionKey: string;
  readonly blockAt?: number;
  readonly escalateAt?: number;
  readonly warnAt?: number;
  readonly failClosed?: boolean;
}

export interface DynamicChecklistItem {
  readonly id: string;
  readonly category: string;
  readonly label: string;
  readonly checked: boolean;
  readonly severity: "blocker" | "recommended" | "info";
  readonly details?: string;
}

export interface JevaultPluginManifest {
  readonly id: string;
  readonly version: string;
  readonly name: string;
  readonly description: string;
  readonly subscribesTo: readonly SpineSignalType[];
  readonly jevQuestions: Record<string, JevQuestionSpec>;
  readonly thresholds: readonly ThresholdRule[];
}

export interface PluginFinding {
  readonly pluginId: string;
  readonly severity: "deny" | "warn" | "info";
  readonly code: string;
  readonly message: string;
  readonly locations?: readonly CodeLocation[];
}

export interface JevaultPlugin {
  readonly manifest: JevaultPluginManifest;
  readonly executeFloor: (
    signal: SpineSignal,
    project: ProjectRecord,
  ) => Effect.Effect<FloorOutcome, unknown>;
  readonly evaluateJevAnswers?: (
    answers: Record<string, unknown>,
    signal: SpineSignal,
    project: ProjectRecord,
  ) => Effect.Effect<readonly PluginFinding[], unknown>;
}

export interface SpinePulseReport {
  readonly projectId: string;
  readonly status: "pass" | "warn" | "block";
  readonly findings: readonly PluginFinding[];
  readonly evaluatedPlugins: readonly string[];
  readonly timestamp: string;
}

export interface ShipPreflightReport {
  readonly projectId: string;
  readonly targetEnv: string;
  readonly status: "ready" | "needs-attention" | "blocked";
  readonly envParity: {
    readonly matched: readonly string[];
    readonly missing: readonly string[];
    readonly extra: readonly string[];
  };
  readonly checklist: readonly DynamicChecklistItem[];
  readonly findings: readonly PluginFinding[];
  readonly receipt: {
    readonly digest: string;
    readonly timestamp: string;
    readonly verifiedBy: string;
  };
}

export interface SpineService {
  readonly registerPlugin: (plugin: JevaultPlugin) => void;
  readonly unregisterPlugin: (pluginId: string) => void;
  readonly listActivePlugins: () => readonly JevaultPlugin[];
  readonly evaluateSignal: (
    signal: SpineSignal,
    project: ProjectRecord,
  ) => Effect.Effect<SpinePulseReport>;
}

export class Spine extends Context.Tag("Spine")<Spine, SpineService>() {}
