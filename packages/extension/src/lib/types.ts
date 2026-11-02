export type ExtensionMode = "companion" | "standalone";

export interface PendingGrant {
  readonly grantId: string;
  readonly agentId: string;
  readonly ide: string;
  readonly alias: string;
  readonly requestedScope: string;
  readonly recommendedScope?: string;
  readonly risk?: "low" | "medium" | "high";
  readonly reason: string;
  readonly createdAt: number;
}

export interface ExtensionState {
  readonly mode: ExtensionMode;
  readonly connected: boolean;
  readonly daemonUrl: string;
  readonly pendingCount: number;
  readonly geminiNanoReady: boolean;
  readonly phiSilicaConnected: boolean;
}

export interface GeminiDecision {
  readonly risk: "low" | "medium" | "high";
  readonly recommendedScope: string;
  readonly requireApproval: boolean;
  readonly explanation: string;
}
