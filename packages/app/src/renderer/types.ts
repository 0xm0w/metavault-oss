// Plain shared types for the Electron shell. The renderer imports nothing
// from the daemon-side packages: it only ever sees these shapes, which the
// daemon constructs without secret values or ciphertext.

export type Risk = "low" | "medium" | "high";

export type DecisionSource = "policy" | "marshal" | "marshal+policy" | "human";

export type AuditStage =
  | "requested"
  | "marshal"
  | "policy"
  | "approved"
  | "denied"
  | "executed"
  | "expired"
  | "revoked"
  | "credential-added"
  | "credential-deleted"
  | "enrollment-created"
  | "enrollment-completed"
  | "settings-changed";

export interface PendingApproval {
  readonly grantId: string;
  readonly agentId: string;
  readonly ide: string;
  readonly tool: string;
  readonly alias: string;
  readonly requestedScope: string;
  readonly allowedScope: string;
  readonly reason: string;
  readonly risk: Risk;
  readonly marshalExplanation: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly modelId?: string;
}

export interface AuditEventLike {
  readonly ts: string;
  readonly agentId: string;
  readonly alias: string;
  readonly scope: string;
  readonly stage: AuditStage;
  readonly detail: string;
  readonly modelId?: string;
  readonly requestId?: string;
  readonly risk?: Risk;
  readonly recommendedScope?: string;
  readonly decisionSource?: DecisionSource;
  readonly latencyMs?: number;
  readonly explanation?: string;
}

export interface CapabilityRequestLike {
  readonly agentId: string;
  readonly ide: string;
  readonly tool: string;
  readonly alias: string;
  readonly requestedScope: string;
  readonly reason: string;
}

export interface StandingApproval {
  readonly agentId: string;
  readonly alias: string;
  readonly scope: string;
}

// Real policy state from GET /policies: enforced ceiling per alias plus the
// standing approvals currently in force. Metadata only.
export interface PoliciesData {
  readonly ceilings: Readonly<Record<string, string>>;
  readonly standingApprovals: readonly StandingApproval[];
}

export interface CredentialMeta {
  readonly alias: string;
  readonly website: string;
}

export interface DeeplinkAddParams {
  readonly alias: string;
  readonly scope: string;
  readonly website: string;
  readonly enrollmentId: string;
}

export interface CredentialPatch {
  readonly scope?: string;
  readonly website?: string;
  readonly secret?: string;
}

// The whole preload bridge surface: daemon API calls only, nothing else.
export interface VaultApi {
  readonly request: (body: CapabilityRequestLike) => Promise<unknown>;
  readonly approve: (grantId: string) => Promise<unknown>;
  readonly deny: (grantId: string) => Promise<unknown>;
  readonly approveAlways: (grantId: string) => Promise<unknown>;
  readonly revoke: (target: string) => Promise<unknown>;
  readonly aliases: () => Promise<unknown>;
  readonly audit: () => Promise<unknown>;
  readonly pending: () => Promise<unknown>;
  readonly policies: () => Promise<unknown>;
  readonly addCredential: (alias: string, scope: string, secret: string, website?: string, enrollmentId?: string) => Promise<unknown>;
  readonly onDeeplinkAdd: (handler: (params: DeeplinkAddParams) => void) => () => void;
  readonly updateCredential: (alias: string, patch: CredentialPatch) => Promise<unknown>;
  readonly deleteCredential: (alias: string) => Promise<unknown>;
}

declare global {
  interface Window {
    readonly openvault: VaultApi;
  }
}
