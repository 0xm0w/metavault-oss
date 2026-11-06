export type Scope = string;
export type Risk = "low" | "medium" | "high";
export interface CapabilityRequest {
  agentId: string; ide: string; tool: string; alias: string;
  requestedScope: string; reason: string;
  // Agent-supplied call parameters (e.g. a GraphQL query). Carried on the
  // grant so the connector can execute the exact call after approval;
  // never contains secret material — the human approves the tool/alias/scope.
  payload?: unknown;
  verified?: boolean;
  clientPid?: number | undefined;
  clientProcess?: string | undefined;
  // Remote origin, set only for requests that arrived through the gateway.
  deviceId?: string | undefined;
  origin?: "local" | "remote" | undefined;
  transport?: string | undefined;
}
export interface MarshalDecision {
  risk: Risk; recommendedScope: string; requireApproval: boolean; explanation: string;
}
export type DecisionSource = "policy" | "marshal" | "marshal+policy" | "human";
export interface AuditEvent {
  ts: string; agentId: string; alias: string; scope: string;
  stage: "requested"|"marshal"|"policy"|"approved"|"denied"|"executed"|"expired"|"revoked"|"credential-added"|"credential-deleted"|"enrollment-created"|"enrollment-completed"|"settings-changed"|"exported";
  detail: string; modelId?: string;
  requestId?: string; risk?: Risk; recommendedScope?: string;
  decisionSource?: DecisionSource; latencyMs?: number; explanation?: string;
  verified?: boolean;
  clientPid?: number | undefined;
  clientProcess?: string | undefined;
  // Remote origin, set only for requests that arrived through the gateway.
  deviceId?: string | undefined;
  origin?: "local" | "remote" | undefined;
  transport?: string | undefined;
}
