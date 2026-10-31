export type Scope = string;
export type Risk = "low" | "medium" | "high";
export interface CapabilityRequest {
  agentId: string; ide: string; tool: string; alias: string;
  requestedScope: string; reason: string;
}
export interface MarshalDecision {
  risk: Risk; recommendedScope: string; requireApproval: boolean; explanation: string;
}
export interface AuditEvent {
  ts: string; agentId: string; alias: string; scope: string;
  stage: "requested"|"marshal"|"policy"|"approved"|"denied"|"executed"|"expired"|"revoked"|"credential-added"|"credential-deleted"|"enrollment-created"|"enrollment-completed";
  detail: string; modelId?: string;
}
