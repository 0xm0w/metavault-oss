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
  readonly verified?: boolean;
  readonly clientPid?: number;
  readonly clientProcess?: string;
  // Remote origin, present only for requests that arrived through the
  // gateway. Drives the remote banner and the remote-approval auth gate.
  readonly deviceId?: string;
  readonly origin?: "local" | "remote";
  readonly transport?: string;
}


export interface AgentSecuritySettingsLike {
  readonly strictMode: boolean;
  readonly verifyCallerProcess: boolean;
}

export interface AgentSecuritySettingsPatchLike {
  readonly strictMode?: boolean;
  readonly verifyCallerProcess?: boolean;
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
  readonly verified?: boolean;
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
export interface RegisteredAgent {
  readonly id: string;
  readonly name: string;
  readonly token: string;
  readonly createdAt: string;
  readonly revoked: boolean;
}

// Agent rows carried by the open GET /policies route: the daemon strips
// bearer tokens there, so this shape has no token field. Full records
// (with token) come only from token-guarded creation/rotation responses.
export interface PolicyAgent {
  readonly id: string;
  readonly name: string;
  readonly createdAt: string;
  readonly revoked: boolean;
}

export interface PoliciesData {
  readonly ceilings: Readonly<Record<string, string>>;
  readonly standingApprovals: readonly StandingApproval[];
  readonly agents?: readonly PolicyAgent[];
}

// Credential types the vault stores. "secret" is an API key/token the
// daemon injects into an HTTP call; "card" is a payment card whose number,
// name, expiry and CVV stay encrypted in the daemon. The renderer only
// ever receives a card's brand and last 4 digits.
export const CREDENTIAL_KINDS = ["secret", "card"] as const;
export type CredentialKind = (typeof CREDENTIAL_KINDS)[number];

export interface CardMetaLike {
  readonly brand: string;
  readonly last4: string;
  readonly masked: string;
}

export interface CredentialMeta {
  readonly alias: string;
  readonly website: string;
  readonly kind?: CredentialKind;
  readonly card?: CardMetaLike;
}

export interface CardInputLike {
  readonly number: string;
  readonly name: string;
  readonly expMonth: number;
  readonly expYear: number;
  readonly cvv: string;
}

export interface DeeplinkAddParams {
  readonly alias: string;
  readonly scope: string;
  readonly website: string;
  readonly enrollmentId: string;
}

export type WardenProvider = "none" | "meta-api" | "local" | "bft";
export type LocalApiStyle = "ollama" | "openai";
export type WardenEffort = "fast" | "standard" | "deep";

export interface WardenSettingsLike {
  readonly provider: WardenProvider;
  readonly model: string;
  readonly effort: WardenEffort;
  readonly metaApiBaseUrl: string;
  readonly localBaseUrl: string;
  readonly localApi: LocalApiStyle;
  readonly localModel: string;
}

export interface WardenSettingsPatch {
  readonly provider?: WardenProvider;
  readonly model?: string;
  readonly effort?: WardenEffort;
  readonly metaApiBaseUrl?: string;
  readonly localBaseUrl?: string;
  readonly localApi?: LocalApiStyle;
  readonly localModel?: string;
}

export interface WardenKeyStatusLike {
  readonly configured: boolean;
  readonly last4: string | null;
}

export interface WardenTestResultLike {
  readonly ok: boolean;
  readonly provider: WardenProvider;
  readonly model: string;
  readonly latencyMs: number;
  readonly detail: string;
  // Fixed failure reason from vaultd (never a response body or key part).
  readonly reason?: string;
}

export interface CredentialPatch {
  readonly scope?: string;
  readonly website?: string;
  readonly secret?: string;
}

export interface SecurityPostureCheckLike {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly passed: boolean;
  readonly severity: "critical" | "warning" | "info";
  readonly scoreImpact: number;
}

export interface SecurityPostureIssueLike {
  readonly id: string;
  readonly title: string;
  readonly detail: string;
  readonly severity: "critical" | "warning" | "info";
  readonly alias?: string;
  readonly agentId?: string;
}

export interface SecurityPostureRemediationLike {
  readonly id: string;
  readonly title: string;
  readonly action: "enable-warden" | "restrict-ceiling" | "revoke-standing" | "rotate-stale";
  readonly alias?: string;
  readonly target?: string;
  readonly recommendedCeiling?: string;
}

export interface SecurityPostureReportLike {
  readonly score: number;
  readonly grade: "A+" | "A" | "B" | "C" | "D" | "F";
  readonly summary: string;
  readonly checks: readonly SecurityPostureCheckLike[];
  readonly issues: readonly SecurityPostureIssueLike[];
  readonly remediations: readonly SecurityPostureRemediationLike[];
}

export interface LocalAuthStatusLike {
  readonly enabled: boolean;
  readonly configured: boolean;
  readonly biometricEnabled: boolean;
  readonly requireOnApproval: boolean;
  readonly requireOnLaunch: boolean;
  readonly requireOnSettings: boolean;
  readonly autoLockMinutes: number;
}

// Remote Connections state mirrored from the daemon. All fields readonly;
// the renderer never holds tokens, keys, or pairing codes after use.
export interface RemoteSettingsLike {
  readonly enabled: boolean;
  readonly host?: string;
  readonly port?: number;
  readonly requireAuthForRemoteApproval?: boolean;
}

export interface RemoteSettingsPatchLike {
  readonly enabled?: boolean;
  readonly host?: string;
  readonly port?: number;
  readonly requireAuthForRemoteApproval?: boolean;
}

export interface DeviceLike {
  readonly id: string;
  readonly name: string;
  readonly platform?: string;
  readonly pairedAt?: string;
  readonly revoked?: boolean;
  readonly lastSeenAt?: string;
}

export interface PairingSessionLike {
  readonly pairingId?: string;
  readonly status: string;
  readonly sas?: string;
  readonly deviceName?: string;
  readonly platform?: string;
  readonly expiresAt?: string;
}

export interface LocalAuthPatchLike {
  readonly enabled?: boolean;
  readonly biometricEnabled?: boolean;
  readonly requireOnApproval?: boolean;
  readonly requireOnLaunch?: boolean;
  readonly requireOnSettings?: boolean;
  readonly autoLockMinutes?: number;
}

export interface WindowsHelloAvailabilityResult {
  readonly available: boolean;
  readonly reason: "available" | "not-configured" | "unavailable" | "failed";
}

export interface WindowsHelloVerifyResult {
  readonly ok: boolean;
  readonly reason: "verified" | "canceled" | "not-configured" | "unavailable" | "failed";
}

export interface UpdaterStatusLike {
  readonly status:
    | "idle"
    | "checking"
    | "available"
    | "not-available"
    | "downloading"
    | "downloaded"
    | "error";
  readonly version?: string;
  readonly percent?: number;
  readonly message?: string;
}


// The whole preload bridge surface: daemon API calls only, nothing else.
export interface VaultApi {
  readonly registerAgent: (id: string, name: string, rotate: boolean) => Promise<unknown>;
  readonly revokeAgent: (id: string) => Promise<unknown>;
  readonly runtimePaths: () => Promise<{ command: string; args: string[]; env: Record<string, string>; dbPath: string }>;
  readonly request: (body: CapabilityRequestLike) => Promise<unknown>;
  readonly approve: (grantId: string) => Promise<unknown>;
  readonly deny: (grantId: string) => Promise<unknown>;
  readonly approveAlways: (grantId: string) => Promise<unknown>;
  readonly revoke: (target: string) => Promise<unknown>;
  readonly aliases: () => Promise<unknown>;
  readonly audit: () => Promise<unknown>;
  readonly pending: () => Promise<unknown>;
  readonly policies: () => Promise<unknown>;
  readonly agents: () => Promise<unknown>;
  readonly getSecurityPosture: () => Promise<unknown>;
  readonly addCredential: (alias: string, scope: string, secret: string, website?: string, enrollmentId?: string) => Promise<unknown>;
  readonly addCard: (alias: string, card: CardInputLike, website?: string) => Promise<unknown>;
  readonly keyStatus: () => Promise<unknown>;
  readonly unlockVault: (passphrase: string) => Promise<unknown>;
  readonly setupVault: (passphrase: string) => Promise<unknown>;
  readonly lockVault: () => Promise<unknown>;
  readonly onDeeplinkAdd: (handler: (params: DeeplinkAddParams) => void) => () => void;
  readonly updateCredential: (alias: string, patch: CredentialPatch) => Promise<unknown>;
  readonly deleteCredential: (alias: string) => Promise<unknown>;
  readonly getWardenSettings: () => Promise<unknown>;
  readonly updateWardenSettings: (patch: WardenSettingsPatch) => Promise<unknown>;
  readonly setWardenKey: (key: string) => Promise<unknown>;
  readonly deleteWardenKey: () => Promise<unknown>;
  readonly wardenKeyStatus: () => Promise<unknown>;
  readonly testWarden: () => Promise<unknown>;
  readonly getLocalAuthStatus: () => Promise<unknown>;
  readonly updateLocalAuthSettings: (patch: LocalAuthPatchLike) => Promise<unknown>;
  readonly getRemoteSettings: () => Promise<unknown>;
  readonly updateRemoteSettings: (patch: RemoteSettingsPatchLike) => Promise<unknown>;
  readonly listDevices: () => Promise<unknown>;
  readonly startPairing: () => Promise<unknown>;
  readonly getPairingSession: () => Promise<unknown>;
  readonly confirmPairing: (pairingId: string) => Promise<unknown>;
  readonly cancelPairing: (pairingId: string) => Promise<unknown>;
  readonly renameDevice: (id: string, name: string) => Promise<unknown>;
  readonly revokeDevice: (target: string) => Promise<unknown>;
  readonly setDeviceAliasPolicy: (deviceId: string, alias: string, allowWrite: boolean) => Promise<unknown>;
  readonly listDeviceAliasPolicies: (deviceId: string) => Promise<unknown>;
  readonly getAgentSecuritySettings: () => Promise<unknown>;
  readonly updateAgentSecuritySettings: (patch: AgentSecuritySettingsPatchLike) => Promise<unknown>;
  readonly setLocalPin: (pin: string, currentPin?: string) => Promise<unknown>;
  readonly verifyLocalPin: (pin: string) => Promise<unknown>;
  readonly verifyBiometric: () => Promise<unknown>;
  readonly windowsHelloAvailability: () => Promise<WindowsHelloAvailabilityResult>;
  readonly verifyWindowsHello: (purpose: "setup" | "unlock") => Promise<WindowsHelloVerifyResult>;
  readonly bringToFront: () => void;
  readonly checkForUpdates: () => Promise<unknown>;
  readonly quitAndInstallUpdate: () => Promise<unknown>;
  readonly onUpdaterStatus: (handler: (status: UpdaterStatusLike) => void) => () => void;
}

declare global {
  interface Window {
    readonly metavault: VaultApi;
  }
}
