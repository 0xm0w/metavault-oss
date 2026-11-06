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
  | "settings-changed"
  | "exported";

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
  // Method and a short body preview. The raw payload never reaches the renderer.
  readonly payloadSummary?: {
    readonly declaredMethod: string | null;
    readonly mutating: boolean;
    readonly preview: string;
  };
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
  // Non-secret prefix present only once a token has been generated;
  // empty on a fresh, never-generated (seeded) agent.
  readonly tokenPrefix?: string;
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
  readonly untrusted?: boolean;
}

// Main-window lock state broadcast (Lock UI vs Lock Vault Daemon).
export interface LockStateLike {
  readonly uiLocked: boolean;
  readonly daemonLocked: boolean;
}

// Toast/deeplink click routing: main tells the renderer to open a target.
export interface NavigateLike {
  readonly kind: "approval" | "registration" | "unlock" | "audit" | "settings" | "add-credential";
  readonly id?: string;
  readonly section?: string;
  readonly target?: string;
}

export type SoundModeLike = "all" | "high-risk-only" | "off";

export interface DesktopPreferencesLike {
  readonly minimizeToTrayOnClose: boolean;
  readonly startMinimizedAtLogin: boolean;
  readonly popWindowOnApproval: boolean;
  readonly toastNotificationsEnabled: boolean;
  readonly redactToastWhenLocked: boolean;
  readonly soundMode: SoundModeLike;
  readonly firstCloseNoticeShown: boolean;
}

export interface DesktopPreferencesPatchLike {
  readonly minimizeToTrayOnClose?: boolean;
  readonly startMinimizedAtLogin?: boolean;
  readonly popWindowOnApproval?: boolean;
  readonly toastNotificationsEnabled?: boolean;
  readonly redactToastWhenLocked?: boolean;
  readonly soundMode?: SoundModeLike;
}

// Web Audio earcon names (synthesized in the renderer; no media files).
export type SoundCue =
  | "approval-standard"
  | "approval-high-risk"
  | "agent-registration"
  | "decision-approved"
  | "decision-denied"
  | "vault-locked";

export interface FlyoutGrantLike {
  readonly grantId: string;
  readonly agentId: string;
  readonly alias: string;
  readonly requestedScope: string;
  readonly allowedScope: string;
  readonly risk: string;
  readonly verified: boolean;
  readonly origin?: "local" | "remote";
  readonly explanation?: string;
  readonly payloadHeadline?: string;
}

// Snapshot pushed to the tray flyout by main. No tokens, no secrets:
// only counts and pending-card metadata the renderer already shows.
export interface FlyoutStateLike {
  readonly uiLocked: boolean;
  readonly daemonLocked: boolean;
  readonly localAuthConfigured: boolean;
  readonly canLockDaemon: boolean;
  readonly soundMode: SoundModeLike;
  readonly pendingCount: number;
  readonly registrationCount: number;
  readonly credentialCount: number;
  readonly grants: readonly FlyoutGrantLike[];
  readonly registrations: readonly {
    readonly id: string;
    readonly agentId: string;
    readonly name: string;
    readonly ide?: string;
  }[];
}

export type FlyoutActionLike =
  | { readonly type: "open-app"; readonly nav?: NavigateLike }
  | { readonly type: "lock-ui" }
  | { readonly type: "lock-daemon" }
  | { readonly type: "toggle-mute" }
  | { readonly type: "close" };

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
  // True only when the saved key's last completed connection test passed.
  readonly verified?: boolean;
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

// App-managed SSH tunnel state, mirrored from the main process. The
// renderer sees host, fingerprint and connection state only - never key
// material, never the known_hosts or identity paths' contents.
export type SshTunnelStateLike =
  | "not-configured"
  | "off"
  | "connecting"
  | "connected"
  | "reconnecting"
  | "error";

export interface SshTunnelStatusLike {
  readonly state: SshTunnelStateLike;
  readonly configured: boolean;
  readonly host?: string;
  readonly user?: string;
  readonly port?: number;
  readonly remotePairingPort?: number;
  readonly remoteDevicePort?: number;
  readonly fingerprint?: string;
  readonly autoReconnect?: boolean;
  readonly detail?: string;
  readonly attempts?: number;
  readonly connectedSince?: string;
}

export interface SshTunnelSetupProposalLike {
  readonly host: string;
  readonly user: string;
  readonly port: number;
  readonly remotePairingPort: number;
  readonly remoteDevicePort: number;
  readonly keyType: string;
  readonly fingerprint: string;
  readonly publicKey: string;
  readonly installLine: string;
  readonly policyBlock: string;
}

// Tagged results from the main process tunnel IPC.
export interface SshTunnelResultLike {
  readonly kind: "status" | "proposal" | "error" | "verification" | "ok";
  readonly status?: SshTunnelStatusLike;
  readonly proposal?: SshTunnelSetupProposalLike;
  readonly error?: string;
  readonly verified?: boolean;
  readonly reason?: string;
}

export interface SshTunnelBeginSetupInput {
  readonly address: string;
  readonly remotePairingPort?: number;
  readonly remoteDevicePort?: number;
}

export interface PresenceProofRequestLike {
  readonly scope: "approve" | "settings-remote" | "settings-local-auth" | "agents-rotate" | "settings-security";
  readonly grantId?: string;
  readonly pin?: string;
  readonly hello?: boolean;
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


// Launch-time MCP self-check result, from main over metavault:mcp-status.
export interface McpStatusLike {
  readonly state?: string;
  readonly tools?: unknown;
  readonly serverName?: string;
  readonly serverVersion?: string;
  readonly detail?: string;
  readonly checkedAt?: string;
}

// Fixed-shape request for the IDE-config channel (inspect | apply). The
// token field is the one allowed secret in an MCP config: the app writes it
// directly into the host config file, never into a chat.
export interface IdeConfigRequestLike {
  readonly action: "inspect" | "apply";
  readonly host?: string;
  readonly entry?: unknown;
  readonly token?: string;
}

// The whole preload bridge surface: daemon API calls only, nothing else.
export interface VaultApi {
  readonly registerAgent: (id: string, name: string, rotate: boolean, presenceProof?: string) => Promise<unknown>;
  readonly agentRegistrations: () => Promise<unknown>;
  readonly decideAgentRegistration: (id: string, action: "approve" | "deny", code?: string) => Promise<unknown>;
  readonly revokeAgent: (id: string) => Promise<unknown>;
  readonly runtimePaths: () => Promise<{ command: string; args: string[]; env: Record<string, string>; dbPath: string }>;
  readonly mcpStatus: () => Promise<unknown>;
  readonly ideConfig: (request: IdeConfigRequestLike) => Promise<unknown>;
  readonly request: (body: CapabilityRequestLike) => Promise<unknown>;
  readonly approve: (grantId: string, presenceProof?: string) => Promise<unknown>;
  readonly deny: (grantId: string) => Promise<unknown>;
  readonly approveAlways: (grantId: string, presenceProof?: string) => Promise<unknown>;
  readonly approveSession: (grantId: string, presenceProof?: string) => Promise<unknown>;
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
  // Desktop windowing, tray, lock state, navigation, and sound cues.
  readonly desktopPrefsGet: () => Promise<unknown>;
  readonly desktopPrefsUpdate: (patch: DesktopPreferencesPatchLike) => Promise<unknown>;
  readonly lockUi: () => Promise<void>;
  readonly lockStateGet: () => Promise<LockStateLike>;
  readonly reportUiLock: (locked: boolean) => void;
  readonly onLockState: (handler: (state: LockStateLike) => void) => () => void;
  readonly onNavigate: (handler: (nav: NavigateLike) => void) => () => void;
  readonly onPlaySound: (handler: (cue: SoundCue) => void) => () => void;
  readonly onFlyoutState: (handler: (state: FlyoutStateLike) => void) => () => void;
  readonly flyoutReady: () => void;
  readonly flyoutAction: (action: FlyoutActionLike) => void;
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
  readonly updateLocalAuthSettings: (patch: LocalAuthPatchLike, presenceProof?: string) => Promise<unknown>;
  readonly getRemoteSettings: () => Promise<unknown>;
  readonly updateRemoteSettings: (patch: RemoteSettingsPatchLike, presenceProof?: string) => Promise<unknown>;
  readonly requestPresenceProof: (req: PresenceProofRequestLike) => Promise<{ token: string }>;
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
  readonly updateAgentSecuritySettings: (patch: AgentSecuritySettingsPatchLike, presenceProof?: string) => Promise<unknown>;
  readonly setLocalPin: (pin: string, currentPin?: string) => Promise<unknown>;
  readonly verifyLocalPin: (pin: string) => Promise<unknown>;
  readonly verifyBiometric: () => Promise<unknown>;
  readonly windowsHelloAvailability: () => Promise<WindowsHelloAvailabilityResult>;
  readonly verifyWindowsHello: (purpose: "setup" | "unlock") => Promise<WindowsHelloVerifyResult>;
  readonly sshTunnelStatus: () => Promise<unknown>;
  readonly sshTunnelBeginSetup: (input: SshTunnelBeginSetupInput) => Promise<unknown>;
  readonly sshTunnelCompleteSetup: (fingerprint: string) => Promise<unknown>;
  readonly sshTunnelCancelSetup: () => Promise<unknown>;
  readonly sshTunnelConnect: () => Promise<unknown>;
  readonly sshTunnelDisconnect: () => Promise<unknown>;
  readonly sshTunnelRemove: () => Promise<unknown>;
  readonly sshTunnelSetAutoReconnect: (enabled: boolean) => Promise<unknown>;
  readonly onSshTunnelStatus: (handler: (status: SshTunnelStatusLike) => void) => () => void;
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
