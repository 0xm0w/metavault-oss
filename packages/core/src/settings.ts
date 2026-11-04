import { Schema } from "effect";

// Warden (marshal) configuration persisted by the daemon. This record holds
// provider/model/effort/base-URL only — never a raw API key. The Meta API key
// lives as an ordinary encrypted credential under WARDEN_KEY_ALIAS.
export interface AgentSecuritySettings {
  readonly strictMode: boolean;
  readonly verifyCallerProcess: boolean;
}

export const DEFAULT_AGENT_SECURITY_SETTINGS: AgentSecuritySettings = {
  strictMode: false,
  verifyCallerProcess: false,
};

export const AgentSecuritySettingsSchema = Schema.Struct({
  strictMode: Schema.Boolean,
  verifyCallerProcess: Schema.Boolean,
});

export const AgentSecuritySettingsPatchSchema = Schema.Struct({
  strictMode: Schema.optional(Schema.Boolean),
  verifyCallerProcess: Schema.optional(Schema.Boolean),
});

// "local" is a bring-your-own endpoint: Ollama or any OpenAI-compatible
// server the user already runs. MetaVault ships and downloads no model.
export type WardenProvider = "none" | "meta-api" | "local" | "bft";
export type LocalEndpointApi = "ollama" | "openai";

export interface WardenSettings {
  readonly provider: WardenProvider;
  // Meta Model API model id (used by meta-api and the cloud half of bft).
  readonly model: string;
  readonly effort: "fast" | "standard" | "deep";
  readonly metaApiBaseUrl: string;
  // Bring-your-own local endpoint (used by local and the local half of bft).
  // Empty means "not configured": the warden is unavailable and policy
  // asks the human.
  readonly localBaseUrl: string;
  readonly localApi: LocalEndpointApi;
  readonly localModel: string;
}

// Out-of-box default: Muse Spark on the Meta Model API. No model is bundled
// or downloaded; a local model is the user's own endpoint, set in Settings.
export const DEFAULT_WARDEN_SETTINGS: WardenSettings = {
  provider: "meta-api",
  model: "muse-spark-1.3",
  effort: "standard",
  metaApiBaseUrl: "https://api.meta.ai/v1",
  localBaseUrl: "",
  localApi: "ollama",
  localModel: "",
};

export const DEFAULT_META_API_WARDEN_MODEL = "muse-spark-1.3";

// Suggestions shown as placeholders for the bring-your-own local endpoint.
// A Meta open model is recommended; nothing here is downloaded by MetaVault.
export const SUGGESTED_LOCAL_BASE_URL: Record<LocalEndpointApi, string> = {
  ollama: "http://localhost:11434",
  openai: "http://localhost:8000/v1",
};
export const SUGGESTED_LOCAL_MODEL = "muse-glimmer:30b";

// Earlier builds stored "ollama" (BYO Ollama) or "builtin" (MetaVault-managed
// Ollama download). Both map to the bring-your-own local endpoint now.
export const LEGACY_LOCAL_PROVIDERS = ["ollama", "builtin"] as const;
export type LegacyLocalProvider = (typeof LEGACY_LOCAL_PROVIDERS)[number];

export function normalizeWardenProvider(raw: string): WardenProvider | null {
  if (raw === "none" || raw === "meta-api" || raw === "local" || raw === "bft") return raw;
  if ((LEGACY_LOCAL_PROVIDERS as readonly string[]).includes(raw)) return "local";
  return null;
}

export function localEndpointConfigured(settings: Pick<WardenSettings, "localBaseUrl" | "localModel">): boolean {
  return settings.localBaseUrl.trim() !== "" && settings.localModel.trim() !== "";
}

// The model id that will actually answer for the selected provider.
export function effectiveWardenModel(settings: WardenSettings): string {
  if (settings.provider === "local") return settings.localModel;
  if (settings.provider === "none") return "";
  return settings.model;
}

export function defaultWardenSettings(): WardenSettings {
  return { ...DEFAULT_WARDEN_SETTINGS };
}

export const WardenSettingsSchema = Schema.Struct({
  provider: Schema.Literal("none", "meta-api", "local", "bft"),
  model: Schema.String,
  effort: Schema.Literal("fast", "standard", "deep"),
  metaApiBaseUrl: Schema.String,
  localBaseUrl: Schema.String,
  localApi: Schema.Literal("ollama", "openai"),
  localModel: Schema.String,
});

export const WARDEN_KEY_ALIAS = "warden-meta-api";
export const WARDEN_KEY_SCOPE = "warden.meta";
export const WARDEN_KEY_MIN_LENGTH = 8;

export interface WardenKeyStatus {
  readonly configured: boolean;
  // True only when the saved key's last completed connection test passed.
  readonly verified: boolean;
}

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export interface LocalAuthRecord {
  readonly enabled: boolean;
  readonly pinHash: string | null;
  readonly salt: string | null;
  readonly biometricEnabled: boolean;
  readonly requireOnApproval: boolean;
  readonly requireOnLaunch: boolean;
  readonly requireOnSettings: boolean;
  readonly autoLockMinutes: number;
}

export interface LocalAuthStatus {
  readonly enabled: boolean;
  readonly configured: boolean;
  readonly biometricEnabled: boolean;
  readonly requireOnApproval: boolean;
  readonly requireOnLaunch: boolean;
  readonly requireOnSettings: boolean;
  readonly autoLockMinutes: number;
}

export const DEFAULT_LOCAL_AUTH_RECORD: LocalAuthRecord = {
  enabled: false,
  pinHash: null,
  salt: null,
  biometricEnabled: false,
  requireOnApproval: false,
  requireOnLaunch: false,
  requireOnSettings: false,
  autoLockMinutes: 0,
};

export const DEFAULT_LOCAL_AUTH_STATUS: LocalAuthStatus = {
  enabled: false,
  configured: false,
  biometricEnabled: false,
  requireOnApproval: false,
  requireOnLaunch: false,
  requireOnSettings: false,
  autoLockMinutes: 0,
};

export function hashPin(pin: string, salt: string): string {
  return createHash("sha256").update(salt + ":" + pin).digest("hex");
}

export function generatePinSalt(): string {
  return randomBytes(16).toString("hex");
}

export function verifyPin(pin: string, salt: string, expectedHash: string): boolean {
  const actual = hashPin(pin, salt);
  const bufA = Buffer.from(actual, "hex");
  const bufB = Buffer.from(expectedHash, "hex");
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
