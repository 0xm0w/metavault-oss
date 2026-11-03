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

export type WardenProvider = "none" | "ollama" | "meta-api" | "builtin" | "bft";

export interface WardenSettings {
  readonly provider: WardenProvider;
  readonly model: string;
  readonly effort: "fast" | "standard" | "deep";
  readonly metaApiBaseUrl: string;
}

export const DEFAULT_WARDEN_SETTINGS: WardenSettings = {
  provider: "builtin",
  model: "muse-glimmer:30b",
  effort: "standard",
  metaApiBaseUrl: "https://api.meta.ai/v1",
};

// Meta Muse Glimmer 30B (official Q4_K_M), served by local Ollama.
export const DEFAULT_BUILTIN_MODEL = "muse-glimmer:30b";

export const WardenSettingsSchema = Schema.Struct({
  provider: Schema.Literal("none", "ollama", "meta-api", "builtin", "bft"),
  model: Schema.String,
  effort: Schema.Literal("fast", "standard", "deep"),
  metaApiBaseUrl: Schema.String,
});

export const WARDEN_KEY_ALIAS = "warden-meta-api";
export const WARDEN_KEY_SCOPE = "warden.meta";
export const WARDEN_KEY_MIN_LENGTH = 8;

export interface WardenKeyStatus {
  readonly configured: boolean;
  readonly last4: string | null;
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
