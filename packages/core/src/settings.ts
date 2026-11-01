import { Schema } from "effect";

// Warden (marshal) configuration persisted by the daemon. This record holds
// provider/model/effort/base-URL only — never a raw API key. The Meta API key
// lives as an ordinary encrypted credential under WARDEN_KEY_ALIAS.
export interface WardenSettings {
  readonly provider: "none" | "ollama" | "meta-api";
  readonly model: string;
  readonly effort: "fast" | "standard" | "deep";
  readonly metaApiBaseUrl: string;
}

export const DEFAULT_WARDEN_SETTINGS: WardenSettings = {
  provider: "ollama",
  model: "llama3.2:3b",
  effort: "standard",
  metaApiBaseUrl: "https://api.llama.com/v1",
};

export const WardenSettingsSchema = Schema.Struct({
  provider: Schema.Literal("none", "ollama", "meta-api"),
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
  readonly requireOnApproval: boolean;
  readonly requireOnLaunch: boolean;
  readonly autoLockMinutes: number;
}

export interface LocalAuthStatus {
  readonly enabled: boolean;
  readonly configured: boolean;
  readonly requireOnApproval: boolean;
  readonly requireOnLaunch: boolean;
  readonly autoLockMinutes: number;
}

export const DEFAULT_LOCAL_AUTH_RECORD: LocalAuthRecord = {
  enabled: false,
  pinHash: null,
  salt: null,
  requireOnApproval: true,
  requireOnLaunch: false,
  autoLockMinutes: 0,
};

export const DEFAULT_LOCAL_AUTH_STATUS: LocalAuthStatus = {
  enabled: false,
  configured: false,
  requireOnApproval: true,
  requireOnLaunch: false,
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
