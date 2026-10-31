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
