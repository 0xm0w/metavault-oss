// Desktop preferences (tray, toasts, sounds, lock windows). Stored as
// desktop-preferences.json next to the vault data; read and written only by
// the Electron main process and handed to the renderer through typed IPC
// (metavault:desktop-prefs:get / metavault:desktop-prefs:update). Values
// never include secret material.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export type SoundMode = "all" | "high-risk-only" | "off";

export interface DesktopPreferences {
  readonly minimizeToTrayOnClose: boolean; // default: true
  readonly startMinimizedAtLogin: boolean; // default: true on packaged Win32
  readonly popWindowOnApproval: boolean; // default: false (toast + tray + chime instead)
  readonly toastNotificationsEnabled: boolean; // default: true
  readonly redactToastWhenLocked: boolean; // default: true
  readonly soundMode: SoundMode; // default: "all"
  readonly firstCloseNoticeShown: boolean; // default: false
}

export const DEFAULT_DESKTOP_PREFERENCES: DesktopPreferences = {
  minimizeToTrayOnClose: true,
  startMinimizedAtLogin: true,
  popWindowOnApproval: false,
  toastNotificationsEnabled: true,
  redactToastWhenLocked: true,
  soundMode: "all",
  firstCloseNoticeShown: false,
};

export const PREFERENCES_FILE_NAME = "desktop-preferences.json";

export const SOUND_MODES: readonly SoundMode[] = ["all", "high-risk-only", "off"];
export const PREFERENCE_KEYS = [
  "minimizeToTrayOnClose",
  "startMinimizedAtLogin",
  "popWindowOnApproval",
  "toastNotificationsEnabled",
  "redactToastWhenLocked",
  "soundMode",
  "firstCloseNoticeShown",
] as const;

export type PreferenceKey = (typeof PREFERENCE_KEYS)[number];

export type PreferencePatch = Partial<
  Pick<DesktopPreferences, Exclude<PreferenceKey, "firstCloseNoticeShown">>
>;

// Full replace of firstCloseNoticeShown is allowed only so main can persist
// the one-time close-to-tray hint; the patch type keeps it internal.
export type PreferenceWrite = { readonly firstCloseNoticeShown?: true } & PreferencePatch;

const SOURCE_DEFAULTS = {
  startMinimizedAtLogin: process.platform === "win32",
};

function isSoundMode(value: unknown): value is SoundMode {
  return value === "all" || value === "high-risk-only" || value === "off";
}

// Projects an untrusted parsed JSON blob onto the schema: unknown keys are
// dropped, wrong-typed values fall back to defaults, and the result is a
// complete DesktopPreferences.
export function projectDesktopPreferences(raw: unknown): DesktopPreferences {
  if (typeof raw !== "object" || raw === null) {
    return { ...DEFAULT_DESKTOP_PREFERENCES, ...SOURCE_DEFAULTS };
  }
  const record = raw as Record<string, unknown>;
  const bool = (key: PreferenceKey, fallback: boolean): boolean => {
    const value = record[key];
    return typeof value === "boolean" ? value : fallback;
  };
  const defaults: DesktopPreferences = { ...DEFAULT_DESKTOP_PREFERENCES, ...SOURCE_DEFAULTS };
  const soundMode = record["soundMode"];
  return {
    minimizeToTrayOnClose: bool("minimizeToTrayOnClose", defaults.minimizeToTrayOnClose),
    startMinimizedAtLogin: bool("startMinimizedAtLogin", defaults.startMinimizedAtLogin),
    popWindowOnApproval: bool("popWindowOnApproval", defaults.popWindowOnApproval),
    toastNotificationsEnabled: bool("toastNotificationsEnabled", defaults.toastNotificationsEnabled),
    redactToastWhenLocked: bool("redactToastWhenLocked", defaults.redactToastWhenLocked),
    soundMode: isSoundMode(soundMode) ? soundMode : defaults.soundMode,
    firstCloseNoticeShown: bool("firstCloseNoticeShown", defaults.firstCloseNoticeShown),
  };
}

// Applies a patch. Valid keys only; firstCloseNoticeShown may not be
// un-set once shown, and every other field keeps its old value otherwise.
export function applyPreferencePatch(
  prefs: DesktopPreferences,
  patch: unknown,
): { readonly prefs: DesktopPreferences; readonly ok: boolean } {
  if (typeof patch !== "object" || patch === null || Array.isArray(patch)) {
    return { prefs, ok: false };
  }
  const record = patch as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length === 0) {
    return { prefs, ok: false };
  }
  const allowedKeys = new Set<string>(PREFERENCE_KEYS);
  for (const k of keys) {
    if (!allowedKeys.has(k)) {
      return { prefs, ok: false };
    }
  }
  let ok = true;
  let appliedAny = false;
  const next: Record<string, unknown> = { ...prefs };
  for (const key of PREFERENCE_KEYS) {
    const value = record[key];
    if (value === undefined) continue;
    if (key === "soundMode" && isSoundMode(value)) {
      next["soundMode"] = value;
      appliedAny = true;
      continue;
    }
    if (key === "firstCloseNoticeShown" && value === true) {
      next["firstCloseNoticeShown"] = true;
      appliedAny = true;
      continue;
    }
    if (key !== "soundMode" && key !== "firstCloseNoticeShown" && typeof value === "boolean") {
      next[key] = value;
      appliedAny = true;
      continue;
    }
    ok = false;
  }
  if (!ok || !appliedAny) {
    return { prefs, ok: false };
  }
  return { prefs: next as unknown as DesktopPreferences, ok: true };
}

export function preferencesFilePath(dataDir: string): string {
  return join(dataDir, PREFERENCES_FILE_NAME);
}

// Synchronous load (main-process boot). A missing or corrupt file yields
// the defaults; writing happens through persistDesktopPreferences.
export function loadDesktopPreferences(
  filePath: string,
  readFile: (path: string) => Buffer = readFileSync,
  fileExists: (path: string) => boolean = existsSync,
): DesktopPreferences {
  try {
    if (!fileExists(filePath)) {
      return { ...DEFAULT_DESKTOP_PREFERENCES, ...SOURCE_DEFAULTS };
    }
    const parsed: unknown = JSON.parse(readFile(filePath).toString("utf8"));
    return projectDesktopPreferences(parsed);
  } catch {
    return { ...DEFAULT_DESKTOP_PREFERENCES, ...SOURCE_DEFAULTS };
  }
}

export function persistDesktopPreferences(filePath: string, prefs: DesktopPreferences): void {
  try {
    writeFileSync(filePath, JSON.stringify(prefs, null, 2), "utf8");
  } catch {
    // A failed preference write must never block the app; values stay in
    // memory for this run and are retried on the next change.
  }
}
