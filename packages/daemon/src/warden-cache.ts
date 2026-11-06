import type { WardenSettings } from "../../core/src/settings.js";

// Settings and the decrypted Meta API key stay in memory only while the
// vault is unlocked. Invalidation zeroes the key buffer. The JS string
// returned to the caller cannot be wiped; callers must not log it.

let settingsCache: WardenSettings | null = null;
let keyBuffer: Buffer | null = null;

export function invalidateWardenCache(): void {
  if (keyBuffer !== null) {
    keyBuffer.fill(0);
    keyBuffer = null;
  }
  settingsCache = null;
}

export function readCachedWardenSettings(): WardenSettings | null {
  return settingsCache;
}

export function writeCachedWardenSettings(settings: WardenSettings): void {
  settingsCache = settings;
}

export function readCachedWardenKey(): string | null {
  if (keyBuffer === null) {
    return null;
  }
  return keyBuffer.toString("utf8");
}

export function writeCachedWardenKey(key: string): void {
  if (keyBuffer !== null) {
    keyBuffer.fill(0);
  }
  keyBuffer = Buffer.from(key, "utf8");
}
