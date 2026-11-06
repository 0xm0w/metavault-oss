import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  applyPreferencePatch,
  DEFAULT_DESKTOP_PREFERENCES,
  loadDesktopPreferences,
  persistDesktopPreferences,
  preferencesFilePath,
  projectDesktopPreferences,
} from "../src/desktop-prefs.js";

describe("desktop-preferences", () => {
  it("keeps popWindowOnApproval off and redactToastWhenLocked on by default", () => {
    expect(DEFAULT_DESKTOP_PREFERENCES.popWindowOnApproval).toBe(false);
    expect(DEFAULT_DESKTOP_PREFERENCES.minimizeToTrayOnClose).toBe(true);
    expect(DEFAULT_DESKTOP_PREFERENCES.toastNotificationsEnabled).toBe(true);
    expect(DEFAULT_DESKTOP_PREFERENCES.redactToastWhenLocked).toBe(true);
    expect(DEFAULT_DESKTOP_PREFERENCES.soundMode).toBe("all");
  });

  it("validates partial patches strictly and rejects empty/unknown/array patches", () => {
    expect(applyPreferencePatch(DEFAULT_DESKTOP_PREFERENCES, {}).ok).toBe(false);
    expect(applyPreferencePatch(DEFAULT_DESKTOP_PREFERENCES, []).ok).toBe(false);
    expect(applyPreferencePatch(DEFAULT_DESKTOP_PREFERENCES, null).ok).toBe(false);
    expect(applyPreferencePatch(DEFAULT_DESKTOP_PREFERENCES, { evil: true }).ok).toBe(false);
    expect(applyPreferencePatch(DEFAULT_DESKTOP_PREFERENCES, { soundMode: "loud" }).ok).toBe(false);
    expect(applyPreferencePatch(DEFAULT_DESKTOP_PREFERENCES, { firstCloseNoticeShown: false }).ok).toBe(false);

    const valid = applyPreferencePatch(DEFAULT_DESKTOP_PREFERENCES, {
      popWindowOnApproval: true,
      soundMode: "high-risk-only",
    });
    expect(valid.ok).toBe(true);
    expect(valid.prefs.popWindowOnApproval).toBe(true);
    expect(valid.prefs.soundMode).toBe("high-risk-only");
    expect(valid.prefs.minimizeToTrayOnClose).toBe(true);
  });

  it("persists and reloads preferences cleanly from disk and survives corrupt JSON", () => {
    const dir = mkdtempSync(join(tmpdir(), "mv-prefs-"));
    try {
      const file = preferencesFilePath(dir);
      const initial = loadDesktopPreferences(file);
      expect(initial.popWindowOnApproval).toBe(false);

      const updated = applyPreferencePatch(initial, {
        minimizeToTrayOnClose: false,
        soundMode: "off",
        firstCloseNoticeShown: true,
      });
      expect(updated.ok).toBe(true);
      persistDesktopPreferences(file, updated.prefs);

      const reloaded = loadDesktopPreferences(file);
      expect(reloaded.minimizeToTrayOnClose).toBe(false);
      expect(reloaded.soundMode).toBe("off");
      expect(reloaded.firstCloseNoticeShown).toBe(true);

      const corrupt = loadDesktopPreferences(file, () => Buffer.from("{bad json", "utf8"), () => true);
      expect(corrupt.popWindowOnApproval).toBe(false);
      expect(projectDesktopPreferences({ soundMode: "invalid", extra: "secret" }).soundMode).toBe("all");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
