import { describe, expect, it, vi } from "vitest";

vi.mock("electron", () => ({
  BrowserWindow: vi.fn(),
  nativeImage: {
    createFromBitmap: vi.fn((buf: Buffer) => ({ bitmap: buf })),
  },
}));

import { FLYOUT_HEIGHT, FLYOUT_MARGIN, FLYOUT_WIDTH, positionFlyoutNearTray } from "../src/flyout-position.js";
import { FLYOUT_FOCUS_GUARD_MS, isFlyoutApprovalArmed } from "../src/renderer/flyout.js";
import { FLYOUT_BLUR_DEBOUNCE_MS, shouldSuppressToggleAfterBlur } from "../src/tray-flyout.js";
import { badgePixelAlpha, composeTrayIcon, dotSpecFor, trayTooltip } from "../src/tray-icons.js";

describe("positionFlyoutNearTray", () => {
  const workArea = { x: 0, y: 0, width: 1920, height: 1040 };

  it("places flyout above a bottom Windows taskbar and centers over tray icon", () => {
    const pos = positionFlyoutNearTray({ x: 1700, y: 1050, width: 24, height: 24 }, workArea);
    expect(pos.x).toBe(Math.min(1700 + 12 - FLYOUT_WIDTH / 2, 1920 - FLYOUT_WIDTH - FLYOUT_MARGIN));
    expect(pos.y).toBe(1040 - FLYOUT_HEIGHT - FLYOUT_MARGIN);
  });

  it("places flyout below a top menu bar / top taskbar", () => {
    const topWorkArea = { x: 0, y: 32, width: 1920, height: 1048 };
    const pos = positionFlyoutNearTray({ x: 1600, y: 4, width: 24, height: 24 }, topWorkArea);
    expect(pos.y).toBe(32 + FLYOUT_MARGIN);
  });

  it("clamps flyout inside left and right display edges (including negative multi-monitor coords)", () => {
    const leftClamp = positionFlyoutNearTray({ x: 2, y: 1050, width: 24, height: 24 }, workArea);
    expect(leftClamp.x).toBe(FLYOUT_MARGIN);

    const rightClamp = positionFlyoutNearTray({ x: 1910, y: 1050, width: 24, height: 24 }, workArea);
    expect(rightClamp.x).toBe(1920 - FLYOUT_WIDTH - FLYOUT_MARGIN);

    const leftMonitor = { x: -1920, y: 0, width: 1920, height: 1040 };
    const secondaryPos = positionFlyoutNearTray({ x: -100, y: 1055, width: 24, height: 24 }, leftMonitor);
    expect(secondaryPos.x).toBeLessThanOrEqual(- FLYOUT_WIDTH - FLYOUT_MARGIN);
    expect(secondaryPos.x).toBeGreaterThanOrEqual(-1920 + FLYOUT_MARGIN);
  });
});

describe("tray flyout debounce, focus guard, and dynamic icon states", () => {
  it("suppresses immediate re-open on tray click right after blur within 150ms", () => {
    expect(FLYOUT_BLUR_DEBOUNCE_MS).toBe(150);
    expect(shouldSuppressToggleAfterBlur(1_100, 1_000)).toBe(true);
    expect(shouldSuppressToggleAfterBlur(1_150, 1_000)).toBe(false);
  });

  it("enforces 500ms focus guard on flyout approval buttons", () => {
    expect(FLYOUT_FOCUS_GUARD_MS).toBe(500);
    expect(isFlyoutApprovalArmed(1_499, 1_500)).toBe(false);
    expect(isFlyoutApprovalArmed(1_500, 1_500)).toBe(true);
  });

  it("computes distinct tray icon badge overlays and tooltips across all 4 states", () => {
    expect(dotSpecFor("unlocked-idle", 16)).toBeNull();
    expect(dotSpecFor("pending", 16)?.rgb).toEqual([255, 176, 32]);
    expect(dotSpecFor("ui-locked", 16)?.rgb).toEqual([100, 116, 139]);
    expect(dotSpecFor("daemon-locked", 16)?.rgb).toEqual([220, 38, 38]);

    const spec = dotSpecFor("pending", 16);
    if (spec === null) {
      throw new Error("expected dotSpec for pending state");
    }
    const mask = badgePixelAlpha(16, spec);
    expect(mask[12 * 16 + 12]).toBe(255);
    expect(mask[0]).toBe(0);

    const fakeBase = {
      resize: () => ({
        isEmpty: () => false,
        toBitmap: () => Buffer.alloc(16 * 16 * 4, 0),
      }),
    } as unknown as Parameters<typeof composeTrayIcon>[0];
    expect(composeTrayIcon(fakeBase, "unlocked-idle")).toBe(fakeBase);
    expect(composeTrayIcon(fakeBase, "pending")).not.toBe(fakeBase);

    expect(trayTooltip("unlocked-idle", 0)).toBe("MetaVault OSS — Unlocked");
    expect(trayTooltip("pending", 1)).toBe("MetaVault OSS — 1 approval waiting");
    expect(trayTooltip("pending", 3)).toBe("MetaVault OSS — 3 approvals waiting");
    expect(trayTooltip("ui-locked", 2)).toBe("MetaVault OSS — UI Locked");
    expect(trayTooltip("daemon-locked", 0)).toBe("MetaVault OSS — Vault Locked");
  });
});
