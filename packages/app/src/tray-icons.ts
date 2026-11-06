// Tray icon states. The status badge is composited as a raw RGBA overlay
// onto a resized copy of the base icon — no native canvas dependency — and
// the same composed image drives the Windows taskbar overlay icon.

import { nativeImage, type NativeImage } from "electron";

export type TrayState = "unlocked-idle" | "pending" | "ui-locked" | "daemon-locked";

export interface DotSpec {
  readonly cx: number;
  readonly cy: number;
  readonly radius: number;
  readonly rgb: readonly [number, number, number];
}

const AMBER: readonly [number, number, number] = [255, 176, 32];
const SLATE: readonly [number, number, number] = [100, 116, 139];
const RED: readonly [number, number, number] = [220, 38, 38];

// One dot spec per state at each supported raster size. A null dot means
// the clean brand icon (unlocked idle).
export function dotSpecFor(state: TrayState, size: 16 | 32): DotSpec | null {
  if (state === "unlocked-idle") {
    return null;
  }
  const rgb =
    state === "pending" ? AMBER : state === "ui-locked" ? SLATE : RED;
  const cx = size === 16 ? 12 : 24;
  const cy = cx;
  const radius = size === 16 ? 3.5 : 7;
  return { cx, cy, radius, rgb };
}

// Pure coverage mask: one byte per pixel, 255 inside the filled dot disc
// and 0 outside. Unit-tested without Electron.
export function badgePixelAlpha(size: number, spec: DotSpec): Uint8Array {
  const alpha = new Uint8Array(size * size);
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const dx = x - spec.cx;
      const dy = y - spec.cy;
      const inside = dx * dx + dy * dy <= spec.radius * spec.radius;
      alpha[y * size + x] = inside ? 255 : 0;
    }
  }
  return alpha;
}

// Merges the dot into a BGRA bitmap from base.getBitmap().
function mergeDotIntoBitmap(bitmap: Buffer, size: number, spec: DotSpec): Buffer {
  const alpha = badgePixelAlpha(size, spec);
  const merged = Buffer.from(bitmap);
  const [r, g, b] = spec.rgb;
  for (let i = 0; i < size * size; i += 1) {
    if (alpha[i] === 255) {
      const offset = i * 4;
      merged[offset] = b;
      merged[offset + 1] = g;
      merged[offset + 2] = r;
      merged[offset + 3] = 255;
    }
  }
  return merged;
}

export function composeTrayIcon(base: NativeImage, state: TrayState): NativeImage {
  const spec = dotSpecFor(state, 16);
  if (spec === null) {
    return base;
  }
  try {
    const sized = base.resize({ width: 16, height: 16 });
    if (sized.isEmpty()) {
      return base;
    }
    const bitmap = sized.toBitmap();
    const merged = mergeDotIntoBitmap(bitmap, 16, spec);
    return nativeImage.createFromBitmap(merged, { width: 16, height: 16 });
  } catch {
    return base;
  }
}

// Tooltip copy matches the tray right-click status label.
export function trayTooltip(state: TrayState, pendingCount: number): string {
  if (state === "pending") {
    return pendingCount === 1
      ? "MetaVault OSS — 1 approval waiting"
      : `MetaVault OSS — ${String(pendingCount)} approvals waiting`;
  }
  if (state === "ui-locked") {
    return "MetaVault OSS — UI Locked";
  }
  if (state === "daemon-locked") {
    return "MetaVault OSS — Vault Locked";
  }
  return "MetaVault OSS — Unlocked";
}
