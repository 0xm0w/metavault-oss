// Pure flyout positioning math (unit-testable, no Electron).

export const FLYOUT_WIDTH = 360;
export const FLYOUT_HEIGHT = 480;
export const FLYOUT_MARGIN = 8;

export interface Rect {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}

export interface FlyoutPosition {
  readonly x: number;
  readonly y: number;
}

// Clamps the flyout horizontally opposite the tray icon and places it above
// a bottom taskbar (Windows wallet pattern) or below a top bar.
//  - bottom taskbar: y = workArea.bottom - height - margin
//  - top bar:        y = workArea.top + margin
export function positionFlyoutNearTray(trayBounds: Rect, workArea: Rect): FlyoutPosition {
  const clamp = (value: number, min: number, max: number): number =>
    Math.max(min, Math.min(max, value));
  const x = Math.round(
    clamp(
      trayBounds.x + trayBounds.width / 2 - FLYOUT_WIDTH / 2,
      workArea.x + FLYOUT_MARGIN,
      workArea.x + workArea.width - FLYOUT_WIDTH - FLYOUT_MARGIN,
    ),
  );
  const taskbarBelow = trayBounds.y > workArea.y + workArea.height / 2;
  const y = taskbarBelow
    ? workArea.y + workArea.height - FLYOUT_HEIGHT - FLYOUT_MARGIN
    : workArea.y + FLYOUT_MARGIN;
  return { x, y };
}
