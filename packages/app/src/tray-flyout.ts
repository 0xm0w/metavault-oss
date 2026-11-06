// Left-click tray flyout controller: a single reusable 360x480 frameless
// popover anchored near the tray icon, with the same hardened webPreferences
// as the main window. The positioning math lives in flyout-position.ts.

import { BrowserWindow, type WebContents, type WebPreferences } from "electron";
import { FLYOUT_HEIGHT, FLYOUT_WIDTH, positionFlyoutNearTray, type Rect } from "./flyout-position.js";

export const FLYOUT_BLUR_DEBOUNCE_MS = 150;

interface BoundsLike {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}

let flyout: BrowserWindow | null = null;
let hiddenForBlurAt = 0;

// Pure bookkeeping for tests: the tray click that follows a blur-hide
// within the debounce window is the same click closing the flyout, not a
// request to reopen one.
export function shouldSuppressToggleAfterBlur(nowMs: number, lastBlurAtMs: number, gapMs = FLYOUT_BLUR_DEBOUNCE_MS): boolean {
  return nowMs - lastBlurAtMs < gapMs;
}

export function flyoutVisible(): boolean {
  return flyout !== null && !flyout.isDestroyed() && flyout.isVisible();
}

export function ensureFlyout(
  preloadPath: string,
  rendererDir: string,
  onReady: () => void,
): BrowserWindow {
  if (flyout !== null && !flyout.isDestroyed()) {
    return flyout;
  }
  const webPreferences: WebPreferences = {
    preload: preloadPath,
    nodeIntegration: false,
    contextIsolation: true,
    sandbox: true,
  };
  const window = new BrowserWindow({
    width: FLYOUT_WIDTH,
    height: FLYOUT_HEIGHT,
    show: false,
    frame: false,
    resizable: false,
    movable: false,
    minimizable: false,
    maximizable: false,
    fullscreenable: false,
    skipTaskbar: true,
    alwaysOnTop: true,
    useContentSize: true,
    webPreferences,
  });
  window.webContents.on("will-navigate", (event) => {
    event.preventDefault();
  });
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.on("blur", () => {
    hiddenForBlurAt = Date.now();
    window.hide();
  });
  window.on("closed", () => {
    if (flyout === window) flyout = null;
  });
  window.webContents.on("did-finish-load", () => {
    onReady();
  });
  void window.loadFile(`${rendererDir}/flyout.html`);
  flyout = window;
  return window;
}

export function positionFlyoutForTray(window: BrowserWindow, trayBounds: BoundsLike, workArea: Rect): void {
  const pos = positionFlyoutNearTray(trayBounds, workArea);
  window.setPosition(pos["x"], pos["y"], false);
}

// Left click on the tray icon toggles the popover.
export function toggleFlyout(trayBounds: BoundsLike, workArea: Rect): void {
  if (flyout === null) return;
  if (flyout.isVisible()) {
    flyout.hide();
    return;
  }
  if (shouldSuppressToggleAfterBlur(Date.now(), hiddenForBlurAt)) return;
  positionFlyoutForTray(flyout, trayBounds, workArea);
  flyout.show();
  flyout.focus();
}

export function hideFlyout(): void {
  if (flyout !== null && !flyout.isDestroyed() && flyout.isVisible()) {
    flyout.hide();
  }
}

export function flyoutWebContents(): WebContents | null {
  if (flyout !== null && !flyout.isDestroyed()) {
    return flyout.webContents;
  }
  return null;
}

export function isFlyoutSender(event: { readonly sender?: unknown; readonly senderFrame: unknown }): boolean {
  const contents = flyout !== null && !flyout.isDestroyed() ? flyout.webContents : null;
  if (contents === null) return false;
  if (event.sender === contents) return true;
  return event.senderFrame === contents.mainFrame;
}

export function destroyFlyoutIfOwned(): void {
  if (flyout !== null && !flyout.isDestroyed()) {
    flyout.destroy();
  }
  flyout = null;
}
