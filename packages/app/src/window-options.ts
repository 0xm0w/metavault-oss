import { join } from "node:path";

// Pure window-hardening contract for the Electron main process. Kept free
// of Electron imports so the security flags are unit-testable headlessly.

// Electron preload scripts must be CommonJS (sandboxed preloads cannot be
// ESM), so the built preload is emitted as preload.cjs - never preload.js
// from this package (which is type module).
export const PRELOAD_FILE_NAME = "preload.cjs";

export interface VaultWindowOptions {
  readonly width: number;
  readonly height: number;
  readonly minWidth: number;
  readonly minHeight: number;
  readonly title: string;
  readonly backgroundColor: string;
  readonly autoHideMenuBar: true;
  readonly titleBarStyle: "hidden";
  readonly titleBarOverlay: {
    readonly color: string;
    readonly symbolColor: string;
    readonly height: number;
  };
  readonly icon?: string;
  readonly show: false;
  readonly webPreferences: {
    readonly preload: string;
    readonly nodeIntegration: false;
    readonly contextIsolation: true;
    readonly sandbox: true;
  };
}

export function buildWindowOptions(preloadPath: string, argv: readonly string[] = []): VaultWindowOptions {
  const options: VaultWindowOptions = {
    width: 980,
    height: 720,
    minWidth: 880,
    minHeight: 520,
    title: "MetaVault OSS",
    backgroundColor: "#ffffff",
    autoHideMenuBar: true,
    titleBarStyle: "hidden",
    titleBarOverlay: {
      color: "#8629ff",
      symbolColor: "#ffffff",
      height: 40,
    },
    icon: join(preloadPath, "..", "renderer", "icon.ico"),
    show: false,
    webPreferences: {
      preload: preloadPath,
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
  };
  // --minimized / --hidden still construct with show: false. The caller
  // decides whether ready-to-show may reveal the window. argv is read so
  // the flag stays part of the contract.
  if (argv.includes("--minimized") || argv.includes("--hidden")) {
    return options;
  }
  return options;
}

export const APPROVAL_FOCUS_GUARD_MS = 500;

// True only after the guard window. An in-flight Enter or Space must not
// activate Approve.
export function approvalActivationAllowed(shownAtMs: number, nowMs: number): boolean {
  return nowMs >= shownAtMs + APPROVAL_FOCUS_GUARD_MS;
}

// Closing the window minimises to the tray when the preference says so.
// An explicit quit always closes.
export function shouldHideOnClose(isQuitting: boolean, minimizeToTrayOnClose = true): boolean {
  if (isQuitting) return false;
  return minimizeToTrayOnClose;
}
