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
  readonly icon?: string;
  readonly webPreferences: {
    readonly preload: string;
    readonly nodeIntegration: false;
    readonly contextIsolation: true;
    readonly sandbox: true;
  };
}

export function buildWindowOptions(preloadPath: string): VaultWindowOptions {
  return {
    width: 980,
    height: 720,
    minWidth: 720,
    minHeight: 520,
    title: "MetaVault OSS",
    backgroundColor: "#0a0a0a",
    icon: join(preloadPath, "..", "renderer", "icon.ico"),
    webPreferences: {
      preload: preloadPath,
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
  };
}

// Closing the window minimises to the tray (wallet pattern); only an
// explicit quit from the tray menu actually closes it.
export function shouldHideOnClose(isQuitting: boolean): boolean {
  return !isQuitting;
}
