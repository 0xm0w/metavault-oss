// Pure window-hardening contract for the Electron main process. Kept free
// of Electron imports so the security flags are unit-testable headlessly.
// Electron preload scripts must be CommonJS (sandboxed preloads cannot be
// ESM), so the built preload is emitted as preload.cjs - never preload.js
// from this package (which is type module).
export const PRELOAD_FILE_NAME = "preload.cjs";
export function buildWindowOptions(preloadPath) {
    return {
        width: 980,
        height: 720,
        minWidth: 720,
        minHeight: 520,
        title: "OpenVault",
        backgroundColor: "#FFFFFF",
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
export function shouldHideOnClose(isQuitting) {
    return !isQuitting;
}
