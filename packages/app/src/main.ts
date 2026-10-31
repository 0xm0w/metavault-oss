import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { app, BrowserWindow, Menu, nativeImage, Tray } from "electron";
import { buildWindowOptions, shouldHideOnClose } from "./window-options.js";

// OpenVault desktop shell: a window over vaultd, in the wallet pattern.
// This process holds no secrets and never talks to anything but the local
// daemon (via the preload bridge). Closing the window minimises to the
// tray so approval prompts can still surface; quitting from the tray stops
// only this UI — vaultd keeps running and queues approvals until the UI or
// CLI next connects.

const here = dirname(fileURLToPath(import.meta.url));
const preloadPath = join(here, "preload.js");
const rendererPath = join(here, "renderer", "index.html");

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let isQuitting = false;

function showWindow(): void {
  if (mainWindow === null) {
    createWindow();
    return;
  }
  if (mainWindow.isMinimized()) {
    mainWindow.restore();
  }
  mainWindow.show();
  mainWindow.focus();
}

function createWindow(): void {
  const window = new BrowserWindow(buildWindowOptions(preloadPath));
  mainWindow = window;
  window.once("ready-to-show", () => {
    window.show();
  });
  window.on("close", (event) => {
    if (shouldHideOnClose(isQuitting)) {
      event.preventDefault();
      window.hide();
    }
  });
  window.on("closed", () => {
    if (mainWindow === window) {
      mainWindow = null;
    }
  });
  void window.loadFile(rendererPath);
}

function createTray(): void {
  // 1x1 navy pixel; a branded icon ships with the installer packaging.
  const icon = nativeImage.createFromDataURL(
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
  );
  tray = new Tray(icon);
  tray.setToolTip("OpenVault");
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: "Open OpenVault", click: () => { showWindow(); } },
      { type: "separator" },
      {
        label: "Quit OpenVault",
        click: () => {
          isQuitting = true;
          app.quit();
        },
      },
    ]),
  );
  tray.on("click", () => {
    showWindow();
  });
}

const hasLock = app.requestSingleInstanceLock();
if (!hasLock) {
  app.quit();
} else {
  app.on("second-instance", () => {
    showWindow();
  });
  void app.whenReady().then(() => {
    createWindow();
    createTray();
    app.on("activate", () => {
      showWindow();
    });
  });
}

app.on("before-quit", () => {
  isQuitting = true;
});

// Tray-resident: the app deliberately does not quit when its window closes.
app.on("window-all-closed", () => {
  // No-op by design — see the close handler in createWindow.
});
