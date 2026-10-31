import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { app, BrowserWindow, ipcMain, Menu, nativeImage, Tray } from "electron";
import { DAEMON_CALL_CHANNEL, callDaemon } from "./daemon-client.js";
import { DEEPLINK_CHANNEL, findOpenVaultUrl, parseOpenVaultUrl, type DeeplinkAddParams } from "./deeplink.js";
import { PRELOAD_FILE_NAME, buildWindowOptions, shouldHideOnClose } from "./window-options.js";

// OpenVault desktop shell: a window over vaultd, in the wallet pattern.
// This main process owns the daemon HTTP client and the daemon token (see
// daemon-client.ts); the token stays in main and never crosses IPC into
// the preload or renderer. It talks to nothing but the local daemon. Closing the window minimises to the
// tray so approval prompts can still surface; quitting from the tray stops
// only this UI — vaultd keeps running and queues approvals until the UI or
// CLI next connects.

const here = dirname(fileURLToPath(import.meta.url));
const preloadPath = join(here, PRELOAD_FILE_NAME);
const rendererPath = join(here, "renderer", "index.html");

// Register as the openvault:// handler. In dev (running via the Electron
// binary) the execPath/argv form is required so Windows launches this app.
if (process.defaultApp) {
  const script = process.argv[1];
  if (script !== undefined) {
    app.setAsDefaultProtocolClient("openvault", process.execPath, [script]);
  } else {
    app.setAsDefaultProtocolClient("openvault");
  }
} else {
  app.setAsDefaultProtocolClient("openvault");
}

let mainWindow: BrowserWindow | null = null;
let pendingDeeplink: DeeplinkAddParams | null = null;
let rendererReady = false;

function routeDeeplink(params: DeeplinkAddParams): void {
  showWindow();
  if (mainWindow !== null && rendererReady) {
    mainWindow.webContents.send(DEEPLINK_CHANNEL, params);
  } else {
    pendingDeeplink = params;
  }
}

function handleDeeplinkUrl(raw: unknown): void {
  const parsed = parseOpenVaultUrl(raw);
  if (parsed !== null) {
    routeDeeplink(parsed);
  }
}
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
  rendererReady = false;
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
  window.webContents.on("did-finish-load", () => {
    rendererReady = true;
    if (pendingDeeplink !== null) {
      const queued = pendingDeeplink;
      pendingDeeplink = null;
      window.webContents.send(DEEPLINK_CHANNEL, queued);
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

const coldStartDeeplink = findOpenVaultUrl(process.argv.slice(1));
if (coldStartDeeplink !== null) {
  pendingDeeplink = coldStartDeeplink;
}

const hasLock = app.requestSingleInstanceLock();
if (!hasLock) {
  app.quit();
} else {
  app.on("second-instance", (_event, argv) => {
    const linked = findOpenVaultUrl(argv);
    if (linked !== null) {
      routeDeeplink(linked);
    } else {
      showWindow();
    }
  });
  // macOS delivers protocol URLs via open-url, not argv.
  app.on("open-url", (event, url) => {
    event.preventDefault();
    handleDeeplinkUrl(url);
  });
  void app.whenReady().then(() => {
    ipcMain.handle(DAEMON_CALL_CHANNEL, async (_event, request: unknown) => callDaemon(request));
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
