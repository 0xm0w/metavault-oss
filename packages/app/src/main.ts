import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { app, BrowserWindow, ipcMain, Menu, nativeImage, Tray } from "electron";
import { DAEMON_CALL_CHANNEL, DAEMON_BASE_URL, callDaemon } from "./daemon-client.js";
import { bundledDaemonPaths, ensureBundledDaemon } from "./daemon-launcher.js";
import type { ChildProcess } from "node:child_process";
import { DEEPLINK_CHANNEL, findVaultDeeplink, parseVaultDeeplink, type DeeplinkAddParams } from "./deeplink.js";
import { PRELOAD_FILE_NAME, buildWindowOptions, shouldHideOnClose } from "./window-options.js";
import { initAutoUpdater } from "./updater.js";
import { registerWindowsHelloIpc } from "./windows-hello.js";

// MetaVault OSS desktop shell: a window over vaultd, in the wallet pattern.
// This main process owns the daemon HTTP client and the daemon token (see
// daemon-client.ts); the token stays in main and never crosses IPC into
// the preload or renderer. It talks to nothing but the local daemon. Closing the window minimises to the
// tray so approval prompts can still surface. In the installed app, if no
// daemon answers on the daemon port, main starts the bundled one
// (resources/vaultd) and stops it again when you quit from the tray. A
// daemon you started yourself (vaultd / metavault) is left alone.

const here = dirname(fileURLToPath(import.meta.url));
const preloadPath = join(here, PRELOAD_FILE_NAME);
const rendererPath = join(here, "renderer", "index.html");

// Register as the metavault:// handler. In dev (running via the Electron
// binary) the execPath/argv form is required so Windows launches this app.
if (process.defaultApp) {
  const script = process.argv[1];
  if (script !== undefined) {
    app.setAsDefaultProtocolClient("metavault", process.execPath, [script]);
  } else {
    app.setAsDefaultProtocolClient("metavault");
  app.setAsDefaultProtocolClient("metavault");
  }
} else {
  app.setAsDefaultProtocolClient("metavault");
}

// Vault data lives in %APPDATA%\MetaVault OSS whatever the package name is,
// so the uninstaller's "delete vault data" step knows where to look.
const dataDir = join(app.getPath("appData"), "MetaVault OSS");
app.setPath("userData", dataDir);
const daemonPaths = bundledDaemonPaths(process.resourcesPath, dataDir);
if (app.isPackaged) {
  // daemon-client reads this lazily to find the daemon token file.
  process.env["METAVAULT_DB_PATH"] ??= daemonPaths.dbPath;
}
let bundledDaemon: ChildProcess | null = null;

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
  const parsed = parseVaultDeeplink(raw);
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

function bringWindowToFront(): void {
  showWindow();
  if (mainWindow !== null) {
    mainWindow.setAlwaysOnTop(true);
    mainWindow.focus();
    mainWindow.setAlwaysOnTop(false);
  }
}

function createWindow(): void {
  rendererReady = false;
  const isMinimizedStart = process.argv.includes("--minimized") || process.argv.includes("--hidden");
  const window = new BrowserWindow(buildWindowOptions(preloadPath));
  window.setMenuBarVisibility(false);
  window.removeMenu();
  mainWindow = window;
  window.once("ready-to-show", () => {
    if (!isMinimizedStart) {
      window.show();
      window.focus();
    }
  });
  if (!isMinimizedStart) {
    setTimeout(() => {
      if (mainWindow === window && !window.isVisible()) {
        window.show();
        window.focus();
      }
    }, 1000);
  }
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
  const iconPath = join(here, "renderer", process.platform === "win32" ? "icon.ico" : "tray.png");
  const icon = existsSync(iconPath)
    ? nativeImage.createFromPath(iconPath)
    : nativeImage.createFromDataURL(
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
      );
  try {
    tray = new Tray(icon);
  tray.setToolTip("MetaVault OSS");
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: "Open MetaVault OSS", click: () => { showWindow(); } },
      { type: "separator" },
      {
        label: "Quit MetaVault OSS",
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
  } catch (err) {
    console.warn("Failed to create tray icon:", err);
  }
}

const coldStartDeeplink = findVaultDeeplink(process.argv.slice(1));
if (coldStartDeeplink !== null) {
  pendingDeeplink = coldStartDeeplink;
}

const hasLock = app.requestSingleInstanceLock();
if (!hasLock) {
  app.quit();
} else {
  app.on("second-instance", (_event, argv) => {
    const linked = findVaultDeeplink(argv);
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
    Menu.setApplicationMenu(null);
    if (app.isPackaged) {
      void ensureBundledDaemon({ execPath: process.execPath, paths: daemonPaths, baseUrl: DAEMON_BASE_URL })
        .then((result) => {
          if (result.child !== undefined) {
            bundledDaemon = result.child;
            result.child.once("exit", () => {
              if (bundledDaemon === result.child) bundledDaemon = null;
            });
          }
        })
        .catch((err: unknown) => {
          console.warn("Could not start the bundled vault daemon:", err);
        });
    }
    ipcMain.handle(DAEMON_CALL_CHANNEL, async (_event, request: unknown) => callDaemon(request));
    registerWindowsHelloIpc();
    ipcMain.on("metavault:bring-to-front", () => {
      bringWindowToFront();
    });
    createWindow();
    createTray();
    void initAutoUpdater(() => mainWindow);
    app.on("activate", () => {
      showWindow();
    });
  });
}

app.on("before-quit", () => {
  isQuitting = true;
});

app.on("will-quit", () => {
  if (bundledDaemon !== null) {
    bundledDaemon.kill();
    bundledDaemon = null;
  }
});

// Tray-resident: the app deliberately does not quit when its window closes.
app.on("window-all-closed", () => {
  // No-op by design — see the close handler in createWindow.
});
