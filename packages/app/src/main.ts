import { appendFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { app, BrowserWindow, ipcMain, Menu, nativeImage, Tray } from "electron";
import { DAEMON_CALL_CHANNEL, DAEMON_BASE_URL, callDaemon } from "./daemon-client.js";
import { PRESENCE_PROOF_CHANNEL, defaultGuardDeps, guardedDaemonCall, issuePresenceProof } from "./remote-approval-ipc.js";
import { PresenceProofIssuer } from "./remote-approval-guard.js";
import { bundledDaemonPaths, ensureBundledDaemon } from "./daemon-launcher.js";
import { autostartGatewayWhenRemoteEnabled } from "./gateway-autostart.js";
import { bundledGatewayPaths, ensureBundledGateway, gatewayListening, GATEWAY_HOST, GATEWAY_PORT, GATEWAY_DEVICE_PORT, type GatewayLaunchResult } from "./gateway-launcher.js";
import { SshTunnelManager, resolveSshBinaries, sshTunnelPaths } from "./ssh-tunnel.js";
import { SSH_TUNNEL_CHANNEL, SSH_TUNNEL_STATUS_CHANNEL, handleSshTunnelRequest } from "./ssh-tunnel-ipc.js";
import type { ChildProcess } from "node:child_process";
import { DEEPLINK_CHANNEL, findVaultDeeplink, parseVaultDeeplink, type DeeplinkAddParams } from "./deeplink.js";
import { PRELOAD_FILE_NAME, buildWindowOptions, shouldHideOnClose } from "./window-options.js";
import { initAutoUpdater } from "./updater.js";
import { runtimePaths } from "./runtime-paths.js";
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
let bundledGateway: ChildProcess | null = null;
let sshTunnel: SshTunnelManager | null = null;

const adoptGatewayChild = (launched: GatewayLaunchResult): void => {
  if (launched.child !== undefined) {
    bundledGateway = launched.child;
    launched.child.once("exit", () => {
      if (bundledGateway === launched.child) bundledGateway = null;
    });
  }
};

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
  // Windows can refuse a plain focus() from a background launch; a brief
  // always-on-top pass brings the window to the front without keeping it there.
  mainWindow.setAlwaysOnTop(true);
  mainWindow.moveTop();
  mainWindow.focus();
  mainWindow.setAlwaysOnTop(false);
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
      // Remote access (mTLS pairing + devices) needs the bundled gateway up
      // whenever it is enabled, independent of the SSH tunnel. Nothing
      // launched it before; start it once the daemon answers. The gateway
      // refuses to run unconfigured, so this is a no-op until remote is on.
      // Diagnostics land in gateway.log (collected by the installer smoke).
      {
        const gatewayPaths = bundledGatewayPaths(process.resourcesPath, dataDir);
        void autostartGatewayWhenRemoteEnabled({
          callDaemonFn: (input) => callDaemon(input),
          ensureGatewayFn: async () => {
            const launched = await ensureBundledGateway({
              execPath: process.execPath,
              paths: gatewayPaths,
              vaultDir: dataDir,
              daemonBaseUrl: DAEMON_BASE_URL,
            });
            adoptGatewayChild(launched);
            return launched.status;
          },
          waitFn: async (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
          logFn: (line) => {
            try {
              appendFileSync(gatewayPaths.logPath, `[main ${new Date().toISOString()}] ${line}\n`);
            } catch {
              // Logging must never break startup.
            }
          },
        }).catch(() => undefined);
      }
    }
    const presenceIssuer = new PresenceProofIssuer();
    const guardDeps = defaultGuardDeps(presenceIssuer);
    ipcMain.handle(DAEMON_CALL_CHANNEL, async (_event, request: unknown) => guardedDaemonCall(request, guardDeps));
    ipcMain.handle(PRESENCE_PROOF_CHANNEL, async (_event, input: unknown) => issuePresenceProof(input, guardDeps));
    ipcMain.handle("metavault:runtime-paths", () => runtimePaths({ packaged: app.isPackaged, execPath: process.execPath, resourcesPath: process.resourcesPath, repoRoot: join(here, "..", "..", ".."), dbPath: process.env["METAVAULT_DB_PATH"] ?? join(process.cwd(), "metavault.db") }));
    registerWindowsHelloIpc();
    // App-managed SSH tunnel for Remote Connections. Off unless the user
    // completed setup and left it connected; a restart then reconnects.
    // The status channel pushes every state change to the renderer.
    const sshBinaries = resolveSshBinaries();
    if (sshBinaries !== null) {
      const gatewayPaths = bundledGatewayPaths(process.resourcesPath, dataDir);
      sshTunnel = new SshTunnelManager({
        paths: sshTunnelPaths(dataDir),
        binaries: sshBinaries,
        gatewayReady: async () => {
          // The tunnel forwards the gateway's two loopback listeners, so
          // "connected" requires them to be up. In the packaged app the
          // bundled gateway is started on demand; it refuses to run
          // unconfigured, so a vault with remote access disabled simply
          // never answers here.
          if (app.isPackaged) {
            try {
              adoptGatewayChild(await ensureBundledGateway({
                execPath: process.execPath,
                paths: gatewayPaths,
                vaultDir: dataDir,
                daemonBaseUrl: DAEMON_BASE_URL,
              }));
            } catch {
              // Fall through to the listener check below.
            }
          }
          return (await gatewayListening(GATEWAY_HOST, GATEWAY_PORT)) && (await gatewayListening(GATEWAY_HOST, GATEWAY_DEVICE_PORT));
        },
        onStatus: (status) => {
          mainWindow?.webContents.send(SSH_TUNNEL_STATUS_CHANNEL, status);
        },
      });
    }
    const tunnelManager = sshTunnel;
    ipcMain.handle(SSH_TUNNEL_CHANNEL, async (_event, request: unknown) => {
      if (tunnelManager === null) {
        return { kind: "error", error: "An OpenSSH client was not found on this PC. Install the Windows OpenSSH Client feature, then try again." };
      }
      return await handleSshTunnelRequest(tunnelManager, request);
    });
    if (tunnelManager !== null && tunnelManager.wantsConnection()) {
      void tunnelManager.connect();
    }
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
  if (sshTunnel !== null) {
    void sshTunnel.shutdown();
    sshTunnel = null;
  }
  if (bundledGateway !== null) {
    bundledGateway.kill();
    bundledGateway = null;
  }
  if (bundledDaemon !== null) {
    bundledDaemon.kill();
    bundledDaemon = null;
  }
});

// Tray-resident: the app deliberately does not quit when its window closes.
app.on("window-all-closed", () => {
  // No-op by design — see the close handler in createWindow.
});
