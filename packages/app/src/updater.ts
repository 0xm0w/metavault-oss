import { existsSync } from "node:fs";
import { join } from "node:path";
import type { BrowserWindow } from "electron";
import { app, ipcMain } from "electron";
import pkg from "electron-updater";

export interface UpdaterStatusPayload {
  readonly status:
    | "idle"
    | "checking"
    | "available"
    | "not-available"
    | "downloading"
    | "downloaded"
    | "error";
  readonly version?: string;
  readonly percent?: number;
  readonly message?: string;
}

export const UPDATER_STATUS_CHANNEL = "metavault:updater-status";
export const CHECK_UPDATES_CHANNEL = "metavault:check-for-updates";
export const QUIT_AND_INSTALL_CHANNEL = "metavault:quit-and-install";

let currentStatus: UpdaterStatusPayload = { status: "idle" };

export function getCurrentUpdaterStatus(): UpdaterStatusPayload {
  return currentStatus;
}

export function initAutoUpdater(getWindow: () => BrowserWindow | null): void {
  let autoUpdater: typeof pkg.autoUpdater;
  try {
    autoUpdater = pkg.autoUpdater;
  } catch {
    return;
  }

  function broadcast(payload: UpdaterStatusPayload): void {
    currentStatus = payload;
    const win = getWindow();
    if (win !== null && !win.isDestroyed()) {
      win.webContents.send(UPDATER_STATUS_CHANNEL, payload);
    }
  }

  // Configure autoUpdater
  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true;

  autoUpdater.on("checking-for-update", () => {
    broadcast({ status: "checking" });
  });

  autoUpdater.on("update-available", (info) => {
    broadcast({ status: "available", version: info.version });
  });

  autoUpdater.on("update-not-available", (info) => {
    broadcast({ status: "not-available", version: info.version });
  });

  autoUpdater.on("download-progress", (progress) => {
    broadcast({
      status: "downloading",
      percent: Math.round(progress.percent),
    });
  });

  autoUpdater.on("update-downloaded", (info) => {
    broadcast({
      status: "downloaded",
      version: info.version,
      message: "Update downloaded. Restart to apply.",
    });
  });

  autoUpdater.on("error", (err) => {
    broadcast({
      status: "error",
      message: err.message,
    });
  });

  const updaterInstance = autoUpdater;

  ipcMain.handle(CHECK_UPDATES_CHANNEL, async () => {
    try {
      broadcast({ status: "checking" });
      const result = await updaterInstance.checkForUpdates();
      return { ok: true, updateInfo: result?.updateInfo };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      broadcast({ status: "error", message: msg });
      return { ok: false, error: msg };
    }
  });

  ipcMain.handle(QUIT_AND_INSTALL_CHANNEL, () => {
    try {
      updaterInstance.quitAndInstall();
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  // Background check on launch after brief delay (if in production with update config)
  setTimeout(() => {
    try {
      const resourcesDir = typeof process.resourcesPath === "string" ? process.resourcesPath : "";
      const updateYml = join(resourcesDir, "app-update.yml");
      if (existsSync(updateYml) && shouldAutoCheckForUpdates(app.getVersion())) {
        void updaterInstance.checkForUpdates().catch(() => {
          // Ignored on network failure
        });
      }
    } catch {
      // Ignored
    }
  }, 5000);
}

// Prerelease builds (e.g. 0.1.0-alpha) do not check on launch: a published
// stable release can sort above them, and an alpha must never replace
// itself without the user asking. "Check for updates" still works.
export function shouldAutoCheckForUpdates(version: string): boolean {
  return !version.includes("-");
}
