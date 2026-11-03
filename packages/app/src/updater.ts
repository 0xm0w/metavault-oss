import { existsSync } from "node:fs";
import { join } from "node:path";
import type { BrowserWindow } from "electron";
import { app, ipcMain } from "electron";
import type { AppUpdater } from "electron-updater";

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

const UPDATER_UNAVAILABLE_MESSAGE = "Auto-update is unavailable in this build.";

let currentStatus: UpdaterStatusPayload = { status: "idle" };

export function getCurrentUpdaterStatus(): UpdaterStatusPayload {
  return currentStatus;
}

// electron-updater is loaded lazily, never through a static import. A
// static import resolves at module load, before any try/catch can run, so
// when the package is missing from the installed app the whole main
// process crashes at startup with ERR_MODULE_NOT_FOUND. The published
// v0.1.0 Windows installer shipped exactly that failure. Auto-update is
// optional: when the package cannot be loaded, the app starts normally
// and update checks report themselves unavailable instead.
async function loadAutoUpdater(): Promise<AppUpdater | null> {
  try {
    const { autoUpdater } = await import("electron-updater");
    return autoUpdater;
  } catch {
    return null;
  }
}

export async function initAutoUpdater(getWindow: () => BrowserWindow | null): Promise<void> {
  // Never reject: auto-update must not be able to take down app startup.
  try {
    function broadcast(payload: UpdaterStatusPayload): void {
      currentStatus = payload;
      const win = getWindow();
      if (win !== null && !win.isDestroyed()) {
        win.webContents.send(UPDATER_STATUS_CHANNEL, payload);
      }
    }

    const autoUpdater = await loadAutoUpdater();

    if (autoUpdater === null) {
      // Keep the IPC surface registered so the renderer gets a clean
      // answer instead of an unhandled missing-handler channel error.
      ipcMain.handle(CHECK_UPDATES_CHANNEL, () => ({ ok: false, error: UPDATER_UNAVAILABLE_MESSAGE }));
      ipcMain.handle(QUIT_AND_INSTALL_CHANNEL, () => ({ ok: false, error: UPDATER_UNAVAILABLE_MESSAGE }));
      return;
    }

    // Configure autoUpdater
    // Download only after isOfferableUpdate() accepts the version.
    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = true;

    autoUpdater.on("checking-for-update", () => {
      broadcast({ status: "checking" });
    });

    autoUpdater.on("update-available", (info) => {
      if (!isOfferableUpdate(info.version)) {
        broadcast({ status: "not-available", version: app.getVersion() });
        return;
      }
      broadcast({ status: "available", version: info.version });
      void autoUpdater.downloadUpdate().catch((err: unknown) => {
        broadcast({ status: "error", message: err instanceof Error ? err.message : String(err) });
      });
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

    ipcMain.handle(CHECK_UPDATES_CHANNEL, async () => {
      try {
        broadcast({ status: "checking" });
        const result = await autoUpdater.checkForUpdates();
        const updateInfo = result?.updateInfo;
        if (updateInfo !== undefined && !isOfferableUpdate(updateInfo.version)) {
          return { ok: true, updateInfo: undefined };
        }
        return { ok: true, updateInfo };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        broadcast({ status: "error", message: msg });
        return { ok: false, error: msg };
      }
    });

    ipcMain.handle(QUIT_AND_INSTALL_CHANNEL, () => {
      try {
        autoUpdater.quitAndInstall();
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
          void autoUpdater.checkForUpdates().catch(() => {
            // Ignored on network failure
          });
        }
      } catch {
        // Ignored
      }
    }, 5000);
  } catch {
    // Startup wins over updates: any failure above leaves the app running
    // with auto-update disabled.
  }
}

// Prerelease builds (e.g. 0.1.0-alpha) do not check on launch: a published
// stable release can sort above them, and an alpha must never replace
// itself without the user asking. "Check for updates" still works.
export function shouldAutoCheckForUpdates(version: string): boolean {
  return !version.includes("-");
}

// v0.1.0 is the older build that bundled a local model. It sorts above
// 0.1.0-alpha (the current build, which bundles no model), so neither the
// launch check nor "Check for updates" may ever offer it.
export const LEGACY_BUNDLED_MODEL_VERSIONS: readonly string[] = ["0.1.0"];

export function isOfferableUpdate(offeredVersion: string): boolean {
  return !LEGACY_BUNDLED_MODEL_VERSIONS.includes(offeredVersion.replace(/^v/, ""));
}
