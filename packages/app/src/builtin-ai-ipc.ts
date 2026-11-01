import { app, BrowserWindow, ipcMain } from "electron";
import {
  BUILTIN_AI_PROGRESS_CHANNEL,
  BUILTIN_AI_STATUS_CHANNEL,
  CANCEL_BUILTIN_AI_DOWNLOAD_CHANNEL,
  ModelDownloader,
  START_BUILTIN_AI_DOWNLOAD_CHANNEL,
} from "./model-downloader.js";
import { resolveBuiltinModel } from "./model-resolver.js";

export function registerBuiltinAiIpc(getMainWindow: () => BrowserWindow | null): void {
  let activeDownloader: ModelDownloader | null = null;

  ipcMain.handle(BUILTIN_AI_STATUS_CHANNEL, () => {
    const resolverStatus = resolveBuiltinModel(process.resourcesPath, app.getPath("userData"));
    const dlStatus = activeDownloader !== null ? activeDownloader.getStatus() : null;
    return { resolverStatus, downloadStatus: dlStatus };
  });

  ipcMain.handle(START_BUILTIN_AI_DOWNLOAD_CHANNEL, async () => {
    if (activeDownloader === null) {
      activeDownloader = new ModelDownloader(app.getPath("userData"), (payload) => {
        const win = getMainWindow();
        if (win !== null && !win.isDestroyed()) {
          win.webContents.send(BUILTIN_AI_PROGRESS_CHANNEL, payload);
        }
      });
    }
    return activeDownloader.download();
  });

  ipcMain.handle(CANCEL_BUILTIN_AI_DOWNLOAD_CHANNEL, () => {
    if (activeDownloader !== null) {
      activeDownloader.cancel();
      activeDownloader = null;
      return true;
    }
    return false;
  });
}
