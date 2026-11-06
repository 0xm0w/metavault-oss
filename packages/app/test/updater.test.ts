import type { BrowserWindow } from "electron";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { handleMock, sendMock } = vi.hoisted(() => ({
  handleMock: vi.fn<(channel: string, handler: unknown) => void>(),
  sendMock: vi.fn(),
}));

vi.mock("electron", () => ({
  app: { getVersion: () => "0.1.0-alpha" },
  ipcMain: { handle: handleMock },
}));

function fakeWindow(): BrowserWindow {
  return {
    isDestroyed: () => false,
    webContents: { send: sendMock },
  } as unknown as BrowserWindow;
}

function registeredChannels(): string[] {
  return handleMock.mock.calls.map(([channel]) => channel);
}

function handlerFor(channel: string): (...args: never[]) => unknown {
  const entry = handleMock.mock.calls.find(([ch]) => ch === channel);
  expect(entry, `handler registered for ${channel}`).toBeDefined();
  return entry?.[1] as (...args: never[]) => unknown;
}

beforeEach(() => {
  vi.resetModules();
  handleMock.mockClear();
  sendMock.mockClear();
});

describe("initAutoUpdater", () => {
  it("wires autoUpdater and registers the IPC surface when electron-updater loads", async () => {
    const fakeUpdater = {
      autoDownload: true,
      autoInstallOnAppQuit: false,
      on: vi.fn(),
      checkForUpdates: vi.fn(),
      downloadUpdate: vi.fn(),
      quitAndInstall: vi.fn(),
    };
    vi.doMock("electron-updater", () => ({ autoUpdater: fakeUpdater }));

    const updater = await import("../src/updater.js");
    await updater.initAutoUpdater(() => null);

    expect(fakeUpdater.autoDownload).toBe(false);
    // Unsigned builds must not auto-install on quit unless explicitly opted in.
    expect(fakeUpdater.autoInstallOnAppQuit).toBe(false);
    expect(registeredChannels()).toContain(updater.CHECK_UPDATES_CHANNEL);
    expect(registeredChannels()).toContain(updater.QUIT_AND_INSTALL_CHANNEL);
  });

  it("enables on-quit install when METAVAULT_AUTO_UPDATE=1 opts in", async () => {
    const fakeUpdater = {
      autoDownload: true,
      autoInstallOnAppQuit: false,
      on: vi.fn(),
      checkForUpdates: vi.fn(),
      downloadUpdate: vi.fn(),
      quitAndInstall: vi.fn(),
    };
    vi.doMock("electron-updater", () => ({ autoUpdater: fakeUpdater }));
    const prev = process.env["METAVAULT_AUTO_UPDATE"];
    process.env["METAVAULT_AUTO_UPDATE"] = "1";
    try {
      const updater = await import("../src/updater.js");
      await updater.initAutoUpdater(() => null);
      expect(fakeUpdater.autoInstallOnAppQuit).toBe(true);
    } finally {
      if (prev === undefined) delete process.env["METAVAULT_AUTO_UPDATE"];
      else process.env["METAVAULT_AUTO_UPDATE"] = prev;
    }
  });

  // Regression test for the published v0.1.0 installer crash: a static
  // import of electron-updater killed the main process at startup with
  // ERR_MODULE_NOT_FOUND when the package was missing from app.asar.
  it("starts cleanly with updates disabled when electron-updater cannot be imported", async () => {
    vi.doMock("electron-updater", () => {
      throw new Error("Cannot find package 'electron-updater'");
    });

    const updater = await import("../src/updater.js");
    await expect(updater.initAutoUpdater(() => null)).resolves.toBeUndefined();

    expect(registeredChannels()).toContain(updater.CHECK_UPDATES_CHANNEL);
    expect(registeredChannels()).toContain(updater.QUIT_AND_INSTALL_CHANNEL);

    const check = handlerFor(updater.CHECK_UPDATES_CHANNEL) as () => { ok: boolean; error?: string };
    const result = check();
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/unavailable/);
    expect(updater.getCurrentUpdaterStatus().status).toBe("idle");
  });

  it("survives an electron-updater import that rejects asynchronously", async () => {
    vi.doMock("electron-updater", () => Promise.reject(new Error("broken install")));

    const updater = await import("../src/updater.js");
    await expect(updater.initAutoUpdater(() => null)).resolves.toBeUndefined();

    const check = handlerFor(updater.CHECK_UPDATES_CHANNEL) as () => { ok: boolean };
    expect(check().ok).toBe(false);
  });

  it("still broadcasts updater events to the window when the updater loads", async () => {
    const listeners = new Map<string, (...args: never[]) => void>();
    const fakeUpdater = {
      autoDownload: true,
      autoInstallOnAppQuit: false,
      on: vi.fn((event: string, cb: (...args: never[]) => void) => listeners.set(event, cb)),
      checkForUpdates: vi.fn(),
      downloadUpdate: vi.fn(),
      quitAndInstall: vi.fn(),
    };
    vi.doMock("electron-updater", () => ({ autoUpdater: fakeUpdater }));

    const updater = await import("../src/updater.js");
    await updater.initAutoUpdater(fakeWindow);

    const onChecking = listeners.get("checking-for-update");
    expect(onChecking).toBeDefined();
    onChecking?.();
    expect(sendMock).toHaveBeenCalledWith(updater.UPDATER_STATUS_CHANNEL, { status: "checking" });
  });
});

describe("update gating", () => {
  it("never auto-checks prerelease builds", async () => {
    const updater = await import("../src/updater.js");
    expect(updater.shouldAutoCheckForUpdates("0.1.0-alpha")).toBe(false);
    expect(updater.shouldAutoCheckForUpdates("0.1.1")).toBe(true);
  });

  it("never offers the legacy bundled-model v0.1.0 build", async () => {
    const updater = await import("../src/updater.js");
    expect(updater.isOfferableUpdate("0.1.0")).toBe(false);
    expect(updater.isOfferableUpdate("v0.1.0")).toBe(false);
    expect(updater.isOfferableUpdate("0.1.1")).toBe(true);
  });
});
