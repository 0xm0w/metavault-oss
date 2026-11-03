import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  CHECK_UPDATES_CHANNEL,
  getCurrentUpdaterStatus,
  QUIT_AND_INSTALL_CHANNEL,
  isOfferableUpdate,
  shouldAutoCheckForUpdates,
  UPDATER_STATUS_CHANNEL,
} from "../src/updater.js";

const here = dirname(fileURLToPath(import.meta.url));
const appRoot = join(here, "..");

describe("Packaging & Installer Wizard Specifications (#16)", () => {
  it("defines auto-updater status and IPC channels correctly", () => {
    expect(UPDATER_STATUS_CHANNEL).toBe("metavault:updater-status");
    expect(CHECK_UPDATES_CHANNEL).toBe("metavault:check-for-updates");
    expect(QUIT_AND_INSTALL_CHANNEL).toBe("metavault:quit-and-install");
    expect(getCurrentUpdaterStatus()).toEqual({ status: "idle" });
  });

  it("provides Windows NSIS script with PATH configuration and data retention choice", () => {
    const nshPath = join(appRoot, "scripts", "installer.nsh");
    expect(existsSync(nshPath)).toBe(true);

    const nshContent = readFileSync(nshPath, "utf8");

    // Must configure user PATH in registry and broadcast environment change
    expect(nshContent).toContain("customInstall");
    expect(nshContent).toContain("HKCU");
    expect(nshContent).toContain("Environment");
    expect(nshContent).toContain("$INSTDIR\\bin");
    expect(nshContent).toContain("WM_SETTINGCHANGE");

    // Must configure auto-start in registry
    expect(nshContent).toContain("Software\\Microsoft\\Windows\\CurrentVersion\\Run");

    // Must provide clean uninstaller data wipe prompt
    expect(nshContent).toContain("customUnInstall");
    expect(nshContent).toContain("MessageBox MB_YESNO");
    expect(nshContent).toContain("metavault.db");
  });

  it("provides CLI launcher wrappers in bin/ for immediate terminal access", () => {
    const cmdPath = join(appRoot, "bin", "metavault.cmd");
    const ps1Path = join(appRoot, "bin", "metavault.ps1");
    const daemonCmdPath = join(appRoot, "bin", "vaultd.cmd");

    expect(existsSync(cmdPath)).toBe(true);
    expect(existsSync(ps1Path)).toBe(true);
    expect(existsSync(daemonCmdPath)).toBe(true);

    // The installed shims run the bundled scripts with the app's own
    // Electron binary in Node mode, so no separate Node install is needed.
    const cmdContent = readFileSync(cmdPath, "utf8");
    expect(cmdContent).toContain("ELECTRON_RUN_AS_NODE=1");
    expect(cmdContent).toContain("resources\\vaultd\\metavault.cjs");

    const ps1Content = readFileSync(ps1Path, "utf8");
    expect(ps1Content).toContain("ELECTRON_RUN_AS_NODE");
    expect(ps1Content).toContain("resources\\vaultd\\metavault.cjs");

    const daemonCmdContent = readFileSync(daemonCmdPath, "utf8");
    expect(daemonCmdContent).toContain("ELECTRON_RUN_AS_NODE=1");
    expect(daemonCmdContent).toContain("resources\\vaultd\\vaultd.cjs");
    expect(daemonCmdContent).toContain("METAVAULT_FIRST_RUN_SETUP=1");
  });

  it("keeps vault data on a silent uninstall and does not duplicate shortcuts", () => {
    const nshContent = readFileSync(join(appRoot, "scripts", "installer.nsh"), "utf8");
    expect(nshContent).toContain("/SD IDNO");
    expect(nshContent).not.toContain("CreateShortCut");
    expect(nshContent).toContain("-notcontains $$d");
  });

  it("ships a short alpha TERMS page as the installer license", () => {
    const terms = readFileSync(join(appRoot, "TERMS.txt"), "utf8");
    expect(terms).toContain("0.1.1-alpha");
    expect(terms).toContain("Apache License");
    expect(terms).toContain("AS IS");
    const pkg = JSON.parse(readFileSync(join(appRoot, "package.json"), "utf8")) as {
      version: string;
      scripts: Record<string, string>;
      build: {
        nsis: { license: string; allowToChangeInstallationDirectory: boolean };
        extraResources: { from: string; to: string }[];
        extraMetadata: { main: string };
      };
    };
    expect(pkg.version).toBe("0.1.1-alpha");
    expect(pkg.build.nsis.license).toBe("TERMS.txt");
    expect(pkg.build.nsis.allowToChangeInstallationDirectory).toBe(true);
    expect(pkg.build.extraResources).toContainEqual({ from: "bundle/vaultd", to: "vaultd" });
    expect(pkg.build.extraMetadata.main).toBe("dist/main.bundle.cjs");
    expect(Object.keys(pkg.scripts)).not.toContain("pack:win:ai");
  });

  it("never offers the legacy v0.1.0 (bundled-model) build as an update", () => {
    expect(isOfferableUpdate("0.1.0")).toBe(false);
    expect(isOfferableUpdate("v0.1.0")).toBe(false);
    expect(isOfferableUpdate("0.1.0-alpha")).toBe(true);
    expect(isOfferableUpdate("0.1.1")).toBe(true);
    expect(isOfferableUpdate("0.2.0-alpha")).toBe(true);
  });

  it("does not auto-check for updates on prerelease builds", () => {
    expect(shouldAutoCheckForUpdates("0.1.0-alpha")).toBe(false);
    expect(shouldAutoCheckForUpdates("0.1.0")).toBe(true);
  });

  it("configures electron-builder with NSIS wizard and GitHub Releases provider", () => {
    const pkgPath = join(appRoot, "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
      build: {
        nsis: {
          oneClick: boolean;
          createDesktopShortcut: boolean;
          createStartMenuShortcut: boolean;
          include: string;
        };
        publish: { provider: string; owner: string; repo: string };
      };
    };

    expect(pkg.build.nsis.oneClick).toBe(false);
    expect(pkg.build.nsis.createDesktopShortcut).toBe(true);
    expect(pkg.build.nsis.createStartMenuShortcut).toBe(true);
    expect(pkg.build.nsis.include).toBe("scripts/installer.nsh");
    expect(pkg.build.publish.provider).toBe("github");
    expect(pkg.build.publish.owner).toBe("0xm0w");
    expect(pkg.build.publish.repo).toBe("metavault-oss");
  });
});
