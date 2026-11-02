import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  CHECK_UPDATES_CHANNEL,
  getCurrentUpdaterStatus,
  QUIT_AND_INSTALL_CHANNEL,
  UPDATER_STATUS_CHANNEL,
} from "../src/updater.js";

const here = dirname(fileURLToPath(import.meta.url));
const appRoot = join(here, "..");

describe("Packaging & Installer Wizard Specifications (#16)", () => {
  it("defines auto-updater status and IPC channels correctly", () => {
    expect(UPDATER_STATUS_CHANNEL).toBe("openvault:updater-status");
    expect(CHECK_UPDATES_CHANNEL).toBe("openvault:check-for-updates");
    expect(QUIT_AND_INSTALL_CHANNEL).toBe("openvault:quit-and-install");
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
    expect(nshContent).toContain("openvault.db");
  });

  it("provides CLI launcher wrappers in bin/ for immediate terminal access", () => {
    const cmdPath = join(appRoot, "bin", "openvault.cmd");
    const ps1Path = join(appRoot, "bin", "openvault.ps1");
    const daemonCmdPath = join(appRoot, "bin", "vaultd.cmd");

    expect(existsSync(cmdPath)).toBe(true);
    expect(existsSync(ps1Path)).toBe(true);
    expect(existsSync(daemonCmdPath)).toBe(true);

    const cmdContent = readFileSync(cmdPath, "utf8");
    expect(cmdContent).toContain("--cli");

    const ps1Content = readFileSync(ps1Path, "utf8");
    expect(ps1Content).toContain("--cli");

    const daemonCmdContent = readFileSync(daemonCmdPath, "utf8");
    expect(daemonCmdContent).toContain("--daemon");
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
