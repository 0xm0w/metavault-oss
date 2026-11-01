import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { deleteMasterKey, retrieveMasterKey, storeMasterKey } from "../src/keychain.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..");

describe("macOS Platform Support & Keychain Integration (#21)", () => {
  it("enforces 32-byte master key invariant on storage", () => {
    expect(() => storeMasterKey(Buffer.alloc(16))).toThrow("masterKey must be 32 bytes");
    expect(() => storeMasterKey(Buffer.alloc(64))).toThrow("masterKey must be 32 bytes");
  });

  it("safely handles keychain retrieval and deletion without uncaught throws", () => {
    // In non-darwin or CI environment without mocked security CLI, retrieve returns null or buffer
    const retrieved = retrieveMasterKey();
    expect(retrieved === null || Buffer.isBuffer(retrieved)).toBe(true);

    const deleted = deleteMasterKey();
    expect(typeof deleted).toBe("boolean");
  });

  it("provides valid launchd daemon plist with standard KeepAlive and logging paths", () => {
    const plistPath = join(repoRoot, "packages", "daemon", "launchd", "dev.openvault.vaultd.plist");
    expect(existsSync(plistPath)).toBe(true);

    const content = readFileSync(plistPath, "utf8");
    expect(content).toContain("<string>dev.openvault.vaultd</string>");
    expect(content).toContain("<key>RunAtLoad</key>");
    expect(content).toContain("<true/>");
    expect(content).toContain("<key>KeepAlive</key>");
    expect(content).toContain("openvault-vaultd.log");
    expect(content).toContain("7077");
  });

  it("configures electron-builder for universal macOS packaging with DMG drag-and-drop", () => {
    const pkgPath = join(repoRoot, "packages", "app", "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
      build: {
        mac: {
          category: string;
          darkModeSupport: boolean;
          hardenedRuntime: boolean;
          target: { target: string; arch: string[] }[];
        };
        dmg: {
          title: string;
          contents: { type?: string; path?: string }[];
        };
      };
    };

    expect(pkg.build.mac.category).toBe("public.app-category.developer-tools");
    expect(pkg.build.mac.darkModeSupport).toBe(true);
    expect(pkg.build.mac.hardenedRuntime).toBe(true);

    const dmgTarget = pkg.build.mac.target.find((t) => t.target === "dmg");
    expect(dmgTarget?.arch).toContain("arm64");
    expect(dmgTarget?.arch).toContain("x64");
    expect(dmgTarget?.arch).toContain("universal");

    expect(pkg.build.dmg.title).toBe("MetaVault OSS");
    const appLink = pkg.build.dmg.contents.find((c) => c.path === "/Applications");
    expect(appLink?.type).toBe("link");
  });
});
