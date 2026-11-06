import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  APPROVAL_FOCUS_GUARD_MS,
  approvalActivationAllowed,
  buildWindowOptions,
  shouldHideOnClose,
} from "../src/window-options.js";

const here = dirname(fileURLToPath(import.meta.url));
const appSrc = join(here, "..", "src");

describe("Electron window hardening & focus-steal prevention", () => {
  it("keeps nodeIntegration off, contextIsolation on, and show: false to prevent --minimized flash", () => {
    const normal = buildWindowOptions("/tmp/preload.cjs");
    expect(normal.show).toBe(false);
    expect(normal.webPreferences.nodeIntegration).toBe(false);
    expect(normal.webPreferences.contextIsolation).toBe(true);
    expect(normal.webPreferences.sandbox).toBe(true);
    expect(normal.webPreferences.preload).toBe("/tmp/preload.cjs");

    const minimized = buildWindowOptions("/tmp/preload.cjs", ["--minimized"]);
    expect(minimized.show).toBe(false);
  });

  it("hides to tray on close when minimizeToTrayOnClose is enabled and not quitting", () => {
    expect(shouldHideOnClose(false, true)).toBe(true);
    expect(shouldHideOnClose(false, false)).toBe(false);
    expect(shouldHideOnClose(true, true)).toBe(false);
  });

  it("enforces the 500ms focus activation guard and never auto-focuses .btn-approve", () => {
    expect(APPROVAL_FOCUS_GUARD_MS).toBe(500);
    expect(approvalActivationAllowed(1_000, 1_499)).toBe(false);
    expect(approvalActivationAllowed(1_000, 1_500)).toBe(true);

    const rendererMain = readFileSync(join(appSrc, "renderer", "main.ts"), "utf8");
    const flyoutSource = readFileSync(join(appSrc, "renderer", "flyout.ts"), "utf8");
    expect(rendererMain).not.toMatch(/approve\.focus\s*\(/);
    expect(rendererMain).not.toMatch(/approveBtn\.focus\s*\(/);
    expect(flyoutSource).not.toMatch(/approveBtn\.focus\s*\(/);
  });
});
