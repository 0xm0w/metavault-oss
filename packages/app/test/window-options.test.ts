import { describe, expect, it } from "vitest";
import { buildWindowOptions, shouldHideOnClose } from "../src/window-options.js";

describe("Electron window hardening", () => {
  it("keeps nodeIntegration off and contextIsolation on", () => {
    const options = buildWindowOptions("/tmp/preload.js");
    expect(options.webPreferences.nodeIntegration).toBe(false);
    expect(options.webPreferences.contextIsolation).toBe(true);
    expect(options.webPreferences.sandbox).toBe(true);
    expect(options.webPreferences.preload).toBe("/tmp/preload.js");
  });

  it("hides to tray on close unless quitting", () => {
    expect(shouldHideOnClose(false)).toBe(true);
    expect(shouldHideOnClose(true)).toBe(false);
  });
});
