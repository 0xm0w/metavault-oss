import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { PRELOAD_FILE_NAME, buildWindowOptions } from "../src/window-options.js";

// Regression guard for the blank-renderer gate failure: Electron preload
// scripts (especially sandboxed ones) must be CommonJS. When preload.js was
// emitted as ESM from the "type": "module" package, Electron threw
// "Cannot use import statement outside a module" and the window stayed blank.
const here = dirname(fileURLToPath(import.meta.url));
const appRoot = join(here, "..");

describe("Electron preload (CommonJS contract)", () => {
  it("points window options at a .cjs preload file", () => {
    expect(PRELOAD_FILE_NAME).toBe("preload.cjs");
    expect(PRELOAD_FILE_NAME.endsWith(".cjs")).toBe(true);
    const options = buildWindowOptions(join("/app", "dist", PRELOAD_FILE_NAME));
    expect(options.webPreferences.preload.endsWith("preload.cjs")).toBe(true);
    expect(options.webPreferences.preload.endsWith("preload.js")).toBe(false);
  });

  it("main process resolves the preload via the .cjs file name", () => {
    const mainSource = readFileSync(join(appRoot, "src", "main.ts"), "utf8");
    expect(mainSource).toContain("PRELOAD_FILE_NAME");
    expect(mainSource).not.toContain('"preload.js"');
    expect(mainSource).not.toContain("'preload.js'");
  });

  it("built preload.cjs, when present, is CommonJS-shaped", () => {
    const builtPreload = join(appRoot, "dist", "preload.cjs");
    if (!existsSync(builtPreload)) {
      // Not built yet (clean checkout): the .cjs name contract above still
      // guards the regression. After `npm --prefix packages/app run build`
      // this branch exercises the emitted file.
      expect(PRELOAD_FILE_NAME).toBe("preload.cjs");
      return;
    }
    const source = readFileSync(builtPreload, "utf8");
    const lines = source.split(/\r?\n/);
    const topLevelEsm = lines.filter((line) =>
      /^(?:import|export)\s/.test(line.trimStart()),
    );
    expect(topLevelEsm).toEqual([]);
    expect(source).toContain('require("electron")');
  });

  it("built renderer page, when present, loads its script and styles", () => {
    const builtPage = join(appRoot, "dist", "renderer", "index.html");
    if (!existsSync(builtPage)) {
      return;
    }
    const html = readFileSync(builtPage, "utf8");
    expect(html).toContain("./styles.css");
    expect(html).toContain("./main.js");
    expect(existsSync(join(appRoot, "dist", "renderer", "styles.css"))).toBe(true);
    expect(existsSync(join(appRoot, "dist", "renderer", "main.js"))).toBe(true);
  });
});
