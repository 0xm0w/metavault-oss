// Build asset step for the Electron app: tsc only emits JS, so the
// renderer's static page/styles must be copied into dist, and the
// CommonJS preload (emitted as dist/preload.js by tsconfig.preload.json)
// must be renamed to preload.cjs so Electron loads it as CommonJS from
// this "type": "module" package.
import { copyFileSync, existsSync, mkdirSync, renameSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const srcRenderer = join(appRoot, "src", "renderer");
const distRenderer = join(appRoot, "dist", "renderer");

mkdirSync(distRenderer, { recursive: true });
for (const name of ["index.html", "styles.css", "favicon.svg", "icon.ico", "tray.png"]) {
  const srcFile = join(srcRenderer, name);
  if (existsSync(srcFile)) {
    copyFileSync(srcFile, join(distRenderer, name));
  }
}

const srcBin = join(appRoot, "bin");
const distBin = join(appRoot, "dist", "bin");
mkdirSync(distBin, { recursive: true });
for (const name of ["metavault.cmd", "vaultd.cmd", "metavault.ps1", "openvault.cmd", "openvault.ps1"]) {
  const srcFile = join(srcBin, name);
  if (existsSync(srcFile)) {
    copyFileSync(srcFile, join(distBin, name));
  }
}

const emittedPreload = join(appRoot, "dist", "preload.js");
const cjsPreload = join(appRoot, "dist", "preload.cjs");
if (existsSync(emittedPreload)) {
  rmSync(cjsPreload, { force: true });
  renameSync(emittedPreload, cjsPreload);
} else if (!existsSync(cjsPreload)) {
  throw new Error(
    "dist/preload.js not found: run `tsc -p tsconfig.preload.json` first (npm run build does this).",
  );
}

console.log("assets: dist/renderer/index.html, dist/renderer/styles.css, dist/preload.cjs");
