// Packaging step for the Windows installer (run after `npm run build`).
//
// The repo is not an npm workspace, so electron-builder cannot pull the
// root node_modules into the app. Instead we bundle with esbuild:
//   dist/main.bundle.cjs       Electron main process (electron external)
//   bundle/vaultd/vaultd.cjs   the vault daemon
//   bundle/vaultd/metavault.cjs  the CLI
//   bundle/vaultd/mcp.cjs      the MCP server for agents
//   bundle/vaultd/gateway.cjs  the remote-access gateway (remote off by default)
// bundle/vaultd ships as resources/vaultd and runs under the app's own
// Electron binary with ELECTRON_RUN_AS_NODE=1, so users need no Node.
// better-sqlite3 stays external: its Node-API prebuild for the target
// platform is copied to bundle/vaultd/native/better-sqlite3 (not
// node_modules: electron-builder drops node_modules folders from
// extraResources) and the bundles require it by that relative path.
// No model is bundled.
import { build } from "esbuild";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = join(appRoot, "..", "..");
const outVaultd = join(appRoot, "bundle", "vaultd");
const target = process.env["METAVAULT_BUNDLE_TARGET"] ?? `${process.platform}-${process.arch}`;

// CJS output has no import.meta; the entry checks and path lookups use
// import.meta.url, so define it from __filename.
const shared = {
  bundle: true,
  platform: "node",
  format: "cjs",
  target: "node22",
  sourcemap: false,
  legalComments: "none",
  logLevel: "warning",
  metafile: true,
  define: { "import.meta.url": "__metavault_import_meta_url" },
  banner: { js: 'const __metavault_import_meta_url = require("node:url").pathToFileURL(__filename).href;' },
};

const metafiles = [];
metafiles.push((await build({
  ...shared,
  entryPoints: [join(appRoot, "src", "main.ts")],
  outfile: join(appRoot, "dist", "main.bundle.cjs"),
  external: ["electron"],
})).metafile);

const nativeSqlite = {
  name: "native-better-sqlite3",
  setup(b) {
    b.onResolve({ filter: /^better-sqlite3$/ }, () => ({ path: "./native/better-sqlite3", external: true }));
  },
};

rmSync(outVaultd, { recursive: true, force: true });
mkdirSync(outVaultd, { recursive: true });
const entries = [
  ["daemon/src/server.ts", "vaultd.cjs"],
  ["cli/src/cli.ts", "metavault.cjs"],
  ["mcp/src/server.ts", "mcp.cjs"],
  ["gateway/src/index.ts", "gateway.cjs"],
];
for (const [entry, out] of entries) {
  metafiles.push((await build({
    ...shared,
    entryPoints: [join(repoRoot, "packages", entry)],
    outfile: join(outVaultd, out),
    plugins: [nativeSqlite],
  })).metafile);
}

// better-sqlite3: package.json + lib + the one Node-API prebuild we need.
const sqliteSrc = join(repoRoot, "node_modules", "better-sqlite3");
const sqliteDst = join(outVaultd, "native", "better-sqlite3");
const prebuild = join(sqliteSrc, "prebuilds", `${target}.node`);
if (!existsSync(prebuild)) {
  throw new Error(`better-sqlite3 has no prebuild for ${target} (${prebuild})`);
}
mkdirSync(join(sqliteDst, "prebuilds"), { recursive: true });
cpSync(join(sqliteSrc, "package.json"), join(sqliteDst, "package.json"));
cpSync(join(sqliteSrc, "LICENSE"), join(sqliteDst, "LICENSE"));
cpSync(join(sqliteSrc, "lib"), join(sqliteDst, "lib"), { recursive: true });
cpSync(prebuild, join(sqliteDst, "prebuilds", `${target}.node`));
writeFileSync(join(outVaultd, "package.json"), `${JSON.stringify({ type: "commonjs" }, null, 2)}\n`);

// Distribution notices: the project license plus the license text of every
// npm package esbuild actually bundled (read from the metafile), so the
// installer carries the notices the dependencies require.
cpSync(join(repoRoot, "LICENSE"), join(outVaultd, "LICENSE-MetaVault-OSS.txt"));
const pkgDirs = new Set([sqliteSrc]);
for (const m of metafiles) {
  for (const input of Object.keys(m.inputs)) {
    const i = input.replaceAll("\\", "/").lastIndexOf("node_modules/");
    if (i < 0) continue;
    const rest = input.replaceAll("\\", "/").slice(i + "node_modules/".length).split("/");
    const name = rest[0].startsWith("@") ? `${rest[0]}/${rest[1]}` : rest[0];
    pkgDirs.add(join(repoRoot, "node_modules", name));
  }
}
const sections = [];
for (const dir of [...pkgDirs].sort()) {
  const pj = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  const lic = readdirSync(dir).filter((f) => /^(licen[sc]e|notice|copying)/i.test(f));
  const texts = lic.map((f) => readFileSync(join(dir, f), "utf8").trim());
  sections.push(
    `=== ${pj.name}@${pj.version} (declared license: ${typeof pj.license === "string" ? pj.license : JSON.stringify(pj.license ?? "none declared")}) ===\n` +
      `Author: ${typeof pj.author === "string" ? pj.author : (pj.author?.name ?? "not declared")}; repository: ${typeof pj.repository === "string" ? pj.repository : (pj.repository?.url ?? "not declared")}\n` +
      (texts.length ? texts.join("\n\n") : "(the upstream repository and npm package publish no license or copyright text; only the license identifier above is declared by the author)"),
  );
}
writeFileSync(
  join(outVaultd, "THIRD_PARTY_LICENSES.txt"),
  `Third-party software bundled in MetaVault OSS (resources/vaultd and the app main bundle).\nGenerated at build time from the esbuild metafile. Electron and Chromium licenses are in the application directory (LICENSE.electron.txt, LICENSES.chromium.html).\n\n${sections.join("\n\n")}\n`,
);
console.log(`bundle: ${pkgDirs.size} bundled npm packages with notices`);

console.log(`bundle: dist/main.bundle.cjs, bundle/vaultd/{vaultd,metavault,mcp,gateway}.cjs, better-sqlite3 ${target}`);
