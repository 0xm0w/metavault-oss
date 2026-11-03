import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  bundledDaemonEnv,
  bundledDaemonPaths,
  daemonHealthy,
  ensureBundledDaemon,
} from "../src/daemon-launcher.js";

let server: Server | null = null;
afterEach(async () => {
  if (server !== null) {
    await new Promise<void>((resolve) => server?.close(() => { resolve(); }));
    server = null;
  }
});

async function serve(status: number, body: unknown): Promise<string> {
  server = createServer((_req, res) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  });
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", () => { resolve(); }));
  return `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
}

describe("bundled daemon launcher", () => {
  it("puts the daemon script under resources and the vault in the data folder", () => {
    const p = bundledDaemonPaths(join("C:", "App", "resources"), join("C:", "Data"));
    expect(p.script).toBe(join("C:", "App", "resources", "vaultd", "vaultd.cjs"));
    expect(p.dbPath).toBe(join("C:", "Data", "metavault.db"));
    expect(p.logPath).toBe(join("C:", "Data", "vaultd.log"));
  });

  it("runs the daemon in Node mode with first-run setup, keeping a user DB path", () => {
    const env = bundledDaemonEnv({ PATH: "x" }, "/data/metavault.db");
    expect(env["ELECTRON_RUN_AS_NODE"]).toBe("1");
    expect(env["METAVAULT_FIRST_RUN_SETUP"]).toBe("1");
    expect(env["METAVAULT_DB_PATH"]).toBe("/data/metavault.db");
    expect(env["PATH"]).toBe("x");
    expect(bundledDaemonEnv({ METAVAULT_DB_PATH: "/mine.db" }, "/data/metavault.db")["METAVAULT_DB_PATH"]).toBe("/mine.db");
  });

  it("treats only a vaultd /health answer as a running daemon", async () => {
    expect(await daemonHealthy(await serve(200, { status: "ok", service: "vaultd" }))).toBe(true);
    await new Promise<void>((resolve) => server?.close(() => { resolve(); }));
    server = null;
    expect(await daemonHealthy(await serve(200, { status: "ok", service: "other" }))).toBe(false);
    await new Promise<void>((resolve) => server?.close(() => { resolve(); }));
    server = null;
    expect(await daemonHealthy(await serve(500, {}))).toBe(false);
  });

  it("reports unreachable as not healthy", async () => {
    expect(await daemonHealthy("http://127.0.0.1:1", 500)).toBe(false);
  });

  it("does not spawn when a daemon already answers, or when none is bundled", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mv-launch-"));
    try {
      const paths = bundledDaemonPaths(join(dir, "resources"), join(dir, "data"));
      const up = await serve(200, { status: "ok", service: "vaultd" });
      expect((await ensureBundledDaemon({ execPath: process.execPath, paths, baseUrl: up })).status).toBe("already-running");
      expect(
        (await ensureBundledDaemon({ execPath: process.execPath, paths, baseUrl: "http://127.0.0.1:1" })).status,
      ).toBe("not-bundled");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
