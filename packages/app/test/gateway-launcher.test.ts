import { createServer, type Server } from "node:net";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  bundledGatewayEnv,
  bundledGatewayPaths,
  ensureBundledGateway,
  gatewayListening,
} from "../src/gateway-launcher.js";

let server: Server | null = null;
let dir: string | null = null;
afterEach(async () => {
  if (server !== null) {
    await new Promise<void>((resolve) => server?.close(() => { resolve(); }));
    server = null;
  }
  if (dir !== null) {
    rmSync(dir, { recursive: true, force: true });
    dir = null;
  }
});

describe("bundled gateway launcher", () => {
  it("puts the gateway script under resources and its log in the data folder", () => {
    const p = bundledGatewayPaths(join("C:", "App", "resources"), join("C:", "Data"));
    expect(p.script).toBe(join("C:", "App", "resources", "vaultd", "gateway.cjs"));
    expect(p.logPath).toBe(join("C:", "Data", "gateway.log"));
  });

  it("pins the gateway to loopback and never inherits a wider bind or transport", () => {
    const env = bundledGatewayEnv(
      { PATH: "x", METAVAULT_GATEWAY_HOST: "0.0.0.0", METAVAULT_TRANSPORT: "overlay", METAVAULT_GATEWAY_PORT: "9999" },
      { vaultDir: "/vault", daemonBaseUrl: "http://127.0.0.1:7077" },
    );
    expect(env["ELECTRON_RUN_AS_NODE"]).toBe("1");
    expect(env["METAVAULT_GATEWAY_HOST"]).toBe("127.0.0.1");
    expect(env["METAVAULT_TRANSPORT"]).toBe("loopback");
    expect(env["METAVAULT_GATEWAY_PORT"]).toBe("7078");
    expect(env["METAVAULT_VAULT_DIR"]).toBe("/vault");
    expect(env["METAVAULT_DAEMON_URL"]).toBe("http://127.0.0.1:7077");
  });

  it("detects a listening gateway over plain TCP (mTLS has no anonymous health route)", async () => {
    server = createServer();
    server.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => server?.once("listening", () => { resolve(); }));
    const port = (server.address() as AddressInfo).port;
    expect(await gatewayListening("127.0.0.1", port)).toBe(true);
    expect(await gatewayListening("127.0.0.1", 1, 300)).toBe(false);
  });

  it("reports not-bundled when the gateway script is absent", async () => {
    dir = mkdtempSync(join(tmpdir(), "mv-gw-launch-"));
    const result = await ensureBundledGateway({
      execPath: "/bin/echo",
      paths: bundledGatewayPaths(join(dir, "resources"), join(dir, "data")),
      vaultDir: join(dir, "vault"),
      daemonBaseUrl: "http://127.0.0.1:7077",
      port: 1,
    });
    expect(result.status).toBe("not-bundled");
  });

  it("reports already-running when the port is served", async () => {
    dir = mkdtempSync(join(tmpdir(), "mv-gw-launch-"));
    server = createServer();
    server.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => server?.once("listening", () => { resolve(); }));
    const port = (server.address() as AddressInfo).port;
    const result = await ensureBundledGateway({
      execPath: "/bin/echo",
      paths: bundledGatewayPaths(join(dir, "resources"), join(dir, "data")),
      vaultDir: join(dir, "vault"),
      daemonBaseUrl: "http://127.0.0.1:7077",
      port,
    });
    expect(result.status).toBe("already-running");
  });
});
