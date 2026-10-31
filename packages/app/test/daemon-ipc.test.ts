import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  ALLOWED_DAEMON_CALLS,
  DAEMON_CALL_CHANNEL,
  isAllowedDaemonCall,
  validateDaemonCall,
} from "../src/daemon-client.js";

// Regression guards for the sandbox gate failure: the preload runs
// sandboxed and cannot use node:fs or fetch, so the daemon HTTP client
// must live in the main process behind a single whitelisted IPC channel.
const here = dirname(fileURLToPath(import.meta.url));
const appRoot = join(here, "..");

describe("preload is a thin IPC bridge (no fs, no fetch)", () => {
  const preloadSource = readFileSync(join(appRoot, "src", "preload.ts"), "utf8");

  it("contains no node:fs and no fetch call", () => {
    expect(preloadSource).not.toContain("node:fs");
    expect(preloadSource).not.toContain("fetch(");
    expect(preloadSource).not.toContain("node:path");
    expect(preloadSource).not.toContain("readFileSync");
  });

  it("uses ipcRenderer.invoke to the single daemon-call channel", () => {
    expect(preloadSource).toContain("ipcRenderer.invoke");
    expect(preloadSource).toContain(DAEMON_CALL_CHANNEL);
    expect(DAEMON_CALL_CHANNEL).toBe("openvault:daemon-call");
  });

  it("imports only electron (plus erased types)", () => {
    const imports = [...preloadSource.matchAll(/from\s+"([^"]+)"/g)].map((m) => m[1]);
    for (const specifier of imports) {
      expect(specifier === "electron" || specifier?.endsWith("renderer/types.js")).toBe(true);
    }
    expect(imports).toContain("electron");
  });
});

describe("main-process daemon whitelist", () => {
  it("allows exactly the VaultApi operations", () => {
    expect(ALLOWED_DAEMON_CALLS).toEqual([
      { method: "POST", path: "/request" },
      { method: "POST", path: "/approve" },
      { method: "POST", path: "/deny" },
      { method: "POST", path: "/approve-always" },
      { method: "POST", path: "/revoke" },
      { method: "GET", path: "/aliases" },
      { method: "GET", path: "/audit" },
      { method: "GET", path: "/pending" },
      { method: "GET", path: "/policies" },
      { method: "POST", path: "/credentials" },
    ]);
    for (const call of ALLOWED_DAEMON_CALLS) {
      expect(isAllowedDaemonCall(call.method, call.path)).toBe(true);
      expect(validateDaemonCall({ method: call.method, path: call.path })).toEqual({
        method: call.method,
        path: call.path,
      });
    }
  });

  it("rejects non-whitelisted paths and method/path mismatches", () => {
    expect(isAllowedDaemonCall("GET", "/secrets")).toBe(false);
    expect(isAllowedDaemonCall("POST", "/aliases")).toBe(false);
    expect(isAllowedDaemonCall("GET", "/approve")).toBe(false);
    expect(isAllowedDaemonCall("DELETE", "/pending")).toBe(false);
    expect(isAllowedDaemonCall("GET", "/pending/extra")).toBe(false);
    expect(() => validateDaemonCall({ method: "GET", path: "/secrets" })).toThrow(/not allowed/);
    expect(() => validateDaemonCall({ method: "POST", path: "/aliases" })).toThrow(/not allowed/);
    expect(() => validateDaemonCall({ method: "GET", path: "/evil" })).toThrow(/not allowed/);
    expect(() => validateDaemonCall(null)).toThrow(/malformed/);
    expect(() => validateDaemonCall("GET /pending")).toThrow(/malformed/);
    expect(() => validateDaemonCall({ method: 42, path: "/pending" })).toThrow(/not allowed/);
  });

  it("main registers exactly one ipcMain.handle for the daemon channel", () => {
    const mainSource = readFileSync(join(appRoot, "src", "main.ts"), "utf8");
    expect(mainSource).toContain("ipcMain.handle");
    expect(mainSource).toContain("DAEMON_CALL_CHANNEL");
    expect(mainSource).toContain("callDaemon");
    const handleCount = (mainSource.match(/ipcMain\.handle/g) ?? []).length;
    expect(handleCount).toBe(1);
    expect(mainSource).not.toContain("OPENVAULT_DAEMON_TOKEN");
  });

  it("daemon client owns token, base URL, and header in main", () => {
    const clientSource = readFileSync(join(appRoot, "src", "daemon-client.ts"), "utf8");
    expect(clientSource).toContain("OPENVAULT_DAEMON_URL");
    expect(clientSource).toContain("http://127.0.0.1:7077");
    expect(clientSource).toContain("OPENVAULT_DAEMON_TOKEN");
    expect(clientSource).toContain("openvault.token");
    expect(clientSource).toContain("x-openvault-token");
    expect(clientSource).not.toContain("electron");
  });
});
