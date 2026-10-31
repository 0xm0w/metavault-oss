import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  ALLOWED_DAEMON_CALLS,
  DAEMON_CALL_CHANNEL,
  callDaemon,
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
      { method: "GET", path: "/settings/warden" },
      { method: "PATCH", path: "/settings/warden" },
      { method: "GET", path: "/settings/warden/key" },
      { method: "PUT", path: "/settings/warden/key" },
      { method: "DELETE", path: "/settings/warden/key" },
    ]);
    for (const call of ALLOWED_DAEMON_CALLS) {
      expect(isAllowedDaemonCall(call.method, call.path)).toBe(true);
      expect(validateDaemonCall({ method: call.method, path: call.path })).toEqual({
        method: call.method,
        path: call.path,
      });
    }
  });

  it("allows PATCH/DELETE only for a single credential item path", () => {
    expect(isAllowedDaemonCall("PATCH", "/credentials/stripe")).toBe(true);
    expect(isAllowedDaemonCall("DELETE", "/credentials/stripe")).toBe(true);
    expect(isAllowedDaemonCall("PATCH", "/credentials")).toBe(false);
    expect(isAllowedDaemonCall("DELETE", "/credentials/a/b")).toBe(false);
    expect(isAllowedDaemonCall("PATCH", "/aliases")).toBe(false);
    expect(validateDaemonCall({ method: "PATCH", path: "/credentials/stripe", body: { scope: "x.read" } })).toEqual({
      method: "PATCH",
      path: "/credentials/stripe",
      body: { scope: "x.read" },
    });
    expect(() => validateDaemonCall({ method: "DELETE", path: "/pending" })).toThrow(/not allowed/);
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

describe("warden settings IPC whitelist (Task 6)", () => {
  const wardenCalls = [
    { method: "GET", path: "/settings/warden" },
    { method: "PATCH", path: "/settings/warden" },
    { method: "GET", path: "/settings/warden/key" },
    { method: "PUT", path: "/settings/warden/key" },
    { method: "DELETE", path: "/settings/warden/key" },
  ] as const;

  it("whitelists exactly the warden settings routes", () => {
    for (const call of wardenCalls) {
      expect(isAllowedDaemonCall(call.method, call.path)).toBe(true);
    }
    expect(isAllowedDaemonCall("POST", "/settings/warden")).toBe(false);
    expect(isAllowedDaemonCall("PUT", "/settings/warden")).toBe(false);
    expect(isAllowedDaemonCall("DELETE", "/settings/warden")).toBe(false);
    expect(isAllowedDaemonCall("POST", "/settings/warden/key")).toBe(false);
    expect(isAllowedDaemonCall("PATCH", "/settings/warden/key")).toBe(false);
    expect(isAllowedDaemonCall("GET", "/settings")).toBe(false);
    expect(isAllowedDaemonCall("GET", "/settings/warden/extra")).toBe(false);
    expect(isAllowedDaemonCall("GET", "/settings/warden/key/extra")).toBe(false);
    expect(() => validateDaemonCall({ method: "POST", path: "/settings/warden/key", body: { key: "x" } })).toThrow(/not allowed/);
    expect(() => validateDaemonCall({ method: "GET", path: "/settings/warden/../credentials" })).toThrow(/not allowed/);
  });

  it("forwards warden calls to the daemon with the token header (token stays in main)", async () => {
    process.env["OPENVAULT_DAEMON_TOKEN"] = "test-token-warden";
    const seen: { url: string; init: RequestInit }[] = [];
    const originalFetch = globalThis.fetch;
    const mockFetch = async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      seen.push({ url: typeof url === "string" ? url : url instanceof URL ? url.href : url.url, init: init ?? {} });
      await Promise.resolve();
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
    };
    globalThis.fetch = mockFetch;
    try {
      await callDaemon({ method: "GET", path: "/settings/warden" });
      await callDaemon({ method: "PATCH", path: "/settings/warden", body: { provider: "ollama", model: "llama3.1:8b", effort: "deep" } });
      await callDaemon({ method: "PUT", path: "/settings/warden/key", body: { key: "meta-key-12345678" } });
      await callDaemon({ method: "GET", path: "/settings/warden/key" });
      await callDaemon({ method: "DELETE", path: "/settings/warden/key" });
    } finally {
      globalThis.fetch = originalFetch;
      delete process.env["OPENVAULT_DAEMON_TOKEN"];
    }
    expect(seen.map((s) => s.url)).toEqual([
      "http://127.0.0.1:7077/settings/warden",
      "http://127.0.0.1:7077/settings/warden",
      "http://127.0.0.1:7077/settings/warden/key",
      "http://127.0.0.1:7077/settings/warden/key",
      "http://127.0.0.1:7077/settings/warden/key",
    ]);
    expect(seen.map((s) => s.init.method)).toEqual(["GET", "PATCH", "PUT", "GET", "DELETE"]);
    for (const call of seen) {
      const headers = call.init.headers as Record<string, string>;
      expect(headers["x-openvault-token"]).toBe("test-token-warden");
    }
    expect(JSON.parse(seen[2]?.init.body as string)).toEqual({ key: "meta-key-12345678" });
  });

  it("preload exposes named warden methods forwarding to the whitelisted routes and no token", () => {
    const preload = readFileSync(join(appRoot, "src", "preload.ts"), "utf8");
    expect(preload).toContain("getWardenSettings");
    expect(preload).toContain("updateWardenSettings");
    expect(preload).toContain("setWardenKey");
    expect(preload).toContain("deleteWardenKey");
    expect(preload).toContain("wardenKeyStatus");
    expect(preload).toContain('"/settings/warden"');
    expect(preload).toContain('"/settings/warden/key"');
    expect(preload).not.toContain("x-openvault-token");
    expect(preload).not.toContain("OPENVAULT_DAEMON_TOKEN");
    expect(preload).not.toContain("openvault.token");
  });
});
