// callDaemon token lifecycle with the environment-only daemon token. The
// daemon never writes a token file, so the app resolves
// METAVAULT_DAEMON_TOKEN from its own environment (the launcher shares the
// same value with the bundled daemon) and caches it; a 401 re-reads once
// and retries.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const appRoot = join(here, "..");

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("callDaemon daemon-token refresh", () => {
  it("sends the env token and never resolves token material from disk", async () => {
    vi.stubEnv("METAVAULT_DAEMON_TOKEN", "T1");
    const seen: (string | undefined)[] = [];
    vi.stubGlobal("fetch", (_url: string, init: { headers: Record<string, string> }) => {
      seen.push(init.headers["x-metavault-token"]);
      return Promise.resolve(new Response(JSON.stringify({ enabled: true }), { status: 200 }));
    });
    vi.resetModules(); // drop any cachedDaemonToken from another test
    const { callDaemon } = await import("../src/daemon-client.js");
    const result = await callDaemon({ method: "GET", path: "/settings/remote" });
    expect(result).toEqual({ enabled: true });
    const second = await callDaemon({ method: "GET", path: "/settings/remote" });
    expect(second).toEqual({ enabled: true });
    expect(seen).toEqual(["T1", "T1"]);
    // The client source must not even mention the legacy token file: there
    // is no on-disk copy of the admin secret to fall back to.
    const source = readFileSync(join(appRoot, "src", "daemon-client.ts"), "utf8");
    expect(source).not.toContain("metavault.token");
  });

  it("re-reads the environment once on 401 and retries", async () => {
    const seen: (string | undefined)[] = [];
    vi.stubGlobal("fetch", (_url: string, init: { headers: Record<string, string> }) => {
      const tok = init.headers["x-metavault-token"];
      seen.push(tok);
      if (tok !== "T2") {
        // An external restart installed a different session token.
        vi.stubEnv("METAVAULT_DAEMON_TOKEN", "T2");
        return Promise.resolve(new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 }));
      }
      return Promise.resolve(new Response(JSON.stringify({ enabled: true }), { status: 200 }));
    });
    vi.stubEnv("METAVAULT_DAEMON_TOKEN", "T1");
    vi.resetModules();
    const { callDaemon } = await import("../src/daemon-client.js");
    const result = await callDaemon({ method: "GET", path: "/settings/remote" });
    expect(result).toEqual({ enabled: true });
    expect(seen).toEqual(["T1", "T2"]);
  });

  it("re-reads only once: a persistent 401 still fails", async () => {
    const seen: (string | undefined)[] = [];
    vi.stubEnv("METAVAULT_DAEMON_TOKEN", "T1");
    vi.stubGlobal("fetch", (_url: string, init: { headers: Record<string, string> }) => {
      seen.push(init.headers["x-metavault-token"]);
      return Promise.resolve(new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 }));
    });
    vi.resetModules();
    const { callDaemon } = await import("../src/daemon-client.js");
    await expect(callDaemon({ method: "GET", path: "/settings/remote" })).rejects.toThrow(/401/);
    expect(seen).toEqual(["T1", "T1"]);
  });

  it("without METAVAULT_DAEMON_TOKEN the guarded call goes out headerless and fails", async () => {
    const seen: (string | undefined)[] = [];
    vi.stubEnv("METAVAULT_DAEMON_TOKEN", "");
    vi.stubGlobal("fetch", (_url: string, init: { headers: Record<string, string> }) => {
      seen.push(init.headers["x-metavault-token"]);
      return Promise.resolve(new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 }));
    });
    vi.resetModules();
    const { callDaemon } = await import("../src/daemon-client.js");
    await expect(callDaemon({ method: "GET", path: "/settings/remote" })).rejects.toThrow(/401/);
    expect(seen.every((t) => t === undefined)).toBe(true);
  });
});
