// callDaemon token lifecycle: the daemon mints a fresh token on EVERY start
// (resolveDaemonToken) and rewrites metavault.token. A token cached while a
// previous daemon process ran - or read before the new daemon rewrote the
// file - is stale forever after; callDaemon must re-read once on 401.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

let dir = "";
let tokenPath = "";

const setup = (): void => {
  dir = mkdtempSync(join(tmpdir(), "mv-daemon-token-"));
  tokenPath = join(dir, "metavault.token");
  vi.stubEnv("METAVAULT_DB_PATH", join(dir, "metavault.db"));
  vi.stubEnv("METAVAULT_DAEMON_TOKEN", ""); // force the file path branch
};

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  rmSync(dir, { recursive: true, force: true });
});

describe("callDaemon daemon-token refresh", () => {
  it("re-reads the token file and retries once on 401 (daemon restart rotation)", async () => {
    setup();
    writeFileSync(tokenPath, "T1");
    const seen: (string | undefined)[] = [];
    vi.stubGlobal("fetch", (_url: string, init: { headers: Record<string, string> }) => {
      const tok = init.headers["x-metavault-token"];
      seen.push(tok);
      if (tok === "T1") {
        // The daemon restarts (rotating the token) mid-flight.
        writeFileSync(tokenPath, "T2");
        return Promise.resolve(new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 }));
      }
      if (tok === "T2") {
        return Promise.resolve(new Response(JSON.stringify({ enabled: true }), { status: 200 }));
      }
      return Promise.resolve(new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 }));
    });
    vi.resetModules(); // drop any cachedDaemonToken from another test
    const { callDaemon } = await import("../src/daemon-client.js");
    const result = await callDaemon({ method: "GET", path: "/settings/remote" });
    expect(result).toEqual({ enabled: true });
    expect(seen).toEqual(["T1", "T2"]);
  });

  it("re-reads only once: a persistent 401 still fails", async () => {
    setup();
    writeFileSync(tokenPath, "T1");
    const seen: (string | undefined)[] = [];
    vi.stubGlobal("fetch", (_url: string, init: { headers: Record<string, string> }) => {
      seen.push(init.headers["x-metavault-token"]);
      return Promise.resolve(new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 }));
    });
    vi.resetModules(); // drop any cachedDaemonToken from another test
    const { callDaemon } = await import("../src/daemon-client.js");
    await expect(callDaemon({ method: "GET", path: "/settings/remote" })).rejects.toThrow(/401/);
    expect(seen).toEqual(["T1", "T1"]);
  });
});
