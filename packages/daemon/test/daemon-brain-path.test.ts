import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect } from "effect";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { encryptSecret } from "../../core/src/crypto.js";
import { VaultStore, VaultStoreLive } from "../../core/src/storage.js";
import { startVaultDaemon } from "../src/server.js";

// End-to-end check of the daemon's real warden path: no Brain is injected,
// so startVaultDaemon builds its dynamic brain from stored settings and
// calls Ollama over HTTP. A fake Ollama server stands in for the model and
// returns a high-risk decision; the request must stop for a human and the
// audit must carry the model's own explanation.

const MASTER_KEY = Buffer.alloc(32, 9);
const TOKEN = "brain-path-daemon-token-0123456789";
const SENTINEL = "FAKE-OLLAMA-SENTINEL-HIGH";

const closers: (() => Promise<void>)[] = [];
afterEach(() => {
  vi.unstubAllEnvs();
});
afterAll(async () => {
  await Promise.all(closers.splice(0).map((close) => close()));
});

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.closeAllConnections();
    server.close(() => {
      resolve();
    });
  });
}

function portOf(server: Server): number {
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  return address.port;
}

async function listen(server: Server): Promise<void> {
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve();
    });
  });
}

interface OllamaCall {
  readonly path: string;
  readonly body: { model?: string; format?: string; messages?: { role: string; content: string }[] };
}

async function startFakeOllama(calls: OllamaCall[]): Promise<Server> {
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk: Buffer) => {
      raw += chunk.toString("utf8");
    });
    req.on("end", () => {
      calls.push({ path: req.url ?? "", body: JSON.parse(raw === "" ? "{}" : raw) as OllamaCall["body"] });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          model: "muse-glimmer:30b",
          message: {
            role: "assistant",
            content: JSON.stringify({
              risk: "high",
              recommendedScope: "charges.read",
              requireApproval: true,
              explanation: SENTINEL,
            }),
          },
          done: true,
        }),
      );
    });
  });
  closers.push(() => closeServer(server));
  await listen(server);
  return server;
}

describe("daemon warden path with no injected brain", () => {
  it("calls Ollama with the default model and lets the model's decision gate the request", async () => {
    const calls: OllamaCall[] = [];
    const ollama = await startFakeOllama(calls);
    vi.stubEnv("METAVAULT_OLLAMA_URL", `http://127.0.0.1:${String(portOf(ollama))}`);
    vi.stubEnv("METAVAULT_WARDEN_MODEL", "");

    const dir = mkdtempSync(join(tmpdir(), "metavault-brain-"));
    const dbPath = join(dir, "metavault.db");
    try {
      await Effect.runPromise(
        Effect.gen(function* () {
          const store = yield* VaultStore;
          yield* store.addCredential("stripe", "charges.read", encryptSecret(MASTER_KEY, "sk-test-brain-path"));
        }).pipe(Effect.provide(VaultStoreLive(dbPath, MASTER_KEY))),
      );

      const daemon = await startVaultDaemon({ port: 0, dbPath, masterKey: MASTER_KEY, daemonToken: TOKEN });
      closers.push(() => closeServer(daemon));
      const base = `http://127.0.0.1:${String(portOf(daemon))}`;
      const auth = { "content-type": "application/json", "x-metavault-token": TOKEN };

      const settings = (await (await fetch(`${base}/settings/warden`, { headers: auth })).json()) as {
        provider: string;
        model: string;
      };
      expect(settings.provider).toBe("builtin");
      expect(settings.model).toBe("muse-glimmer:30b");

      const requested = await fetch(`${base}/request`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          agentId: "cursor",
          ide: "Cursor",
          tool: "http",
          alias: "stripe",
          requestedScope: "charges.read",
          reason: "list charges",
        }),
      });
      expect(requested.status).toBe(200);
      const body = (await requested.json()) as { status: string };
      expect(body.status).toBe("awaiting-approval");

      expect(calls).toHaveLength(1);
      expect(calls[0]?.path).toBe("/api/chat");
      expect(calls[0]?.body.model).toBe("muse-glimmer:30b");
      expect(calls[0]?.body.format).toBe("json");
      expect(JSON.stringify(calls[0]?.body.messages)).toContain("charges.read");
      expect(JSON.stringify(calls[0]?.body)).not.toContain("sk-test-brain-path");

      const auditText = await (await fetch(`${base}/audit`, { headers: auth })).text();
      expect(auditText).toContain(SENTINEL);
      expect(auditText).toContain("muse-glimmer:30b");
      expect(auditText).not.toContain("sk-test-brain-path");
    } finally {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // best effort: the sqlite handle may still be open on Windows
      }
    }
  });

  it("a provider-only switch over HTTP resets the model to that provider's default", async () => {
    const dir = mkdtempSync(join(tmpdir(), "metavault-brain-"));
    const dbPath = join(dir, "metavault.db");
    try {
      const daemon = await startVaultDaemon({ port: 0, dbPath, masterKey: MASTER_KEY, daemonToken: TOKEN });
      closers.push(() => closeServer(daemon));
      const base = `http://127.0.0.1:${String(portOf(daemon))}`;
      const auth = { "content-type": "application/json", "x-metavault-token": TOKEN };
      const patch = async (body: unknown) =>
        (await (
          await fetch(`${base}/settings/warden`, { method: "PATCH", headers: auth, body: JSON.stringify(body) })
        ).json()) as { provider: string; model: string };

      expect(await patch({ provider: "meta-api" })).toMatchObject({ provider: "meta-api", model: "muse-spark-1.3" });
      expect(await patch({ provider: "builtin" })).toMatchObject({ provider: "builtin", model: "muse-glimmer:30b" });
      expect(await patch({ provider: "meta-api", model: "muse-spark-1.2" })).toMatchObject({ model: "muse-spark-1.2" });
      // Same provider, no model: keep what the user chose.
      expect(await patch({ provider: "meta-api", effort: "deep" })).toMatchObject({ model: "muse-spark-1.2" });
    } finally {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // best effort
      }
    }
  });
});
