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
// calls the user's own local endpoint over HTTP. A fake Ollama (or
// OpenAI-compatible) server stands in for the model and returns a high-risk
// decision; the request must stop for a human and the audit must carry the
// model's own explanation. With no reachable warden the daemon must fail
// closed to the human, and the Meta API must never be called.

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
    const openAiStyle = (req.url ?? "").endsWith("/chat/completions");
    let raw = "";
    req.on("data", (chunk: Buffer) => {
      raw += chunk.toString("utf8");
    });
    req.on("end", () => {
      calls.push({ path: req.url ?? "", body: JSON.parse(raw === "" ? "{}" : raw) as OllamaCall["body"] });
      res.writeHead(200, { "content-type": "application/json" });
      const decision = JSON.stringify({
        risk: "high",
        recommendedScope: "charges.read",
        requireApproval: true,
        explanation: SENTINEL,
      });
      if (openAiStyle) {
        res.end(JSON.stringify({ choices: [{ message: { role: "assistant", content: decision } }] }));
        return;
      }
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

const REQUEST_BODY = JSON.stringify({
  agentId: "cursor",
  ide: "Cursor",
  tool: "http",
  alias: "stripe",
  requestedScope: "charges.read",
  reason: "list charges",
});

interface Harness {
  readonly base: string;
  readonly auth: Record<string, string>;
  readonly dir: string;
  readonly patch: (body: unknown) => Promise<Response>;
  readonly request: () => Promise<{ status: string }>;
  readonly audit: () => Promise<string>;
}

async function startHarness(): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), "metavault-brain-"));
  const dbPath = join(dir, "metavault.db");
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
  return {
    base,
    auth,
    dir,
    patch: (body) => fetch(`${base}/settings/warden`, { method: "PATCH", headers: auth, body: JSON.stringify(body) }),
    request: async () => {
      const res = await fetch(`${base}/request`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: REQUEST_BODY,
      });
      expect(res.status).toBe(200);
      return (await res.json()) as { status: string };
    },
    audit: async () => (await fetch(`${base}/audit`, { headers: auth })).text(),
  };
}

function cleanup(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    // best effort: the sqlite handle may still be open on Windows
  }
}

// Wraps fetch so the test can prove which hosts the daemon contacted.
function recordFetchUrls(): string[] {
  const urls: string[] = [];
  const realFetch = globalThis.fetch;
  vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    urls.push(url);
    return realFetch(input, init);
  });
  return urls;
}

async function closedPort(): Promise<number> {
  const probe = createServer();
  await listen(probe);
  const port = portOf(probe);
  await closeServer(probe);
  return port;
}

describe("daemon warden path with no injected brain", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("calls your local Ollama endpoint and lets the model's decision gate the request", async () => {
    const calls: OllamaCall[] = [];
    const ollama = await startFakeOllama(calls);
    const h = await startHarness();
    try {
      const settings = (await (await fetch(`${h.base}/settings/warden`, { headers: h.auth })).json()) as Record<string, unknown>;
      // Out-of-box default is Muse Spark on the Meta API, with no local endpoint.
      expect(settings).toMatchObject({ provider: "meta-api", model: "muse-spark-1.3", localBaseUrl: "", localModel: "" });

      const switched = await h.patch({
        provider: "local",
        localBaseUrl: `http://127.0.0.1:${String(portOf(ollama))}`,
        localApi: "ollama",
        localModel: "muse-glimmer:30b",
      });
      expect(switched.status).toBe(200);
      expect(await switched.json()).toMatchObject({ provider: "local", model: "muse-spark-1.3", localModel: "muse-glimmer:30b" });

      const body = await h.request();
      expect(body.status).toBe("awaiting-approval");

      expect(calls).toHaveLength(1);
      expect(calls[0]?.path).toBe("/api/chat");
      expect(calls[0]?.body.model).toBe("muse-glimmer:30b");
      expect(calls[0]?.body.format).toBe("json");
      expect(JSON.stringify(calls[0]?.body.messages)).toContain("charges.read");
      expect(JSON.stringify(calls[0]?.body)).not.toContain("sk-test-brain-path");

      const auditText = await h.audit();
      expect(auditText).toContain(SENTINEL);
      expect(auditText).toContain("muse-glimmer:30b");
      expect(auditText).not.toContain("sk-test-brain-path");
    } finally {
      cleanup(h.dir);
    }
  });

  it("calls an OpenAI-compatible endpoint at {base}/chat/completions", async () => {
    const calls: OllamaCall[] = [];
    const server = await startFakeOllama(calls);
    const h = await startHarness();
    try {
      const switched = await h.patch({
        provider: "local",
        localBaseUrl: `http://127.0.0.1:${String(portOf(server))}/v1/`,
        localApi: "openai",
        localModel: "muse-glimmer",
      });
      expect(switched.status).toBe(200);
      expect((await h.request()).status).toBe("awaiting-approval");
      expect(calls).toHaveLength(1);
      expect(calls[0]?.path).toBe("/v1/chat/completions");
      expect(calls[0]?.body.model).toBe("muse-glimmer");
      expect(await h.audit()).toContain(SENTINEL);
    } finally {
      cleanup(h.dir);
    }
  });

  it("fails closed to the human with the default Meta API and no key, without calling the Meta API", async () => {
    const h = await startHarness();
    const urls = recordFetchUrls();
    try {
      expect((await h.request()).status).toBe("awaiting-approval");
      expect(urls.some((u) => u.includes("meta.ai"))).toBe(false);
      expect(urls.every((u) => u.startsWith("http://127.0.0.1:"))).toBe(true);
    } finally {
      cleanup(h.dir);
    }
  });

  it("fails closed to the human when the local provider has no endpoint configured", async () => {
    const h = await startHarness();
    const urls = recordFetchUrls();
    try {
      expect((await h.patch({ provider: "local" })).status).toBe(200);
      expect((await h.request()).status).toBe("awaiting-approval");
      // Only the test's own calls to the daemon: no model endpoint was tried.
      expect(urls.every((u) => u.startsWith(h.base))).toBe(true);
    } finally {
      cleanup(h.dir);
    }
  });

  it("fails closed to the human when the local endpoint is unreachable", async () => {
    const port = await closedPort();
    const h = await startHarness();
    try {
      expect(
        (await h.patch({ provider: "local", localBaseUrl: `http://127.0.0.1:${String(port)}`, localModel: "muse-glimmer:30b" })).status,
      ).toBe(200);
      expect((await h.request()).status).toBe("awaiting-approval");
    } finally {
      cleanup(h.dir);
    }
  });

  it("fails closed to the human in BFT mode with no key and no local endpoint", async () => {
    const h = await startHarness();
    const urls = recordFetchUrls();
    try {
      expect((await h.patch({ provider: "bft" })).status).toBe(200);
      expect((await h.request()).status).toBe("awaiting-approval");
      expect(urls.some((u) => u.includes("meta.ai"))).toBe(false);
    } finally {
      cleanup(h.dir);
    }
  });

  it("keeps the Meta API model and the local model separate, and maps legacy providers to local", async () => {
    const h = await startHarness();
    const patch = async (body: unknown) => (await (await h.patch(body)).json()) as Record<string, unknown>;
    try {
      expect(await patch({ provider: "meta-api" })).toMatchObject({ provider: "meta-api", model: "muse-spark-1.3" });
      expect(await patch({ provider: "local", localModel: "muse-glimmer:30b" })).toMatchObject({
        provider: "local",
        model: "muse-spark-1.3",
        localModel: "muse-glimmer:30b",
      });
      expect(await patch({ provider: "ollama" })).toMatchObject({ provider: "local", localModel: "muse-glimmer:30b" });
      expect(await patch({ provider: "builtin" })).toMatchObject({ provider: "local" });
      expect(await patch({ provider: "meta-api", model: "muse-spark-1.2" })).toMatchObject({ model: "muse-spark-1.2", localModel: "muse-glimmer:30b" });
      expect(await patch({ provider: "meta-api", effort: "deep" })).toMatchObject({ model: "muse-spark-1.2" });
      expect(await patch({ localBaseUrl: "" })).toMatchObject({ localBaseUrl: "" });
    } finally {
      cleanup(h.dir);
    }
  });

  it("rejects a local base URL that is not http(s) or carries credentials", async () => {
    const h = await startHarness();
    try {
      for (const bad of ["file:///etc/passwd", "not a url", "http://user:pw@localhost:11434"]) {
        expect((await h.patch({ localBaseUrl: bad })).status).toBe(400);
      }
      expect((await h.patch({ localApi: "grpc" })).status).toBe(400);
    } finally {
      cleanup(h.dir);
    }
  });
});
