import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  BUILTIN_MODEL_DIR_NAME,
  BUILTIN_MODEL_ID,
  OLLAMA_MARKER_FILE,
  resolveBuiltinModel,
} from "../src/model-resolver.js";
import {
  BUILTIN_AI_PROGRESS_CHANNEL,
  BUILTIN_AI_STATUS_CHANNEL,
  CANCEL_BUILTIN_AI_DOWNLOAD_CHANNEL,
  ModelDownloader,
  START_BUILTIN_AI_DOWNLOAD_CHANNEL,
} from "../src/model-downloader.js";

describe("Built-in AI Model Resolver & Downloader Specifications", () => {
  let testRoot: string;
  let resourcesDir: string;
  let userDataDir: string;

  beforeEach(() => {
    testRoot = join(tmpdir(), "meta-vault-builtin-ai-test-" + Math.random().toString(36).slice(2));
    resourcesDir = join(testRoot, "resources");
    userDataDir = join(testRoot, "userData");
    mkdirSync(resourcesDir, { recursive: true });
    mkdirSync(userDataDir, { recursive: true });
  });

  afterEach(() => {
    try {
      rmSync(testRoot, { recursive: true, force: true });
    } catch {
      // Ignored
    }
  });

  it("defines standard IPC channels for built-in AI", () => {
    expect(BUILTIN_AI_STATUS_CHANNEL).toBe("metavault:builtin-ai-status");
    expect(START_BUILTIN_AI_DOWNLOAD_CHANNEL).toBe("metavault:start-builtin-ai-download");
    expect(CANCEL_BUILTIN_AI_DOWNLOAD_CHANNEL).toBe("metavault:cancel-builtin-ai-download");
    expect(BUILTIN_AI_PROGRESS_CHANNEL).toBe("metavault:builtin-ai-progress");
  });

  it("reports 'missing' when neither bundled nor cached model exists", () => {
    const status = resolveBuiltinModel(resourcesDir, userDataDir);
    expect(status.state).toBe("missing");
    expect(status.path).toBeNull();
    expect(status.modelId).toBe("muse-glimmer:30b");
    expect(status.requiredBytes).toBe(16_756_683_904);
  });

  it("detects bundled model in resources/ (Baked-in Complete Edition)", () => {
    const bundledDir = join(resourcesDir, "models", BUILTIN_MODEL_DIR_NAME);
    mkdirSync(bundledDir, { recursive: true });
    writeFileSync(join(bundledDir, OLLAMA_MARKER_FILE), '{"model":"muse-glimmer:30b"}');

    const status = resolveBuiltinModel(resourcesDir, userDataDir);
    expect(status.state).toBe("bundled");
    expect(status.path).toBe(bundledDir);
  });

  it("detects cached model in userData/ (Standard Edition after lazy download)", () => {
    const cachedDir = join(userDataDir, "models", BUILTIN_MODEL_DIR_NAME);
    mkdirSync(cachedDir, { recursive: true });
    writeFileSync(join(cachedDir, OLLAMA_MARKER_FILE), '{"model":"muse-glimmer:30b"}');

    const status = resolveBuiltinModel(resourcesDir, userDataDir);
    expect(status.state).toBe("cached");
    expect(status.path).toBe(cachedDir);
  });

  it("handles chunked download streaming and emits progress callbacks", async () => {
    const events: number[] = [];
    const downloader = new ModelDownloader(userDataDir, (p) => {
      events.push(p.percent);
    });

    const success = await downloader.download((onChunk) => {
      onChunk(100_000_000);
      onChunk(300_000_000);
      onChunk(313_031_680);
      return Promise.resolve();
    });

    expect(success).toBe(true);
    expect(events.length).toBeGreaterThanOrEqual(3);
    expect(downloader.getStatus().state).toBe("completed");
    expect(downloader.getStatus().percent).toBe(100);
  });

  it("handles cancellation gracefully during download", async () => {
    const downloader = new ModelDownloader(userDataDir);
    const downloadPromise = downloader.download((onChunk, signal) => {
      onChunk(50_000_000);
      downloader.cancel();
      if (signal.aborted) return Promise.reject(new Error("Aborted"));
      return Promise.resolve();
    });

    const success = await downloadPromise;
    expect(success).toBe(false);
    expect(downloader.getStatus().state).toBe("cancelled");
  });

  it("pulls muse-glimmer:30b through Ollama /api/pull, reports progress and marks the model ready", async () => {
    const lines = [
      { status: "pulling manifest" },
      { status: "pulling a", digest: "sha256:a", total: 1000, completed: 0 },
      { status: "pulling a", digest: "sha256:a", total: 1000, completed: 500 },
      { status: "pulling b", digest: "sha256:b", total: 1000, completed: 1000 },
      { status: "pulling a", digest: "sha256:a", total: 1000, completed: 1000 },
      { status: "verifying sha256 digest" },
      { status: "success" },
    ];
    const ndjson = lines.map((l) => JSON.stringify(l)).join("\n") + "\n";
    const calls: { url: string; body: unknown }[] = [];
    const fetchImpl = (url: string, init?: RequestInit): Promise<Response> => {
      calls.push({ url, body: JSON.parse(typeof init?.body === "string" ? init.body : "null") as unknown });
      return Promise.resolve(new Response(ndjson, { status: 200 }));
    };
    const percents: number[] = [];
    const downloader = new ModelDownloader(userDataDir, (p) => percents.push(p.percent), fetchImpl);

    expect(await downloader.download()).toBe(true);
    expect(calls).toEqual([{ url: "http://localhost:11434/api/pull", body: { model: BUILTIN_MODEL_ID, stream: true } }]);
    expect(percents).toEqual([0, 0, 50, 75, 100, 100]);
    expect(downloader.getStatus()).toMatchObject({ state: "completed", percent: 100, totalBytes: 2000 });
    expect(resolveBuiltinModel(resourcesDir, userDataDir).state).toBe("cached");
  });

  it("reports an Ollama pull error and does not mark the model ready", async () => {
    const fetchImpl = (): Promise<Response> =>
      Promise.resolve(new Response(JSON.stringify({ error: "pull model manifest: file does not exist" }) + "\n", { status: 200 }));
    const downloader = new ModelDownloader(userDataDir, undefined, fetchImpl);
    expect(await downloader.download()).toBe(false);
    expect(downloader.getStatus().state).toBe("error");
    expect(downloader.getStatus().error).toContain("file does not exist");
    expect(resolveBuiltinModel(resourcesDir, userDataDir).state).toBe("missing");
  });

  it("reports an error when Ollama is not running", async () => {
    const fetchImpl = (): Promise<Response> => Promise.reject(new Error("fetch failed: ECONNREFUSED"));
    const downloader = new ModelDownloader(userDataDir, undefined, fetchImpl);
    expect(await downloader.download()).toBe(false);
    expect(downloader.getStatus().error).toContain("ECONNREFUSED");
  });
});
