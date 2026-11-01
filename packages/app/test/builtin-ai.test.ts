import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resolveBuiltinModel } from "../src/model-resolver.js";
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
    expect(BUILTIN_AI_STATUS_CHANNEL).toBe("openvault:builtin-ai-status");
    expect(START_BUILTIN_AI_DOWNLOAD_CHANNEL).toBe("openvault:start-builtin-ai-download");
    expect(CANCEL_BUILTIN_AI_DOWNLOAD_CHANNEL).toBe("openvault:cancel-builtin-ai-download");
    expect(BUILTIN_AI_PROGRESS_CHANNEL).toBe("openvault:builtin-ai-progress");
  });

  it("reports 'missing' when neither bundled nor cached model exists", () => {
    const status = resolveBuiltinModel(resourcesDir, userDataDir);
    expect(status.state).toBe("missing");
    expect(status.path).toBeNull();
    expect(status.requiredBytes).toBeGreaterThan(500_000_000);
  });

  it("detects bundled model in resources/ (Baked-in Complete Edition)", () => {
    const bundledDir = join(resourcesDir, "models", "llama-3.2-1b-int4");
    mkdirSync(bundledDir, { recursive: true });
    writeFileSync(join(bundledDir, "model.onnx"), "dummy-weights");
    writeFileSync(join(bundledDir, "tokenizer.json"), "{}");

    const status = resolveBuiltinModel(resourcesDir, userDataDir);
    expect(status.state).toBe("bundled");
    expect(status.path).toBe(bundledDir);
  });

  it("detects cached model in userData/ (Standard Edition after lazy download)", () => {
    const cachedDir = join(userDataDir, "models", "llama-3.2-1b-int4");
    mkdirSync(cachedDir, { recursive: true });
    writeFileSync(join(cachedDir, "model.onnx"), "dummy-weights");
    writeFileSync(join(cachedDir, "tokenizer.json"), "{}");

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
});
