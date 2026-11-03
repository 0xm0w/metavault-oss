import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  BUILTIN_MODEL_DIR_NAME,
  BUILTIN_MODEL_ID,
  BUILTIN_MODEL_REQUIRED_BYTES,
  OLLAMA_MARKER_FILE,
} from "./model-resolver.js";

export const BUILTIN_AI_STATUS_CHANNEL = "metavault:builtin-ai-status";
export const START_BUILTIN_AI_DOWNLOAD_CHANNEL = "metavault:start-builtin-ai-download";
export const CANCEL_BUILTIN_AI_DOWNLOAD_CHANNEL = "metavault:cancel-builtin-ai-download";
export const BUILTIN_AI_PROGRESS_CHANNEL = "metavault:builtin-ai-progress";

export interface DownloadProgressPayload {
  readonly state: "idle" | "downloading" | "verifying" | "completed" | "error" | "cancelled";
  readonly percent: number;
  readonly downloadedBytes: number;
  readonly totalBytes: number;
  readonly speedBytesPerSec: number;
  readonly error?: string;
}

export type ProgressListener = (payload: DownloadProgressPayload) => void;

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export function ollamaBaseUrl(): string {
  const raw = process.env["METAVAULT_OLLAMA_URL"]?.trim();
  return raw !== undefined && raw !== "" ? raw.replace(/\/+$/, "") : "http://localhost:11434";
}

interface OllamaPullLine {
  readonly status?: string;
  readonly digest?: string;
  readonly total?: number;
  readonly completed?: number;
  readonly error?: string;
}

/**
 * Streams `POST /api/pull` (NDJSON) for the model and reports aggregate
 * progress across layers. Resolves on `status: "success"`, rejects on an
 * `error` line or a non-2xx response.
 */
export async function pullOllamaModel(
  fetchImpl: FetchLike,
  baseUrl: string,
  model: string,
  onProgress: (completed: number, total: number) => void,
  signal: AbortSignal,
): Promise<void> {
  const res = await fetchImpl(`${baseUrl}/api/pull`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model, stream: true }),
    signal,
  });
  if (!res.ok || res.body === null) {
    throw new Error(`Ollama pull failed: HTTP ${String(res.status)} (is Ollama 0.32.7+ running at ${baseUrl}?)`);
  }
  const layers = new Map<string, { total: number; completed: number }>();
  const decoder = new TextDecoder();
  const reader = res.body.getReader();
  let buffered = "";
  let succeeded = false;
  // Returns true when the line is Ollama's final `status: "success"`.
  const handle = (line: string): boolean => {
    if (line.trim() === "") return false;
    const msg = JSON.parse(line) as OllamaPullLine;
    if (msg.error !== undefined) throw new Error(`Ollama pull failed: ${msg.error}`);
    if (msg.digest !== undefined && typeof msg.total === "number") {
      layers.set(msg.digest, { total: msg.total, completed: msg.completed ?? 0 });
      let total = 0;
      let completed = 0;
      for (const layer of layers.values()) {
        total += layer.total;
        completed += layer.completed;
      }
      onProgress(completed, total);
    }
    return msg.status === "success";
  };
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffered += decoder.decode(value, { stream: true });
    let nl = buffered.indexOf("\n");
    while (nl !== -1) {
      if (handle(buffered.slice(0, nl))) succeeded = true;
      buffered = buffered.slice(nl + 1);
      nl = buffered.indexOf("\n");
    }
  }
  if (handle(buffered)) succeeded = true;
  if (!succeeded) throw new Error("Ollama pull ended without success");
}

export class ModelDownloader {
  private abortController: AbortController | null = null;
  private currentPayload: DownloadProgressPayload = {
    state: "idle",
    percent: 0,
    downloadedBytes: 0,
    totalBytes: BUILTIN_MODEL_REQUIRED_BYTES,
    speedBytesPerSec: 0,
  };

  constructor(
    private readonly targetBaseDir: string,
    private readonly listener?: ProgressListener,
    private readonly fetchImpl: FetchLike = (input, init) => fetch(input, init),
  ) {}

  public getStatus(): DownloadProgressPayload {
    return this.currentPayload;
  }

  private update(partial: Partial<DownloadProgressPayload>): void {
    this.currentPayload = { ...this.currentPayload, ...partial };
    if (this.listener) {
      this.listener(this.currentPayload);
    }
  }

  public cancel(): void {
    if (this.abortController !== null) {
      this.abortController.abort();
      this.abortController = null;
    }
    this.update({ state: "cancelled", speedBytesPerSec: 0 });
  }

  public async download(
    mockStreamProvider?: (
      onChunk: (chunkLength: number) => void,
      signal: AbortSignal,
    ) => Promise<void>,
  ): Promise<boolean> {
    if (this.currentPayload.state === "downloading") {
      return false;
    }

    const modelDir = join(this.targetBaseDir, "models", BUILTIN_MODEL_DIR_NAME);
    mkdirSync(modelDir, { recursive: true });

    this.abortController = new AbortController();
    const signal = this.abortController.signal;

    this.update({
      state: "downloading",
      percent: 0,
      downloadedBytes: 0,
      totalBytes: BUILTIN_MODEL_REQUIRED_BYTES,
      speedBytesPerSec: 0,
    });

    const startTime = Date.now();
    let downloaded = 0;

    try {
      if (mockStreamProvider) {
        await mockStreamProvider((chunkLength) => {
          if (signal.aborted) throw new Error("Download aborted");
          downloaded += chunkLength;
          const elapsedSec = Math.max(0.001, (Date.now() - startTime) / 1000);
          const percent = Math.min(100, Math.round((downloaded / BUILTIN_MODEL_REQUIRED_BYTES) * 100));
          this.update({
            percent,
            downloadedBytes: downloaded,
            speedBytesPerSec: Math.round(downloaded / elapsedSec),
          });
        }, signal);
      } else {
        await pullOllamaModel(
          this.fetchImpl,
          ollamaBaseUrl(),
          BUILTIN_MODEL_ID,
          (completed, total) => {
            if (signal.aborted) throw new Error("Download aborted");
            downloaded = completed;
            const elapsedSec = Math.max(0.001, (Date.now() - startTime) / 1000);
            this.update({
              percent: total > 0 ? Math.min(100, Math.round((completed / total) * 100)) : 0,
              downloadedBytes: completed,
              totalBytes: total,
              speedBytesPerSec: Math.round(completed / elapsedSec),
            });
          },
          signal,
        );
      }

      writeFileSync(
        join(modelDir, OLLAMA_MARKER_FILE),
        JSON.stringify({ model: BUILTIN_MODEL_ID, runtime: "ollama", pulledAt: new Date().toISOString() }),
      );

      this.update({
        state: "completed",
        percent: 100,
        downloadedBytes: Math.max(downloaded, this.currentPayload.downloadedBytes),
        speedBytesPerSec: 0,
      });
      return true;
    } catch (err) {
      if (signal.aborted) {
        this.update({ state: "cancelled", speedBytesPerSec: 0 });
        try {
          rmSync(modelDir, { recursive: true, force: true });
        } catch {
          // Ignore cleanup errors
        }
        return false;
      }
      const msg = err instanceof Error ? err.message : String(err);
      this.update({ state: "error", error: msg, speedBytesPerSec: 0 });
      return false;
    } finally {
      this.abortController = null;
    }
  }
}
