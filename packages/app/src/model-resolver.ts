import { existsSync, statSync } from "node:fs";
import { join } from "node:path";

// The on-device warden is Meta Muse Glimmer 30B (official Q4_K_M), served by
// local Ollama as `muse-glimmer:30b` (https://ollama.com/library/muse-glimmer).
// Ollama keeps the weights in its own store; MetaVault records a small marker
// file after a successful `ollama pull` so the settings UI can show "ready".
export const BUILTIN_MODEL_ID = "muse-glimmer:30b";
export const BUILTIN_MODEL_DIR_NAME = "muse-glimmer-30b-q4_k_m";
// Size of Muse-Glimmer-30B-KQuant-17GB-Q4_K_M.gguf on
// https://huggingface.co/meta-models/Muse-Glimmer-30B-GGUF (16.76 GB).
// Ollama's 30b tag lists ~18 GB; the live pull reports the exact total.
export const BUILTIN_MODEL_REQUIRED_BYTES = 16_756_683_904;
export const OLLAMA_MARKER_FILE = "ollama-model.json";
export const REQUIRED_MODEL_FILES = [OLLAMA_MARKER_FILE] as const;

export type BuiltinModelState = "bundled" | "cached" | "missing";

export interface BuiltinModelStatus {
  readonly state: BuiltinModelState;
  readonly modelId: string;
  readonly path: string | null;
  readonly requiredBytes: number;
}

export function isModelComplete(dirPath: string): boolean {
  if (!existsSync(dirPath)) return false;
  try {
    for (const file of REQUIRED_MODEL_FILES) {
      const fullPath = join(dirPath, file);
      if (!existsSync(fullPath)) return false;
      const stat = statSync(fullPath);
      if (stat.size === 0) return false;
    }
    return true;
  } catch {
    return false;
  }
}

export function resolveBuiltinModel(
  resourcesDir?: string,
  userDataDir?: string,
): BuiltinModelStatus {
  const modelId = BUILTIN_MODEL_ID;

  // 1. Check bundled resources (MetaVault Complete / Baked-in Edition)
  if (resourcesDir !== undefined && resourcesDir !== "") {
    const bundledPath = join(resourcesDir, "models", BUILTIN_MODEL_DIR_NAME);
    if (isModelComplete(bundledPath)) {
      return {
        state: "bundled",
        modelId,
        path: bundledPath,
        requiredBytes: BUILTIN_MODEL_REQUIRED_BYTES,
      };
    }
  }

  // 2. Check user data cache (MetaVault Standard Edition after lazy download)
  if (userDataDir !== undefined && userDataDir !== "") {
    const cachedPath = join(userDataDir, "models", BUILTIN_MODEL_DIR_NAME);
    if (isModelComplete(cachedPath)) {
      return {
        state: "cached",
        modelId,
        path: cachedPath,
        requiredBytes: BUILTIN_MODEL_REQUIRED_BYTES,
      };
    }
  }

  return {
    state: "missing",
    modelId,
    path: null,
    requiredBytes: BUILTIN_MODEL_REQUIRED_BYTES,
  };
}
