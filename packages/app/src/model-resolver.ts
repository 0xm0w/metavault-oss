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

// Optional smaller quant, selectable with METAVAULT_WARDEN_MODEL but not the
// shipped default (the default only changes once measured eval numbers exist).
// https://huggingface.co/unsloth/Muse-Glimmer-30B-GGUF/blob/main/Muse-Glimmer-30B-UD-IQ3_XXS.gguf
export const IQ3_XXS_MODEL_ID = "hf.co/unsloth/Muse-Glimmer-30B-GGUF:UD-IQ3_XXS";
export const IQ3_XXS_REQUIRED_BYTES = 13_130_658_848;

const MODEL_TAG_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/;

export interface BuiltinModelChoice {
  readonly modelId: string;
  readonly dirName: string;
  readonly requiredBytes: number;
}

// Mirrors resolveDefaultWardenModel in packages/core/src/settings.ts (the
// app cannot import core). Unknown tags still work; their size is unknown
// until Ollama reports it during the pull, so 0 is used.
export function configuredBuiltinModel(env: NodeJS.ProcessEnv = process.env): BuiltinModelChoice {
  const raw = env["METAVAULT_WARDEN_MODEL"]?.trim();
  const modelId = raw !== undefined && MODEL_TAG_PATTERN.test(raw) && !raw.includes("..") ? raw : BUILTIN_MODEL_ID;
  if (modelId === BUILTIN_MODEL_ID) {
    return { modelId, dirName: BUILTIN_MODEL_DIR_NAME, requiredBytes: BUILTIN_MODEL_REQUIRED_BYTES };
  }
  const dirName = modelId.toLowerCase().replace(/[^a-z0-9._-]+/g, "-");
  return { modelId, dirName, requiredBytes: modelId === IQ3_XXS_MODEL_ID ? IQ3_XXS_REQUIRED_BYTES : 0 };
}
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
  choice: BuiltinModelChoice = configuredBuiltinModel(),
): BuiltinModelStatus {
  const { modelId, dirName } = choice;

  // 1. Check bundled resources (MetaVault Complete / Baked-in Edition)
  if (resourcesDir !== undefined && resourcesDir !== "") {
    const bundledPath = join(resourcesDir, "models", dirName);
    if (isModelComplete(bundledPath)) {
      return {
        state: "bundled",
        modelId,
        path: bundledPath,
        requiredBytes: choice.requiredBytes,
      };
    }
  }

  // 2. Check user data cache (MetaVault Standard Edition after lazy download)
  if (userDataDir !== undefined && userDataDir !== "") {
    const cachedPath = join(userDataDir, "models", dirName);
    if (isModelComplete(cachedPath)) {
      return {
        state: "cached",
        modelId,
        path: cachedPath,
        requiredBytes: choice.requiredBytes,
      };
    }
  }

  return {
    state: "missing",
    modelId,
    path: null,
    requiredBytes: choice.requiredBytes,
  };
}
