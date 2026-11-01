import { existsSync, statSync } from "node:fs";
import { join } from "node:path";

export const BUILTIN_MODEL_DIR_NAME = "llama-3.2-1b-int4";
export const BUILTIN_MODEL_REQUIRED_BYTES = 713_031_680; // ~680 MB
export const REQUIRED_MODEL_FILES = ["model.onnx", "tokenizer.json"] as const;

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
  const modelId = "llama3.2:1b";

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
