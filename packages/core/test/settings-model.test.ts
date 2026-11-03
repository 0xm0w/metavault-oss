import { describe, expect, it } from "vitest";
import {
  DEFAULT_WARDEN_SETTINGS,
  MUSE_GLIMMER_IQ3_XXS_TAG,
  SHIPPED_DEFAULT_WARDEN_MODEL,
  defaultWardenSettings,
  resolveDefaultWardenModel,
} from "../src/settings.js";

describe("configurable default warden model", () => {
  it("keeps the shipped default unchanged (Q4_K_M) until measured numbers exist", () => {
    expect(SHIPPED_DEFAULT_WARDEN_MODEL).toBe("muse-glimmer:30b");
    expect(DEFAULT_WARDEN_SETTINGS.model).toBe("muse-glimmer:30b");
    expect(resolveDefaultWardenModel({})).toBe("muse-glimmer:30b");
  });

  it("honours METAVAULT_WARDEN_MODEL for the IQ3_XXS tag", () => {
    expect(MUSE_GLIMMER_IQ3_XXS_TAG).toBe("hf.co/unsloth/Muse-Glimmer-30B-GGUF:UD-IQ3_XXS");
    const env = { METAVAULT_WARDEN_MODEL: ` ${MUSE_GLIMMER_IQ3_XXS_TAG} ` };
    expect(resolveDefaultWardenModel(env)).toBe(MUSE_GLIMMER_IQ3_XXS_TAG);
    expect(defaultWardenSettings(env)).toEqual({ ...DEFAULT_WARDEN_SETTINGS, model: MUSE_GLIMMER_IQ3_XXS_TAG });
  });

  it("ignores invalid values and falls back to the shipped default", () => {
    for (const bad of ["", "   ", "a b", "x;rm -rf", "../etc", "-flag", "x".repeat(201)]) {
      expect(resolveDefaultWardenModel({ METAVAULT_WARDEN_MODEL: bad })).toBe("muse-glimmer:30b");
    }
  });
});
