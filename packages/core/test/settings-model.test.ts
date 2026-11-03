import { describe, expect, it } from "vitest";
import {
  DEFAULT_META_API_WARDEN_MODEL,
  DEFAULT_WARDEN_SETTINGS,
  SUGGESTED_LOCAL_BASE_URL,
  SUGGESTED_LOCAL_MODEL,
  defaultWardenSettings,
  effectiveWardenModel,
  localEndpointConfigured,
  normalizeWardenProvider,
} from "../src/settings.js";
import { wardenSettingsFromRow } from "../src/storage.js";

describe("default warden settings", () => {
  it("ships Muse Spark on the Meta API, with no local model and no local endpoint", () => {
    expect(DEFAULT_WARDEN_SETTINGS).toEqual({
      provider: "meta-api",
      model: "muse-spark-1.3",
      effort: "standard",
      metaApiBaseUrl: "https://api.meta.ai/v1",
      localBaseUrl: "",
      localApi: "ollama",
      localModel: "",
    });
    expect(DEFAULT_META_API_WARDEN_MODEL).toBe("muse-spark-1.3");
    expect(defaultWardenSettings()).toEqual(DEFAULT_WARDEN_SETTINGS);
    expect(defaultWardenSettings()).not.toBe(DEFAULT_WARDEN_SETTINGS);
  });

  it("suggests a Meta open model and the usual local ports as placeholders only", () => {
    expect(SUGGESTED_LOCAL_MODEL).toBe("muse-glimmer:30b");
    expect(SUGGESTED_LOCAL_BASE_URL).toEqual({ ollama: "http://localhost:11434", openai: "http://localhost:8000/v1" });
    expect(localEndpointConfigured(DEFAULT_WARDEN_SETTINGS)).toBe(false);
  });
});

describe("normalizeWardenProvider", () => {
  it("keeps current providers and maps legacy ollama/builtin to local", () => {
    for (const p of ["none", "meta-api", "local", "bft"] as const) {
      expect(normalizeWardenProvider(p)).toBe(p);
    }
    expect(normalizeWardenProvider("ollama")).toBe("local");
    expect(normalizeWardenProvider("builtin")).toBe("local");
    expect(normalizeWardenProvider("cloud")).toBeNull();
  });
});

describe("local endpoint helpers", () => {
  it("needs both a base URL and a model name", () => {
    expect(localEndpointConfigured({ localBaseUrl: "http://localhost:11434", localModel: "" })).toBe(false);
    expect(localEndpointConfigured({ localBaseUrl: "  ", localModel: "m" })).toBe(false);
    expect(localEndpointConfigured({ localBaseUrl: "http://localhost:11434", localModel: "m" })).toBe(true);
  });

  it("reports the model that will answer for each provider", () => {
    const s = { ...DEFAULT_WARDEN_SETTINGS, localModel: "muse-glimmer:30b" };
    expect(effectiveWardenModel(s)).toBe("muse-spark-1.3");
    expect(effectiveWardenModel({ ...s, provider: "bft" })).toBe("muse-spark-1.3");
    expect(effectiveWardenModel({ ...s, provider: "local" })).toBe("muse-glimmer:30b");
    expect(effectiveWardenModel({ ...s, provider: "none" })).toBe("");
  });
});

describe("wardenSettingsFromRow", () => {
  const base = {
    provider: "meta-api",
    model: "muse-spark-1.3",
    effort: "deep",
    meta_api_base_url: "https://api.meta.ai/v1",
    local_base_url: "",
    local_api: "ollama",
    local_model: "",
  };

  it("reads a current row as-is", () => {
    expect(wardenSettingsFromRow(base)).toEqual({
      provider: "meta-api",
      model: "muse-spark-1.3",
      effort: "deep",
      metaApiBaseUrl: "https://api.meta.ai/v1",
      localBaseUrl: "",
      localApi: "ollama",
      localModel: "",
    });
    expect(wardenSettingsFromRow({ ...base, provider: "local", local_api: "openai", local_base_url: "http://h:8000/v1", local_model: "m" })).toMatchObject({
      provider: "local",
      localApi: "openai",
      localBaseUrl: "http://h:8000/v1",
      localModel: "m",
    });
  });

  it("moves a legacy ollama/builtin row's model into the local fields", () => {
    for (const legacy of ["ollama", "builtin"]) {
      const s = wardenSettingsFromRow({ ...base, provider: legacy, model: "muse-glimmer:30b" });
      expect(s.provider).toBe("local");
      expect(s.localModel).toBe("muse-glimmer:30b");
      expect(s.model).toBe("muse-spark-1.3");
      expect(s.localBaseUrl).toBe("http://localhost:11434");
    }
  });
});
