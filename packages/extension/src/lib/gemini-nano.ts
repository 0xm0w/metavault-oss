import type { GeminiDecision } from "./types.js";

export interface ChromeAILanguageModel {
  prompt(text: string): Promise<string>;
  destroy(): void;
}

export interface ChromeAI {
  languageModel?: {
    capabilities(): Promise<{ available: "readily" | "after-download" | "no" }>;
    create(options?: { systemPrompt?: string }): Promise<ChromeAILanguageModel>;
  };
}

declare global {
  interface Window {
    ai?: ChromeAI;
  }
}

export async function isGeminiNanoAvailable(): Promise<boolean> {
  if (typeof window === "undefined" || !window.ai?.languageModel) {
    return false;
  }
  try {
    const caps = await window.ai.languageModel.capabilities();
    return caps.available === "readily";
  } catch {
    return false;
  }
}

export async function evaluateGeminiNano(
  prompt: string,
  systemPrompt: string = "You are the Google Gemini Nano security co-auditor for MetaVault. Analyze the following capability request and return strict JSON.",
): Promise<GeminiDecision> {
  if (typeof window === "undefined" || !window.ai?.languageModel) {
    // Fallback simulation when run outside browser
    return {
      risk: "low",
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "Evaluated by Google Gemini Nano (offline mock)",
    };
  }

  const session = await window.ai.languageModel.create({ systemPrompt });
  try {
    const raw = await session.prompt(prompt);
    const parsed = JSON.parse(raw) as Partial<GeminiDecision>;
    return {
      risk: parsed.risk === "high" || parsed.risk === "medium" ? parsed.risk : "low",
      recommendedScope: typeof parsed.recommendedScope === "string" ? parsed.recommendedScope : "",
      requireApproval: Boolean(parsed.requireApproval),
      explanation: typeof parsed.explanation === "string" ? parsed.explanation : "Approved by Gemini Nano",
    };
  } finally {
    session.destroy();
  }
}
