import { Effect } from "effect";
import { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
import type { MarshalDecision } from "../../core/src/types.js";

export const DEFAULT_GEMINI_NANO_MODEL = "google:gemini-nano";

export interface GeminiNanoModelInfo {
  readonly id: string;
  readonly label: string;
  readonly provider: "google";
  readonly architecture: string;
  readonly runtime: string;
}

export const GEMINI_NANO_INFO: GeminiNanoModelInfo = {
  id: DEFAULT_GEMINI_NANO_MODEL,
  label: "Google Gemini Nano (Chrome Built-in AI)",
  provider: "google",
  architecture: "1.8B Parameter Edge SLM",
  runtime: "Chromium Prompt API (window.ai)",
};

export type GeminiNanoInferenceHandler = (
  prompt: string,
  timeoutMs: number,
) => Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput>;

let registeredHandler: GeminiNanoInferenceHandler | null = null;

export function setGeminiNanoHandler(handler: GeminiNanoInferenceHandler | null): void {
  registeredHandler = handler;
}

export function getGeminiNanoHandler(): GeminiNanoInferenceHandler | null {
  return registeredHandler;
}

export function isGeminiNanoAvailable(): boolean {
  return registeredHandler !== null;
}

export function requestGeminiNanoDecision(
  prompt: string,
  timeoutMs: number = 30_000,
): Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput> {
  if (registeredHandler === null) {
    return Effect.fail(
      new MarshalUnavailable({
        message:
          "MarshalUnavailable: Google Gemini Nano bridge not connected or Chrome extension inactive",
      }),
    );
  }
  return registeredHandler(prompt, timeoutMs);
}
