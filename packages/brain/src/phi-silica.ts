import { Effect } from "effect";
import { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
import type { MarshalDecision } from "../../core/src/types.js";

export const DEFAULT_PHI_SILICA_MODEL = "microsoft:phi-silica";

export interface PhiSilicaModelInfo {
  readonly id: string;
  readonly label: string;
  readonly provider: "microsoft";
  readonly architecture: string;
  readonly hardware: string;
}

export const PHI_SILICA_INFO: PhiSilicaModelInfo = {
  id: DEFAULT_PHI_SILICA_MODEL,
  label: "Microsoft Phi Silica (On-Device NPU)",
  provider: "microsoft",
  architecture: "3.3B Parameter Small Language Model",
  hardware: "Windows 11 Copilot+ NPU (40+ TOPS DirectML)",
};

export type PhiSilicaInferenceHandler = (
  prompt: string,
  timeoutMs: number,
) => Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput>;

let registeredHandler: PhiSilicaInferenceHandler | null = null;

export function setPhiSilicaHandler(handler: PhiSilicaInferenceHandler | null): void {
  registeredHandler = handler;
}

export function getPhiSilicaHandler(): PhiSilicaInferenceHandler | null {
  return registeredHandler;
}

export function isPhiSilicaAvailable(): boolean {
  return registeredHandler !== null;
}

export function requestPhiSilicaDecision(
  prompt: string,
  timeoutMs: number = 30_000,
): Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput> {
  if (registeredHandler === null) {
    return Effect.fail(
      new MarshalUnavailable({
        message:
          "MarshalUnavailable: Microsoft Phi Silica runtime not detected or NPU unavailable",
      }),
    );
  }
  return registeredHandler(prompt, timeoutMs);
}
