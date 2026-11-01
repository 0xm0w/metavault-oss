import { Effect } from "effect";
import { MarshalInvalidOutput, MarshalUnavailable } from "../../core/src/errors.js";
import type { MarshalDecision } from "../../core/src/types.js";

export const DEFAULT_BUILTIN_MODEL = "llama3.2:1b";

export interface BuiltinModelInfo {
  readonly id: string;
  readonly label: string;
  readonly diskSize: string;
  readonly vramRequired: string;
}

export const BUILTIN_MODELS: readonly BuiltinModelInfo[] = [
  {
    id: "llama3.2:1b",
    label: "Llama 3.2 1B Instruct (INT4 WebGPU)",
    diskSize: "680 MB",
    vramRequired: "750 MB",
  },
  {
    id: "llama3.2:3b",
    label: "Llama 3.2 3B Instruct (INT4 WebGPU)",
    diskSize: "1.85 GB",
    vramRequired: "2.1 GB",
  },
];

export type BuiltinInferenceHandler = (
  model: string,
  prompt: string,
  timeoutMs: number,
) => Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput>;

let registeredHandler: BuiltinInferenceHandler | null = null;

export function setBuiltinInferenceHandler(handler: BuiltinInferenceHandler | null): void {
  registeredHandler = handler;
}

export function getBuiltinInferenceHandler(): BuiltinInferenceHandler | null {
  return registeredHandler;
}

export function requestBuiltinDecision(
  model: string,
  prompt: string,
  timeoutMs: number = 30_000,
): Effect.Effect<MarshalDecision, MarshalUnavailable | MarshalInvalidOutput> {
  if (registeredHandler === null) {
    return Effect.fail(
      new MarshalUnavailable({
        message: "MarshalUnavailable: built-in AI engine not initialized or model not downloaded",
      }),
    );
  }
  return registeredHandler(model, prompt, timeoutMs);
}
