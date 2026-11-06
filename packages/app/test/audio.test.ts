import { describe, expect, it } from "vitest";
import {
  decideEarconPlayback,
  EARCON_COOLDOWN_MS,
  INITIAL_EARCON_COOLDOWN_STATE,
  isArrivalCue,
  shouldPlayCue,
} from "../src/renderer/audio.js";

describe("Web Audio earcon policy & burst coalescing", () => {
  it("filters cues strictly by soundMode (all / high-risk-only / off)", () => {
    expect(shouldPlayCue("approval-standard", "off")).toBe(false);
    expect(shouldPlayCue("approval-high-risk", "off")).toBe(false);

    expect(shouldPlayCue("approval-standard", "high-risk-only")).toBe(false);
    expect(shouldPlayCue("agent-registration", "high-risk-only")).toBe(false);
    expect(shouldPlayCue("decision-approved", "high-risk-only")).toBe(false);
    expect(shouldPlayCue("approval-high-risk", "high-risk-only")).toBe(true);

    expect(shouldPlayCue("approval-standard", "all")).toBe(true);
    expect(shouldPlayCue("decision-denied", "all")).toBe(true);
    expect(shouldPlayCue("vault-locked", "all")).toBe(true);
  });

  it("coalesces arrival bursts within 2,500ms while allowing high-risk preemption", () => {
    expect(EARCON_COOLDOWN_MS).toBe(2500);
    expect(isArrivalCue("approval-standard")).toBe(true);
    expect(isArrivalCue("decision-approved")).toBe(false);

    const first = decideEarconPlayback("approval-standard", "all", 10_000, INITIAL_EARCON_COOLDOWN_STATE);
    expect(first.play).toBe(true);

    // Duplicate standard arrival within 2.5s is suppressed
    const burst = decideEarconPlayback("approval-standard", "all", 11_000, first.nextState);
    expect(burst.play).toBe(false);

    // Registration arrival within 2.5s is also suppressed
    const regBurst = decideEarconPlayback("agent-registration", "all", 11_500, first.nextState);
    expect(regBurst.play).toBe(false);

    // High-risk arrival preempts standard arrival inside cooldown window!
    const urgent = decideEarconPlayback("approval-high-risk", "all", 11_800, first.nextState);
    expect(urgent.play).toBe(true);

    // Second high-risk within 2.5s of the urgent chime is suppressed
    const urgentRepeat = decideEarconPlayback("approval-high-risk", "all", 12_500, urgent.nextState);
    expect(urgentRepeat.play).toBe(false);

    // Local decision feedback cues are never blocked by arrival cooldown
    const decision = decideEarconPlayback("decision-approved", "all", 12_000, urgent.nextState);
    expect(decision.play).toBe(true);

    // After 2,500ms elapses, standard arrivals play again
    const afterWindow = decideEarconPlayback("approval-standard", "all", 14_301, urgent.nextState);
    expect(afterWindow.play).toBe(true);
  });
});
