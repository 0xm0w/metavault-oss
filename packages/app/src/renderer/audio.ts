import type { SoundCue, SoundModeLike } from "./types.js";

// Synthesized Web Audio earcons for MetaVault OSS. Zero media files are
// bundled or fetched, keeping strict CSP (`default-src 'self'`) intact while
// working cleanly on `--minimized` background boots.

export const EARCON_COOLDOWN_MS = 2500;

export interface EarconCooldownState {
  readonly lastArrivalAtMs: number;
  readonly lastArrivalCue: SoundCue | null;
}

export const INITIAL_EARCON_COOLDOWN_STATE: EarconCooldownState = {
  lastArrivalAtMs: -Infinity,
  lastArrivalCue: null,
};

interface NoteStep {
  readonly freqHz: number;
  readonly startSec: number;
  readonly durationSec: number;
  readonly peakGain: number;
  readonly wave: OscillatorType;
}

const CUE_PATTERNS: Readonly<Record<SoundCue, readonly NoteStep[]>> = {
  "approval-standard": [
    { freqHz: 523.25, startSec: 0, durationSec: 0.09, peakGain: 0.12, wave: "sine" },
    { freqHz: 783.99, startSec: 0.09, durationSec: 0.09, peakGain: 0.12, wave: "triangle" },
  ],
  "approval-high-risk": [
    { freqHz: 440, startSec: 0, durationSec: 0.09, peakGain: 0.18, wave: "triangle" },
    { freqHz: 587.33, startSec: 0.09, durationSec: 0.09, peakGain: 0.18, wave: "triangle" },
    { freqHz: 880, startSec: 0.18, durationSec: 0.1, peakGain: 0.18, wave: "triangle" },
  ],
  "agent-registration": [
    { freqHz: 659.25, startSec: 0, durationSec: 0.08, peakGain: 0.12, wave: "sine" },
    { freqHz: 987.77, startSec: 0.08, durationSec: 0.08, peakGain: 0.12, wave: "sine" },
  ],
  "decision-approved": [
    { freqHz: 880, startSec: 0, durationSec: 0.06, peakGain: 0.06, wave: "sine" },
  ],
  "decision-denied": [
    { freqHz: 261.63, startSec: 0, durationSec: 0.08, peakGain: 0.07, wave: "triangle" },
  ],
  "vault-locked": [
    { freqHz: 587.33, startSec: 0, durationSec: 0.055, peakGain: 0.08, wave: "sine" },
    { freqHz: 392, startSec: 0.055, durationSec: 0.055, peakGain: 0.08, wave: "sine" },
  ],
};

export function isArrivalCue(cue: SoundCue): boolean {
  return cue === "approval-standard" || cue === "approval-high-risk" || cue === "agent-registration";
}

export function shouldPlayCue(cue: SoundCue, soundMode: SoundModeLike): boolean {
  if (soundMode === "off") return false;
  if (soundMode === "high-risk-only") return cue === "approval-high-risk";
  return true;
}

// Coalesces background arrival bursts across a 2.5s window so parallel agent
// tool calls do not machine-gun the speakers, while still allowing a high-risk
// arrival cue to preempt a non-high-risk arrival cue inside the window.
export function decideEarconPlayback(
  cue: SoundCue,
  soundMode: SoundModeLike,
  nowMs: number,
  state: EarconCooldownState,
): { readonly play: boolean; readonly nextState: EarconCooldownState } {
  if (!shouldPlayCue(cue, soundMode)) {
    return { play: false, nextState: state };
  }
  if (!isArrivalCue(cue)) {
    return { play: true, nextState: state };
  }
  const withinCooldown = nowMs - state.lastArrivalAtMs < EARCON_COOLDOWN_MS;
  if (withinCooldown) {
    const canPreempt = cue === "approval-high-risk" && state.lastArrivalCue !== "approval-high-risk";
    if (!canPreempt) {
      return { play: false, nextState: state };
    }
  }
  return {
    play: true,
    nextState: {
      lastArrivalAtMs: nowMs,
      lastArrivalCue: cue,
    },
  };
}

let sharedContext: AudioContext | null = null;
let liveCooldownState: EarconCooldownState = INITIAL_EARCON_COOLDOWN_STATE;

export function resetEarconCooldown(): void {
  liveCooldownState = INITIAL_EARCON_COOLDOWN_STATE;
}

function getAudioContext(): AudioContext | null {
  if (typeof window === "undefined") return null;
  if (sharedContext !== null && sharedContext.state !== "closed") {
    return sharedContext;
  }
  const Ctor =
    typeof window.AudioContext === "function"
      ? window.AudioContext
      : (window as unknown as { readonly webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (typeof Ctor !== "function") return null;
  try {
    sharedContext = new Ctor();
    return sharedContext;
  } catch {
    return null;
  }
}

function synthesizeCue(ctx: AudioContext, cue: SoundCue): void {
  const steps = CUE_PATTERNS[cue];
  const baseTime = ctx.currentTime + 0.005;
  const floorGain = 0.0001;
  for (const step of steps) {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = step.wave;
    osc.frequency.setValueAtTime(step.freqHz, baseTime + step.startSec);

    const noteStart = baseTime + step.startSec;
    const attackEnd = noteStart + Math.min(0.012, step.durationSec * 0.25);
    const noteEnd = noteStart + step.durationSec;

    gain.gain.setValueAtTime(floorGain, noteStart);
    gain.gain.exponentialRampToValueAtTime(Math.max(floorGain, step.peakGain), attackEnd);
    gain.gain.exponentialRampToValueAtTime(floorGain, noteEnd);

    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start(noteStart);
    osc.stop(noteEnd + 0.005);
  }
}

export function playEarcon(
  cue: SoundCue,
  soundMode: SoundModeLike = "all",
  nowMs: number = Date.now(),
): boolean {
  const decision = decideEarconPlayback(cue, soundMode, nowMs, liveCooldownState);
  liveCooldownState = decision.nextState;
  if (!decision.play) return false;

  const ctx = getAudioContext();
  if (ctx === null) return false;
  if (ctx.state === "suspended") {
    void ctx.resume().then(
      () => {
        synthesizeCue(ctx, cue);
      },
      () => undefined,
    );
    return true;
  }
  synthesizeCue(ctx, cue);
  return true;
}

export function previewEarcon(soundMode: SoundModeLike): void {
  const cue: SoundCue = soundMode === "high-risk-only" ? "approval-high-risk" : "approval-standard";
  const ctx = getAudioContext();
  if (ctx === null) return;
  if (ctx.state === "suspended") {
    void ctx.resume().then(
      () => {
        synthesizeCue(ctx, cue);
      },
      () => undefined,
    );
    return;
  }
  synthesizeCue(ctx, cue);
}
