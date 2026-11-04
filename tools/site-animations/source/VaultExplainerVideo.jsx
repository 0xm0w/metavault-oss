import React, { useState, useEffect, useRef } from 'react';
import './restyle.css';

// Vault Explainer Video — Muse Spark Warden (updated)
// Changes vs original:
//  - Canvas height 540px -> 620px; SVG viewBox 800x620 with preserveAspectRatio="none"
//    (SVG and IDE icons now share one percent-based grid: lines/icons never misalign).
//  - IDE icons absolutely positioned at left = getIdeX(i)/800*100% (translateX(-50%)).
//  - IDE -> Warden line ends at the Warden's top edge (y=160) with an arrowhead; lines
//    no longer run behind the Warden card.
//  - New "Encryption" box (sealed tunnel) between Warden and Vault; dashed bidirectional
//    arrows Warden<->Encryption and Encryption<->Vault (broken lines = no direct link).
//  - Warden / Vault panels anchored at fixed slots (top 165px / bottom 8px).
// Requires React 18 + Tailwind CSS (all class usage is standard utilities/arbitrary values).

const IDES = [
  { id: 'cursor', name: 'Cursor', icon: '⌘', color: '#8629ff' },
  { id: 'claude', name: 'Claude Code', icon: '✦', color: '#fb923c' },
  { id: 'opencode', name: 'OpenCode', icon: '⚡', color: '#a78bfa' },
  { id: 'musecode', name: 'MuseCode', icon: '◈', color: '#f472b6' },
  { id: 'grok', name: 'Grok Terminal', icon: '>_', color: '#e2e8f0' },
  { id: 'codex', name: 'Codex', icon: '{}', color: '#16a34a' },
];

const SCENARIOS = [
  {
    id: 'low',
    ideIndex: 0, // Cursor
    action: 'read:repo_status',
    risk: 'LOW RISK',
    riskLevel: 'low',
    receipt: 'Executed result',
    caption: 'Low-risk, read-only calls from verified agents can run without a prompt when policy allows. Writes and financial requests always ask.',
  },
  {
    id: 'high',
    ideIndex: 1, // Claude Code
    action: 'deploy:prod_cluster',
    risk: 'HIGH RISK',
    riskLevel: 'high',
    receipt: 'Executed result',
    caption: 'High-risk calls pause for your explicit approval in the desktop app.',
  },
];

// Animation stages:
// 0: Idle / IDE initiates request
// 1: Request travels IDE -> Muse Spark (The Warden)
// 2: Muse Spark inspects & rates risk
// 3: (High Risk) User prompt elevation & approval | (Low Risk) Auto-approved badge
// 4: Muse Spark <-> API Keys Vault exchange (Key stays locked, capability executed)
// 5: Signed Receipt returns to IDE (No raw API key exposed)

export default function VaultExplainerVideo() {
  const panRef = useRef(null);
  useEffect(() => { const node=panRef.current; if(!node) return; const center=()=>{node.scrollLeft=(node.scrollWidth-node.clientWidth)/2}; center(); const observer=new ResizeObserver(center); observer.observe(node); return()=>observer.disconnect(); }, []);
  const [scenarioIdx, setScenarioIdx] = useState(0);
  const [stage, setStage] = useState(0);
  const [isPlaying, setIsPlaying] = useState(true);

  const scenario = SCENARIOS[scenarioIdx];
  const activeIde = IDES[scenario.ideIndex];

  useEffect(() => {
    if (!isPlaying || (typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches)) return;

    const stageDurations = [1400, 1600, 1800, 2200, 2000, 2400];
    const timer = setTimeout(() => {
      if (stage < 5) {
        setStage((prev) => prev + 1);
      } else {
        setStage(0);
        setScenarioIdx((prev) => (prev + 1) % SCENARIOS.length);
      }
    }, stageDurations[stage]);

    return () => clearTimeout(timer);
  }, [stage, isPlaying, scenarioIdx]);

  // Calculate SVG X coordinate for active IDE node (evenly spaced across 720px width)
  const getIdeX = (index) => 100 + index * 152;
  const activeX = getIdeX(scenario.ideIndex);

  return (
    <div className="mv-original w-full max-w-4xl mx-auto bg-slate-950 text-slate-100 rounded-2xl border border-slate-800 shadow-2xl overflow-hidden font-sans select-none">
      {/* Top Bar / Video Header */}
      <div className="mv-header flex items-center justify-between px-6 py-4 bg-slate-900/90 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <span className="w-3 h-3 rounded-full bg-rose-500/80" />
          <span className="w-3 h-3 rounded-full bg-amber-500/80" />
          <span className="w-3 h-3 rounded-full bg-emerald-500/80" />
          <span className="ml-3 text-xs font-mono uppercase tracking-widest text-slate-400">
            Zero-Trust Capability Architecture — Muse Spark Warden
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              setScenarioIdx(0);
              setStage(0);
            }}
            className={`px-3 py-1 text-xs font-mono rounded-md transition ${
              scenario.riskLevel === 'low'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                : 'bg-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            Low-Risk Flow
          </button>
          <button
            onClick={() => {
              setScenarioIdx(1);
              setStage(0);
            }}
            className={`px-3 py-1 text-xs font-mono rounded-md transition ${
              scenario.riskLevel === 'high'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                : 'bg-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            High-Risk Flow
          </button>
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className="ml-2 px-3 py-1 text-xs font-mono bg-indigo-600 hover:bg-indigo-500 text-white rounded-md transition"
          >
            {isPlaying ? '⏸ Pause' : '▶ Play'}
          </button>
        </div>
      </div>

      {/* Main Animation Canvas */}
      <div className="mv-pan" ref={panRef} tabIndex={0} aria-label="Architecture diagram, scroll horizontally on a small screen">
      <div className="mv-canvas relative w-full h-[620px] bg-[radial-gradient(#d4d4d8_1px,transparent_1px)] [background-size:20px_20px] flex flex-col items-center justify-between py-8 px-6">

        {/* SVG Routing Layer (Matches Sketch Topology) */}
        <svg
          viewBox="0 0 960 640"
          preserveAspectRatio="none"
          className="absolute inset-0 w-full h-full pointer-events-none"
        >
          <defs>
            <linearGradient id="reqGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#8629ff" />
              <stop offset="100%" stopColor="#8629ff" />
            </linearGradient>
            <linearGradient id="receiptGrad" x1="0" y1="1" x2="0" y2="0">
              <stop offset="0%" stopColor="#16a34a" />
              <stop offset="100%" stopColor="#16a34a" />
            </linearGradient>
          </defs>

          {/* Background Dimmed Paths from All IDEs to Muse Spark */}
          {IDES.map((ide, idx) => {
            const x = getIdeX(idx);
            return (
              <path
                key={ide.id}
                d={`M ${x} 120 L ${x} 140 L 480 140 L 480 165`}
                fill="none"
                stroke="#d4d4d8"
                strokeWidth="2"
                strokeDasharray="4 4"
              />
            );
          })}

          {/* Active Orthogonal Path from Selected IDE to Muse Spark */}
          <path
            d={`M ${activeX} 120 L ${activeX} 140 L 480 140 L 480 165`}
            fill="none"
            stroke={stage === 5 ? 'url(#receiptGrad)' : 'url(#reqGrad)'}
            strokeWidth="3.5"
            className="transition-all duration-500"
            strokeOpacity={stage >= 1 ? 1 : 0.25}
          />
          <polygon
            points="474,157 486,157 480,165"
            fill={stage === 5 ? '#16a34a' : '#8629ff'}
            strokeOpacity={stage >= 1 ? 1 : 0.25}
            fillOpacity={stage >= 1 ? 1 : 0.25}
            className="transition-all duration-500"
          />

          {/* Packet: IDE -> Muse Spark (Stage 1) */}
          {stage === 1 && (
            <circle r="6" fill="#8629ff">
              <animateMotion
                dur="1.4s"
                repeatCount="indefinite"
                path={`M ${activeX} 120 L ${activeX} 140 L 480 140 L 480 165`}
              />
            </circle>
          )}

          {/* Packet: Signed Receipt Returning Muse Spark -> IDE (Stage 5) */}
          {stage === 5 && (
            <circle r="6" fill="#16a34a">
              <animateMotion
                dur="1.5s"
                repeatCount="indefinite"
                path={`M 480 165 L 480 140 L ${activeX} 140 L ${activeX} 120`}
              />
            </circle>
          )}

          {/* Input/Output dashed Arrows: Warden <-> Encryption, Encryption <-> Vault.
              Four explicit arrows, none hidden behind the boxes. */}
          {/* 1. Warden -> Encryption (request sealed) */}
          <path
            d="M 458 309 L 458 341"
            stroke={stage === 4 ? '#a16207' : '#a1a1aa'}
            strokeWidth="3"
            strokeLinecap="round"
            strokeDasharray="6 5"
            className="transition-all duration-500"
          />
          <polygon
            points="452,341 464,341 458,349"
            fill={stage === 4 ? '#a16207' : '#a1a1aa'}
            className="transition-all duration-500"
          />

          {/* 2. Encryption -> Warden (sealed receipt back) */}
          <path
            d="M 502 349 L 502 317"
            stroke={stage >= 4 ? '#16a34a' : '#a1a1aa'}
            strokeWidth="3"
            strokeLinecap="round"
            strokeDasharray="6 5"
            className="transition-all duration-500"
          />
          <polygon
            points="496,317 508,317 502,309"
            fill={stage >= 4 ? '#16a34a' : '#a1a1aa'}
            className="transition-all duration-500"
          />

          {/* 3. Encryption -> Vault (sealed capability executes) */}
          <path
            d="M 458 413 L 458 445"
            stroke={stage === 4 ? '#a16207' : '#a1a1aa'}
            strokeWidth="3"
            strokeLinecap="round"
            strokeDasharray="6 5"
            className="transition-all duration-500"
          />
          <polygon
            points="452,445 464,445 458,453"
            fill={stage === 4 ? '#a16207' : '#a1a1aa'}
            className="transition-all duration-500"
          />

          {/* 4. Vault -> Encryption (sealed result returns) */}
          <path
            d="M 502 453 L 502 421"
            stroke={stage >= 4 ? '#16a34a' : '#a1a1aa'}
            strokeWidth="3"
            strokeLinecap="round"
            strokeDasharray="6 5"
            className="transition-all duration-500"
          />
          <polygon
            points="496,421 508,421 502,413"
            fill={stage >= 4 ? '#16a34a' : '#a1a1aa'}
            className="transition-all duration-500"
          />
        </svg>

        {/* 1. TOP ROW: IDEs / Coding Agents */}
        <div className="absolute inset-x-0 top-2 z-10">
          {IDES.map((ide, idx) => {
            const isActive = idx === scenario.ideIndex;
            return (
              <div
                key={ide.id}
                onClick={() => {
                  setScenarioIdx(idx % 2);
                  setStage(0);
                }}
                style={{ left: `${(getIdeX(idx) / 960) * 100}%`, transform: 'translateX(-50%)' }}
                className={`absolute top-0 flex flex-col items-center cursor-pointer transition-all duration-300 ${
                  isActive ? 'is-active' : 'is-inactive'
                }`}
              >
                <div
                  className={`w-14 h-14 rounded-full flex items-center justify-center text-lg font-mono font-bold border-2 shadow-lg transition-all ${
                    isActive
                      ? 'bg-slate-900 border-sky-400 text-sky-300 shadow-sky-500/20'
                      : 'bg-slate-900/80 border-slate-700 text-slate-400'
                  }`}
                >
                  {ide.icon}
                </div>
                <span className="mt-2 text-xs font-medium tracking-tight text-slate-300">
                  {ide.name}
                </span>

                {/* Call / Receipt Floating Pill */}
                {isActive && stage === 1 && (
                  <span className="absolute -bottom-7 px-2 py-0.5 text-[10px] font-mono bg-sky-500/20 text-sky-300 border border-sky-500/40 rounded-full whitespace-nowrap mv-calm-enter">
                    req: {scenario.action}
                  </span>
                )}
                {isActive && stage === 5 && (
                  <span className="absolute -bottom-7 px-2 py-0.5 text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded-full whitespace-nowrap">
                    ✓ {scenario.receipt}
                  </span>
                )}
              </div>
            );
          })}
        </div>

        {/* 2. MIDDLE LAYER: Muse Spark (The Warden) + User Elevation Side-Card */}
        <div className="absolute inset-x-0 top-[165px] z-10 flex items-start justify-center">
          <div
            className={`mv-warden relative w-72 rounded-xl bg-slate-900/95 border-2 p-4 shadow-2xl transition-all duration-300 ${
              stage === 2 || stage === 3
                ? scenario.riskLevel === 'high'
                  ? 'border-rose-500 shadow-rose-500/20'
                  : 'border-emerald-500 shadow-emerald-500/20'
                : 'border-indigo-500/60 shadow-indigo-500/10'
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-mono uppercase tracking-wider text-indigo-400">
                🛡️ The Warden
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                Advisory review
              </span>
            </div>
            <div className="text-lg font-bold tracking-tight text-white">
              Muse Spark
            </div>

            {/* Dynamic Inspection Readout */}
            <div className="mt-2 pt-2 border-t border-slate-800 text-xs font-mono">
              {stage === 0 && (
                <span className="text-slate-400">Listening for IDE calls...</span>
              )}
              {stage === 1 && (
                <span className="text-sky-300">
                  Intercepting {activeIde.name} call...
                </span>
              )}
              {stage >= 2 && (
                <div className="space-y-1">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Capability:</span>
                    <span className="text-slate-200">{scenario.action}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">Risk Rating:</span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        scenario.riskLevel === 'high'
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                          : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      }`}
                    >
                      {scenario.risk}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* High-Risk Elevation Modal (Appears to the right on Stage 3 when High Risk) */}
          {stage >= 3 && scenario.riskLevel === 'high' && (
            <div className="mv-elevation absolute right-6 w-60 bg-slate-900 border-2 border-amber-500/80 rounded-xl p-3.5 shadow-xl mv-calm-enter">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-amber-300 mb-1">
                <span>⚠️ ELEVATED TO USER</span>
              </div>
              <p className="text-[11px] text-slate-300 leading-snug mb-2.5">
                Allow <strong className="text-white">{activeIde.name}</strong> to run{' '}
                <code className="text-rose-300">{scenario.action}</code>?
              </p>
              <div className="flex gap-2 text-[11px] font-mono">
                <span
                  className={`flex-1 text-center py-1 rounded font-bold ${
                    stage >= 4
                      ? 'bg-emerald-500 text-slate-950'
                      : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  }`}
                >
                  {stage >= 4 ? '✓ Approved' : 'Approve'}
                </span>
                <span className="px-2.5 py-1 rounded bg-slate-800 text-slate-400">
                  Deny
                </span>
              </div>
            </div>
          )}

          {/* Low-Risk Auto-Approval Badge */}
          {stage >= 3 && scenario.riskLevel === 'low' && (
            <div className="mv-auto absolute right-12 px-4 py-2 bg-emerald-950/90 border border-emerald-500/50 rounded-lg text-xs font-mono text-emerald-300 shadow-lg">
              ✓ Low-risk read: allowed by policy
            </div>
          )}
        </div>

        {/* 2.5 ENCRYPTION: sealed tunnel between Warden and Vault */}
        <div className="absolute left-1/2 z-10 -translate-x-1/2" style={{ top: 349 }}>
          <div className={`mv-encryption w-64 rounded-lg border-2 bg-slate-900/95 px-4 py-2 shadow-xl transition-all duration-300 ${
            stage === 4
              ? 'border-amber-400 shadow-amber-500/25'
              : stage === 5
                ? 'border-emerald-500/70 shadow-emerald-500/15'
                : 'border-slate-700'
          }`}>
            <div className="flex items-center gap-2 text-[11px] font-mono font-bold uppercase tracking-wider text-sky-300">
              <span>🔐</span> Vault boundary
              <span className="ml-auto rounded bg-slate-800 px-1.5 py-0.5 text-[9px] text-slate-400">local</span>
            </div>
            <p className="mt-1 text-[10px] font-mono leading-snug text-slate-400">Secrets encrypted at rest; used only by vaultd.</p>
          </div>
        </div>

        {/* 3. BOTTOM LAYER: API KEYS VAULT */}
        <div className="mv-vault absolute bottom-2 left-1/2 z-10 flex -translate-x-1/2 flex-col items-center">
          <div
            className={`w-80 rounded-xl bg-slate-900 border-2 p-4 shadow-2xl transition-all duration-300 ${
              stage === 4
                ? 'border-amber-400 shadow-amber-500/20'
                : 'border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-mono uppercase tracking-wider text-amber-400 flex items-center gap-1.5">
                🔒 API KEYS VAULT
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/15 text-rose-300 border border-rose-500/30">
                Zero Key Exposure
              </span>
            </div>

            <div className="flex items-center justify-between bg-slate-950 px-3 py-2 rounded-lg border border-slate-800 font-mono text-xs mt-2">
              <span className="text-slate-400">SECRET_KEY:</span>
              <span className="text-amber-300 tracking-widest">
                sk-live-••••••••••••••••
              </span>
            </div>

            <div className="mt-2.5 flex items-center justify-between text-[11px] font-mono">
              <span className="text-slate-400">Output to IDE:</span>
              <span className="text-emerald-400 font-semibold">
                {stage >= 4 ? `Executed result` : 'Waiting...'}
              </span>
            </div>
          </div>
        </div>
      </div>

      </div>
      {/* Footer Narration & Step Progress */}
      <div className="mv-footer px-6 py-4 bg-slate-900 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="mv-narration text-xs sm:text-sm text-slate-200 font-medium">
          <span className="inline-block px-2 py-0.5 mr-2 text-xs font-mono rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
            Step {stage + 1}/6
          </span>
          {stage === 0 && `${activeIde.name} prepares a capability request (never touching raw credentials).`}
          {stage === 1 && `${activeIde.name} calls the Vault; Muse Spark intercepts the request first.`}
          {stage === 2 && `Muse Spark reviews request metadata and recommends a risk rating: ${scenario.risk}.`}
          {stage === 3 && scenario.caption}
          {stage === 4 && `vaultd executes the approved capability. The raw key stays out of the agent's context.`}
          {stage === 5 && `${activeIde.name} receives the executed result once, never the API key.`}
        </div>

        {/* Step Scrubber Dots */}
        <div className="mv-scrubber flex items-center gap-1.5">
          {[0, 1, 2, 3, 4, 5].map((s) => (
            <button
              key={s}
              onClick={() => {
                setIsPlaying(false);
                setStage(s);
              }}
              className={`h-2 rounded-full transition-all ${
                stage === s ? 'w-6 bg-indigo-400' : 'w-2 bg-slate-700 hover:bg-slate-500'
              }`}
              title={`Jump to Step ${s + 1}`}
              aria-label={`Jump to Step ${s + 1}`}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
