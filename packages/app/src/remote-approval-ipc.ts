import { PresenceProofIssuer, SETTINGS_REMOTE_PROOF_SCOPE, guardApprovalCall, guardRemoteSettingsCall } from "./remote-approval-guard.js";
import { callDaemon, validateDaemonCall, type DaemonCallRequest } from "./daemon-client.js";
import { queryWindowsHello } from "./windows-hello.js";

// IPC-boundary wiring for the remote-approval presence guard (trusted
// main process). All decisions are made here; the renderer only supplies
// the PIN the user typed or asks for a Hello prompt.

export const PRESENCE_PROOF_CHANNEL = "metavault:presence-proof";

export interface PresenceProofRequest {
  readonly scope: "approve" | "settings-remote";
  readonly grantId?: string;
  readonly pin?: string;
  readonly hello?: boolean;
}

export interface GuardDeps {
  readonly issuer: PresenceProofIssuer;
  readonly nowMs: () => number;
  readonly getPending: () => Promise<unknown>;
  readonly getRemoteSettings: () => Promise<unknown>;
  // Resolves to the daemon-issued presence proof when the PIN checked out
  // and the daemon issued one, null when the PIN checked out but the daemon
  // issued no proof (no PIN configured: vacuous verify), false otherwise.
  readonly verifyPin: (pin: string) => Promise<string | null | false>;
  readonly verifyHello: () => Promise<boolean>;
  // Injectable for tests; production forwards to the real daemon client.
  readonly forward?: (call: DaemonCallRequest) => Promise<unknown>;
}

export function defaultGuardDeps(issuer: PresenceProofIssuer): GuardDeps {
  return {
    issuer,
    nowMs: () => Date.now(),
    getPending: () => callDaemon({ method: "GET", path: "/pending" }),
    getRemoteSettings: () => callDaemon({ method: "GET", path: "/settings/remote" }),
    verifyPin: async (pin: string) => {
      try {
        const res = (await callDaemon({ method: "POST", path: "/settings/local-auth/verify", body: { pin } })) as { ok?: boolean; presenceProof?: unknown } | null;
        if (res?.ok !== true) return false;
        return typeof res.presenceProof === "string" && res.presenceProof !== "" ? res.presenceProof : null;
      } catch {
        return false;
      }
    },
    verifyHello: async () => (await queryWindowsHello("verify", "unlock")) === "verified",
  };
}

// Issues a single-use presence proof after a REAL PIN verification.
// No configured PIN means no proof: remote approval fails closed, never
// silently bypasses. Hello is deliberately not accepted here.
export async function issuePresenceProof(input: unknown, deps: GuardDeps): Promise<{ token: string }> {
  if (typeof input !== "object" || input === null) throw new Error("malformed presence proof request");
  const req = input as PresenceProofRequest;
  let scopeKey: string;
  if (req.scope === "approve" && typeof req.grantId === "string" && req.grantId !== "") {
    scopeKey = `approve:${req.grantId}`;
  } else if (req.scope === "settings-remote") {
    scopeKey = SETTINGS_REMOTE_PROOF_SCOPE;
  } else {
    throw new Error("malformed presence proof request");
  }
  // PIN is the ONLY accepted factor. Windows Hello results are
  // caller-attested at the daemon, so a Hello-based proof would be a faux
  // guarantee: remote approvals fail closed to the app PIN instead.
  if (req.hello === true && (typeof req.pin !== "string" || req.pin === "")) {
    throw new Error("Windows Hello cannot authorize remote approvals - use the app PIN");
  }
  let verified = false;
  let daemonProof: string | null = null;
  if (typeof req.pin === "string" && req.pin !== "") {
    const pinResult = await deps.verifyPin(req.pin);
    verified = pinResult !== false;
    daemonProof = typeof pinResult === "string" ? pinResult : null;
  }
  if (!verified) {
    throw new Error("local presence not verified - set an app PIN to approve remote requests");
  }
  // When the PIN was verified by the daemon, its single-use proof rides
  // along so the guarded approval can satisfy the daemon-side presence
  // enforcement as well as the main-process guard.
  return { token: deps.issuer.issue(scopeKey, deps.nowMs(), daemonProof ?? undefined) };
}

// The guarded daemon-call entry point used by the main-process IPC
// handler. Throws with a safe reason when the guard rejects.
export async function guardedDaemonCall(request: unknown, deps: GuardDeps): Promise<unknown> {
  const validated: DaemonCallRequest = validateDaemonCall(request);
  const settingsGuard = guardRemoteSettingsCall({
    method: validated.method,
    path: validated.path,
    body: validated.body,
    issuer: deps.issuer,
    nowMs: deps.nowMs(),
  });
  if (!settingsGuard.decision.allow) {
    throw new Error(settingsGuard.decision.reason ?? "rejected by remote settings guard");
  }
  const approvalGuard = await guardApprovalCall({
    path: validated.path,
    body: settingsGuard.body,
    issuer: deps.issuer,
    nowMs: deps.nowMs(),
    getPending: deps.getPending,
    getRemoteSettings: deps.getRemoteSettings,
  });
  if (!approvalGuard.decision.allow) {
    throw new Error(approvalGuard.decision.reason ?? "rejected by remote approval guard");
  }
  // The main-issued __presenceProof never leaves main; the daemon-issued
  // presenceProof (when present) is forwarded so the daemon can enforce
  // presence for direct token-authenticated approval calls too.
  let body = approvalGuard.body;
  if (typeof body === "object" && body !== null && "__presenceProof" in body) {
    const cleaned = { ...(body as Record<string, unknown>) };
    delete cleaned["__presenceProof"];
    body = cleaned;
  }
  const forward = deps.forward ?? callDaemon;
  return forward(
    body !== undefined
      ? { method: validated.method, path: validated.path, body }
      : { method: validated.method, path: validated.path },
  );
}
