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
  readonly verifyPin: (pin: string) => Promise<boolean>;
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
        const res = (await callDaemon({ method: "POST", path: "/settings/local-auth/verify", body: { pin } })) as { ok?: boolean } | null;
        return res?.ok === true;
      } catch {
        return false;
      }
    },
    verifyHello: async () => (await queryWindowsHello("verify", "unlock")) === "verified",
  };
}

// Issues a single-use presence proof after a REAL local-presence check.
// No configured PIN and no usable Hello means no proof: remote approval
// fails closed, never silently bypasses.
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
  let verified = false;
  if (req.hello === true) {
    verified = await deps.verifyHello();
  } else if (typeof req.pin === "string" && req.pin !== "") {
    verified = await deps.verifyPin(req.pin);
  }
  if (!verified) {
    throw new Error("local presence not verified - set an app PIN or Windows Hello to approve remote requests");
  }
  return { token: deps.issuer.issue(scopeKey, deps.nowMs()) };
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
  if (!settingsGuard.allow) {
    throw new Error(settingsGuard.reason ?? "rejected by remote settings guard");
  }
  const approvalGuard = await guardApprovalCall({
    path: validated.path,
    body: validated.body,
    issuer: deps.issuer,
    nowMs: deps.nowMs(),
    getPending: deps.getPending,
    getRemoteSettings: deps.getRemoteSettings,
  });
  if (!approvalGuard.decision.allow) {
    throw new Error(approvalGuard.decision.reason ?? "rejected by remote approval guard");
  }
  // Strip the proof field before the daemon ever sees the call.
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
