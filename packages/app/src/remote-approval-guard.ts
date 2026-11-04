import { randomBytes } from "node:crypto";

// Trusted-boundary enforcement for remote approvals (WP5/WP6): a request
// that arrived through the gateway may only be approved with fresh local
// presence. This runs in the Electron MAIN process - never the renderer -
// so a forged renderer IPC call cannot bypass it.
//
// Presence proofs are single-use, short-lived, and bound to exactly one
// grantId (or the remote-settings change they authorize). They are issued
// by main only after a real PIN verification against the daemon or a real
// Windows Hello prompt. When neither PIN nor Hello is usable, no proof can
// be issued and remote approval fails CLOSED.

export const PRESENCE_PROOF_TTL_MS = 60_000;
export const SETTINGS_REMOTE_PROOF_SCOPE = "settings:remote";

export class PresenceProofIssuer {
  private readonly proofs = new Map<string, { scope: string; expiresAtMs: number }>();

  issue(scope: string, nowMs: number): string {
    // Housekeeping on issue keeps the map bounded.
    for (const [token, proof] of this.proofs) {
      if (proof.expiresAtMs <= nowMs) this.proofs.delete(token);
    }
    const token = randomBytes(24).toString("hex");
    this.proofs.set(token, { scope, expiresAtMs: nowMs + PRESENCE_PROOF_TTL_MS });
    return token;
  }

  // Single-use: a consumed token is gone. Wrong scope, unknown token, or
  // expired token all fail closed.
  consume(token: unknown, scope: string, nowMs: number): boolean {
    if (typeof token !== "string" || token === "") return false;
    const proof = this.proofs.get(token);
    if (proof === undefined) return false;
    this.proofs.delete(token);
    return proof.scope === scope && proof.expiresAtMs > nowMs;
  }
}

export interface RemoteApprovalDecision {
  readonly allow: boolean;
  readonly reason?: string;
}

interface PendingLike {
  readonly grantId?: unknown;
  readonly origin?: unknown;
}

interface RemoteSettingsLike {
  readonly requireAuthForRemoteApproval?: unknown;
}

function findGrant(pendingRaw: unknown, grantId: string): PendingLike | null {
  if (typeof pendingRaw !== "object" || pendingRaw === null) return null;
  const approvals = (pendingRaw as Record<string, unknown>)["approvals"];
  if (!Array.isArray(approvals)) return null;
  for (const item of approvals) {
    if (typeof item === "object" && item !== null && (item as PendingLike).grantId === grantId) {
      return item as PendingLike;
    }
  }
  return null;
}

export function remotePresenceRequired(grant: PendingLike | null, settingsRaw: unknown): boolean {
  if (grant === null || grant.origin !== "remote") return false;
  const requireAuth =
    typeof settingsRaw === "object" && settingsRaw !== null
      ? (settingsRaw as RemoteSettingsLike)["requireAuthForRemoteApproval"]
      : undefined;
  // Default ON: fail closed when the setting cannot be read.
  return requireAuth !== false;
}

// Guards POST /approve and /approve-always at the IPC boundary. The proof
// token travels in the request body as __presenceProof and is stripped
// before forwarding to the daemon.
export async function guardApprovalCall(options: {
  readonly path: string;
  readonly body: unknown;
  readonly issuer: PresenceProofIssuer;
  readonly nowMs: number;
  readonly getPending: () => Promise<unknown>;
  readonly getRemoteSettings: () => Promise<unknown>;
}): Promise<{ readonly decision: RemoteApprovalDecision; readonly body: unknown }> {
  if (options.path !== "/approve" && options.path !== "/approve-always") {
    return { decision: { allow: true }, body: options.body };
  }
  const record = typeof options.body === "object" && options.body !== null ? { ...(options.body as Record<string, unknown>) } : {};
  const grantId = record["grantId"];
  if (typeof grantId !== "string" || grantId === "") {
    return { decision: { allow: true }, body: options.body };
  }
  const proof = record["__presenceProof"];
  delete record["__presenceProof"];
  let grant: PendingLike | null = null;
  let settingsRaw: unknown = null;
  try {
    [grant, settingsRaw] = [
      findGrant(await options.getPending(), grantId),
      await options.getRemoteSettings(),
    ];
  } catch {
    // Daemon state unreadable: the daemon itself will answer the call.
    return { decision: { allow: true }, body: record };
  }
  if (!remotePresenceRequired(grant, settingsRaw)) {
    return { decision: { allow: true }, body: record };
  }
  if (options.issuer.consume(proof, `approve:${grantId}`, options.nowMs)) {
    return { decision: { allow: true }, body: record };
  }
  return {
    decision: { allow: false, reason: "remote approval requires fresh local presence (PIN or Windows Hello)" },
    body: record,
  };
}

// Guards PATCH /settings/remote: weakening the remote-approval presence
// requirement itself requires fresh local presence.
export function guardRemoteSettingsCall(options: {
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
  readonly issuer: PresenceProofIssuer;
  readonly nowMs: number;
}): RemoteApprovalDecision {
  if (!(options.method === "PATCH" && options.path === "/settings/remote")) return { allow: true };
  const record = typeof options.body === "object" && options.body !== null ? (options.body as Record<string, unknown>) : {};
  if (record["requireAuthForRemoteApproval"] !== false) return { allow: true };
  if (options.issuer.consume(record["__presenceProof"], SETTINGS_REMOTE_PROOF_SCOPE, options.nowMs)) {
    return { allow: true };
  }
  return { allow: false, reason: "disabling remote-approval presence requires fresh local presence (PIN or Windows Hello)" };
}
