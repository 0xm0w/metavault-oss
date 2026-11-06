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
export const SETTINGS_LOCAL_AUTH_PROOF_SCOPE = "settings:local-auth";
export const AGENTS_ROTATE_PROOF_SCOPE = "agents:rotate";
export const SETTINGS_SECURITY_PROOF_SCOPE = "settings:security";

export class PresenceProofIssuer {
  private readonly proofs = new Map<string, { scope: string; expiresAtMs: number; daemonProof?: string | undefined }>();

  issue(scope: string, nowMs: number, daemonProof?: string): string {
    // Housekeeping on issue keeps the map bounded.
    for (const [token, proof] of this.proofs) {
      if (proof.expiresAtMs <= nowMs) this.proofs.delete(token);
    }
    const token = randomBytes(24).toString("hex");
    this.proofs.set(token, { scope, expiresAtMs: nowMs + PRESENCE_PROOF_TTL_MS, daemonProof });
    return token;
  }

  // Single-use: a consumed token is gone. Wrong scope, unknown token, or
  // expired token all fail closed. On success the stored record (with the
  // daemon-issued proof, when the factor was a daemon-verified PIN) is
  // returned so the guarded call can forward it to the daemon.
  consume(token: unknown, scope: string, nowMs: number): { readonly daemonProof?: string | undefined } | null {
    if (typeof token !== "string" || token === "") return null;
    const proof = this.proofs.get(token);
    if (proof === undefined) return null;
    this.proofs.delete(token);
    if (proof.scope !== scope || proof.expiresAtMs <= nowMs) return null;
    return { daemonProof: proof.daemonProof };
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
  // Unknown/unreadable origin is treated as remote: a grant whose
  // provenance cannot be established must NOT inherit the local fast path.
  if (grant === null) return true;
  if (grant.origin !== "remote") return false;
  const requireAuth =
    typeof settingsRaw === "object" && settingsRaw !== null
      ? (settingsRaw as RemoteSettingsLike)["requireAuthForRemoteApproval"]
      : undefined;
  // Default ON: fail closed when the setting cannot be read.
  return requireAuth !== false;
}

function isWriteScope(scope: string): boolean {
  if (scope.includes("*")) return true;
  return !(scope === "read" || scope.endsWith(".read") || scope.endsWith(":read"));
}

function grantField(grant: PendingLike | null, key: "risk" | "allowedScope" | "scope"): string | undefined {
  if (grant === null) return undefined;
  const value = (grant as Record<string, unknown>)[key];
  return typeof value === "string" ? value : undefined;
}

export function approvalPresenceRequired(
  grant: PendingLike | null,
  risk: string | undefined,
  scope: string | undefined,
  settingsRaw: unknown = null,
): boolean {
  if (remotePresenceRequired(grant, settingsRaw)) return true;
  if (risk === "high") return true;
  return typeof scope === "string" && isWriteScope(scope);
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
  if (options.path !== "/approve" && options.path !== "/approve-always" && options.path !== "/approve-session") {
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
    // Daemon state unreadable: origin cannot be established, so fail closed.
    return {
      decision: { allow: false, reason: "remote approval requires fresh local presence (app PIN)" },
      body: record,
    };
  }
  const risk = grantField(grant, "risk");
  const scope = grantField(grant, "allowedScope") ?? grantField(grant, "scope");
  if (!approvalPresenceRequired(grant, risk, scope, settingsRaw)) {
    return { decision: { allow: true }, body: record };
  }
  const consumed = options.issuer.consume(proof, `approve:${grantId}`, options.nowMs);
  if (consumed !== null) {
    if (typeof consumed.daemonProof === "string" && consumed.daemonProof !== "") {
      record["presenceProof"] = consumed.daemonProof;
    }
    return { decision: { allow: true }, body: record };
  }
  return {
    decision: { allow: false, reason: "remote approval requires fresh local presence (app PIN)" },
    body: record,
  };
}

// Guards PATCH /settings/remote: weakening the remote-approval presence
// requirement itself requires fresh local presence, and the daemon-issued
// proof is forwarded so the daemon enforces the same rule for direct
// token-authenticated calls.
export function guardRemoteSettingsCall(options: {
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
  readonly issuer: PresenceProofIssuer;
  readonly nowMs: number;
}): { readonly decision: RemoteApprovalDecision; readonly body: unknown } {
  if (!(options.method === "PATCH" && options.path === "/settings/remote")) {
    return { decision: { allow: true }, body: options.body };
  }
  const record = typeof options.body === "object" && options.body !== null ? { ...(options.body as Record<string, unknown>) } : {};
  if (record["requireAuthForRemoteApproval"] !== false) {
    return { decision: { allow: true }, body: options.body };
  }
  const proof = record["__presenceProof"];
  delete record["__presenceProof"];
  const consumed = options.issuer.consume(proof, SETTINGS_REMOTE_PROOF_SCOPE, options.nowMs);
  if (consumed !== null) {
    if (typeof consumed.daemonProof === "string" && consumed.daemonProof !== "") {
      record["presenceProof"] = consumed.daemonProof;
    }
    return { decision: { allow: true }, body: record };
  }
  return {
    decision: { allow: false, reason: "disabling remote-approval presence requires fresh local presence (app PIN)" },
    body: record,
  };
}

const LOCAL_AUTH_WEAKEN_KEYS = ["enabled", "requireOnLaunch", "requireOnApproval", "requireOnSettings", "biometricEnabled"] as const;

function copyBody(body: unknown): Record<string, unknown> {
  return typeof body === "object" && body !== null ? { ...(body as Record<string, unknown>) } : {};
}

function consumeStripped(
  record: Record<string, unknown>,
  issuer: PresenceProofIssuer,
  scope: string,
  nowMs: number,
  reason: string,
): { readonly decision: RemoteApprovalDecision; readonly body: unknown } {
  const proof = record["__presenceProof"];
  delete record["__presenceProof"];
  const consumed = issuer.consume(proof, scope, nowMs);
  if (consumed !== null) {
    if (typeof consumed.daemonProof === "string" && consumed.daemonProof !== "") {
      record["presenceProof"] = consumed.daemonProof;
    }
    return { decision: { allow: true }, body: record };
  }
  return { decision: { allow: false, reason }, body: record };
}

export function guardLocalAuthCall(options: {
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
  readonly issuer: PresenceProofIssuer;
  readonly nowMs: number;
}): { readonly decision: RemoteApprovalDecision; readonly body: unknown } {
  if (!(options.method === "PATCH" && options.path === "/settings/local-auth")) {
    return { decision: { allow: true }, body: options.body };
  }
  const record = copyBody(options.body);
  const weakens = LOCAL_AUTH_WEAKEN_KEYS.some((key) => record[key] === false);
  if (!weakens) return { decision: { allow: true }, body: options.body };
  return consumeStripped(
    record,
    options.issuer,
    SETTINGS_LOCAL_AUTH_PROOF_SCOPE,
    options.nowMs,
    "this approval requires fresh local presence (app PIN)",
  );
}

export function guardSecuritySettingsCall(options: {
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
  readonly issuer: PresenceProofIssuer;
  readonly nowMs: number;
}): { readonly decision: RemoteApprovalDecision; readonly body: unknown } {
  if (!(options.method === "PATCH" && options.path === "/settings/security")) {
    return { decision: { allow: true }, body: options.body };
  }
  const record = copyBody(options.body);
  if (record["strictMode"] !== false && record["verifyCallerProcess"] !== false) {
    return { decision: { allow: true }, body: options.body };
  }
  return consumeStripped(
    record,
    options.issuer,
    SETTINGS_SECURITY_PROOF_SCOPE,
    options.nowMs,
    "this approval requires fresh local presence (app PIN)",
  );
}

export function guardAgentRotateCall(options: {
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
  readonly issuer: PresenceProofIssuer;
  readonly nowMs: number;
}): { readonly decision: RemoteApprovalDecision; readonly body: unknown } {
  if (
    !(
      options.method === "POST" &&
      (options.path === "/agents/rotate" || options.path === "/agents" || options.path === "/agents/revoke")
    )
  ) {
    return { decision: { allow: true }, body: options.body };
  }
  const record = copyBody(options.body);
  return consumeStripped(
    record,
    options.issuer,
    AGENTS_ROTATE_PROOF_SCOPE,
    options.nowMs,
    "this approval requires fresh local presence (app PIN)",
  );
}
