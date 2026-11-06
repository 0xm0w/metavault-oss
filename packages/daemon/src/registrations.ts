import { createHash, randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import { publishVaultEvent } from "./live-events.js";

// Verified-agent registration. An MCP process proves it is the one that asked
// by holding a claim secret whose hash it sent. The user approves the exact
// pending request after matching its code in the agent's chat. Approval does
// not grant any capability; it only issues an agent credential to whoever
// holds the claim secret. The token is handed over once and never listed.

export type RegistrationStatus = "pending" | "approved" | "denied" | "expired" | "claimed";

interface Entry {
  id: string;
  agentId: string;
  name: string;
  ide: string;
  claimHash: Buffer;
  code: string;
  status: RegistrationStatus;
  createdAt: number;
  expiresAt: number;
  attempts: number;
  token?: string;
}

export interface PendingRegistration {
  readonly id: string;
  readonly agentId: string;
  readonly name: string;
  readonly ide: string;
  readonly code: string;
  readonly expiresAt: number;
}

const TTL_MS = 10 * 60_000;
const MAX_PENDING = 20;
const MAX_CLAIM_ATTEMPTS = 5;
const CREATE_WINDOW_MS = 60_000;
const MAX_CREATES_PER_WINDOW = 10;

export class AgentRegistrations {
  private readonly entries = new Map<string, Entry>();
  private readonly waiters = new Map<string, Set<() => void>>();
  private creates: number[] = [];
  constructor(
    private readonly revokeUnclaimed: (agentId: string, issuedToken: string) => Promise<void>,
    private readonly now: () => number = Date.now,
  ) {}

  private async sweep(): Promise<void> {
    const t = this.now();
    let changedId: string | null = null;
    for (const [id, e] of this.entries) {
      if (e.expiresAt <= t && e.status !== "claimed" && e.status !== "denied" && e.status !== "expired") {
        const issued = e.token;
        e.status = "expired";
        delete e.token;
        if (issued !== undefined) await this.revokeUnclaimed(e.agentId, issued).catch(() => undefined);
        changedId = id;
      }
      if (e.expiresAt + TTL_MS <= t) this.entries.delete(id);
    }
    if (changedId !== null) this.registrationChanged(changedId);
  }

  // Long-poll support: resolves when the registration leaves "pending"
  // (approved, denied or expired) or the wait budget expires.
  async waitForChange(id: string, waitMs: number): Promise<void> {
    if (waitMs <= 0) return;
    const capped = Math.min(25_000, Math.floor(waitMs));
    const current = this.entries.get(id);
    if (current === undefined || current.status !== "pending") return;
    await new Promise<void>((resolve) => {
      let settled = false;
      const finish = (): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        const set = this.waiters.get(id);
        set?.delete(finish);
        if (set !== undefined && set.size === 0) this.waiters.delete(id);
        resolve();
      };
      let set = this.waiters.get(id);
      if (set === undefined) {
        set = new Set();
        this.waiters.set(id, set);
      }
      set.add(finish);
      const timer = setTimeout(finish, capped);
    });
  }

  private notify(id: string): void {
    const set = this.waiters.get(id);
    if (set === undefined) return;
    this.waiters.delete(id);
    for (const finish of [...set]) finish();
  }

  // Emit registration.changed on the live-event bus. Counts and ids only.
  private registrationChanged(id?: string): void {
    const pendingCount = [...this.entries.values()].filter((e) => e.status === "pending").length;
    publishVaultEvent({
      type: "registration.changed",
      pendingRegistrationsCount: pendingCount,
      ...(id !== undefined ? { addedRegistrationId: id } : {}),
    });
  }

  async create(input: { agentId: string; name: string; ide: string; claimHash: string }, agentExists: (id: string) => Promise<boolean>):
    Promise<{ ok: true; id: string; code: string; expiresAt: number } | { ok: false; status: number; error: string }> {
    await this.sweep();
    const t = this.now();
    this.creates = this.creates.filter((x) => t - x < CREATE_WINDOW_MS);
    if (this.creates.length >= MAX_CREATES_PER_WINDOW) return { ok: false, status: 429, error: "too many registration attempts; try again shortly" };
    if (!/^[a-f0-9]{64}$/.test(input.claimHash)) return { ok: false, status: 400, error: "invalid claim hash" };
    const active = [...this.entries.values()].filter((e) => e.status === "pending" || e.status === "approved");
    if (active.length >= MAX_PENDING) return { ok: false, status: 429, error: "too many pending registrations" };
    if (active.some((e) => e.agentId === input.agentId)) return { ok: false, status: 409, error: "a registration for this agent id is already pending" };
    this.creates.push(t);
    const id = `reg_${randomBytes(12).toString("hex")}`;
    const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
    // Reserve the agent id before any await so concurrent requests cannot both pass.
    this.entries.set(id, {
      id, agentId: input.agentId, name: input.name, ide: input.ide,
      claimHash: Buffer.from(input.claimHash, "hex"), code, status: "pending", createdAt: t, expiresAt: t + TTL_MS, attempts: 0,
    });
    if (await agentExists(input.agentId)) {
      this.entries.delete(id);
      return { ok: false, status: 409, error: "this agent id is already registered; revoke it in MetaVault first" };
    }
    this.registrationChanged(id);
    return { ok: true, id, code, expiresAt: t + TTL_MS };
  }

  async list(): Promise<PendingRegistration[]> {
    await this.sweep();
    return [...this.entries.values()]
      .filter((e) => e.status === "pending")
      .map((e) => ({ id: e.id, agentId: e.agentId, name: e.name, ide: e.ide, code: e.code, expiresAt: e.expiresAt }));
  }

  // The approval ties to the exact pending entry the user saw (id + code).
  async approve(id: string, code: string, issueToken: (agentId: string, name: string) => Promise<string>):
    Promise<{ ok: true } | { ok: false; status: number; error: string }> {
    await this.sweep();
    const e = this.entries.get(id);
    if (e === undefined || e.status !== "pending") return { ok: false, status: 404, error: "registration not found or no longer pending" };
    const a = Buffer.from(code); const b = Buffer.from(e.code);
    if (a.length !== b.length || !timingSafeEqual(a, b)) return { ok: false, status: 403, error: "the code does not match this request" };
    e.token = await issueToken(e.agentId, e.name);
    e.status = "approved";
    this.notify(id);
    this.registrationChanged(id);
    return { ok: true };
  }

  async deny(id: string): Promise<boolean> {
    await this.sweep();
    const e = this.entries.get(id);
    if (e === undefined || e.status !== "pending") return false;
    e.status = "denied";
    this.notify(id);
    this.registrationChanged(id);
    return true;
  }

  async claim(id: string, claimSecret: string):
    Promise<{ ok: true; token: string; agentId: string } | { ok: false; status: number; status2: string; error: string }> {
    await this.sweep();
    const e = this.entries.get(id);
    const miss = { ok: false as const, status: 404, status2: "unknown", error: "registration not found" };
    if (e === undefined) return miss;
    if (e.status === "pending") return { ok: false, status: 202, status2: "pending", error: "waiting for the user to approve in MetaVault" };
    if (e.status === "denied") return { ok: false, status: 403, status2: "denied", error: "the user denied this registration" };
    if (e.status === "expired") return { ok: false, status: 410, status2: "expired", error: "this registration expired" };
    if (e.status === "claimed" || e.token === undefined) return { ok: false, status: 410, status2: "claimed", error: "this registration was already claimed" };
    const given = createHash("sha256").update(claimSecret).digest();
    if (!timingSafeEqual(given, e.claimHash)) {
      e.attempts += 1;
      if (e.attempts >= MAX_CLAIM_ATTEMPTS) {
        const issued = e.token;
        e.status = "denied";
        delete e.token;
        // Only the credential this registration itself issued is revoked, and
        // only if it is still the live one for that agent id.
        await this.revokeUnclaimed(e.agentId, issued).catch(() => undefined);
        this.notify(id);
        this.registrationChanged(id);
      }
      return { ok: false, status: 403, status2: "bad-claim", error: "claim proof rejected" };
    }
    const token = e.token;
    delete e.token;
    e.status = "claimed";
    return { ok: true, token, agentId: e.agentId };
  }
}
