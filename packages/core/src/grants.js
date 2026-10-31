import { Effect, SynchronizedRef } from "effect";
import { GrantExpired, GrantRevoked } from "./errors.js";
export function createGrant(grantId, request, allowedScope, createdAtMs, ttlMs) {
    return {
        grantId,
        request,
        allowedScope,
        status: "pending",
        createdAtMs,
        expiresAtMs: createdAtMs + ttlMs,
    };
}
function withGrant(state, grant) {
    const grants = new Map(state.grants);
    grants.set(grant.grantId, grant);
    return { ...state, grants };
}
export function makeGrantRegistry() {
    return SynchronizedRef.make({
        grants: new Map(),
        revokedTargets: new Set(),
    }).pipe(Effect.map((ref) => {
        const registry = {
            register: (grant) => SynchronizedRef.update(ref, (state) => withGrant(state, grant)),
            get: (grantId) => SynchronizedRef.get(ref).pipe(Effect.map((state) => state.grants.get(grantId))),
            consumeForExecution: (grantId, nowMs) => Effect.gen(function* () {
                const outcome = yield* SynchronizedRef.modify(ref, (state) => {
                    const grant = state.grants.get(grantId);
                    if (grant === undefined) {
                        return [{ kind: "gone", grantId }, state];
                    }
                    if (grant.status === "revoked") {
                        return [{ kind: "revoked", grantId }, state];
                    }
                    if (grant.status !== "pending") {
                        return [{ kind: "gone", grantId }, state];
                    }
                    if (nowMs >= grant.expiresAtMs) {
                        const expired = { ...grant, status: "expired" };
                        return [{ kind: "expired", grantId }, withGrant(state, expired)];
                    }
                    const consumed = { ...grant, status: "executed" };
                    return [{ kind: "consumed", grant: consumed }, withGrant(state, consumed)];
                });
                switch (outcome.kind) {
                    case "consumed":
                        return outcome.grant;
                    case "revoked":
                        return yield* Effect.fail(new GrantRevoked({ grantId: outcome.grantId, message: "grant has been revoked" }));
                    case "expired":
                        return yield* Effect.fail(new GrantExpired({ grantId: outcome.grantId, message: "grant has expired" }));
                    case "gone":
                        return yield* Effect.fail(new GrantExpired({
                            grantId: outcome.grantId,
                            message: "grant not found or already consumed",
                        }));
                }
            }),
            markDenied: (grantId) => SynchronizedRef.modify(ref, (state) => {
                const grant = state.grants.get(grantId);
                if (grant === undefined || grant.status !== "pending") {
                    return [false, state];
                }
                return [true, withGrant(state, { ...grant, status: "denied" })];
            }),
            markExpired: (grantId) => SynchronizedRef.modify(ref, (state) => {
                const grant = state.grants.get(grantId);
                if (grant === undefined || grant.status !== "pending") {
                    return [false, state];
                }
                return [true, withGrant(state, { ...grant, status: "expired" })];
            }),
            revokePendingFor: (target) => SynchronizedRef.modify(ref, (state) => {
                const revokedTargets = new Set(state.revokedTargets);
                revokedTargets.add(target);
                let next = { ...state, revokedTargets };
                const affected = [];
                for (const grant of state.grants.values()) {
                    if (grant.status === "pending" &&
                        (grant.request.agentId === target || grant.request.alias === target)) {
                        const revoked = { ...grant, status: "revoked" };
                        next = withGrant(next, revoked);
                        affected.push(revoked);
                    }
                }
                return [affected, next];
            }),
            revokePendingForAlias: (alias) => SynchronizedRef.modify(ref, (state) => {
                let next = state;
                const affected = [];
                for (const grant of state.grants.values()) {
                    if (grant.status === "pending" && grant.request.alias === alias) {
                        const revoked = { ...grant, status: "revoked" };
                        next = withGrant(next, revoked);
                        affected.push(revoked);
                    }
                }
                return [affected, next];
            }),
            isRevoked: (agentId, alias) => SynchronizedRef.get(ref).pipe(Effect.map((state) => state.revokedTargets.has(agentId) || state.revokedTargets.has(alias))),
            listGrants: () => SynchronizedRef.get(ref).pipe(Effect.map((state) => [...state.grants.values()])),
        };
        return registry;
    }));
}
