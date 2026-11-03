import { Effect, SynchronizedRef } from "effect";
import { GrantExpired, GrantRevoked } from "./errors.js";
import type { CapabilityRequest } from "./types.js";

export type GrantStatus = "pending" | "executed" | "denied" | "expired" | "revoked";

export interface Grant {
  readonly grantId: string;
  readonly request: CapabilityRequest;
  readonly allowedScope: string;
  readonly status: GrantStatus;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
}

export function createGrant(
  grantId: string,
  request: CapabilityRequest,
  allowedScope: string,
  createdAtMs: number,
  ttlMs: number,
): Grant {
  return {
    grantId,
    request,
    allowedScope,
    status: "pending",
    createdAtMs,
    expiresAtMs: createdAtMs + ttlMs,
  };
}

export interface GrantRegistry {
  readonly register: (grant: Grant) => Effect.Effect<void>;
  readonly get: (grantId: string) => Effect.Effect<Grant | undefined>;
  readonly consumeForExecution: (
    grantId: string,
    nowMs: number,
  ) => Effect.Effect<Grant, GrantExpired | GrantRevoked>;
  readonly markDenied: (grantId: string) => Effect.Effect<boolean>;
  readonly markExpired: (grantId: string) => Effect.Effect<boolean>;
  readonly revokePendingFor: (target: string) => Effect.Effect<Grant[]>;
  readonly invalidatePendingForAgent: (agentId: string) => Effect.Effect<Grant[]>;
  readonly revokePendingForAlias: (alias: string) => Effect.Effect<Grant[]>;
  readonly isRevoked: (agentId: string, alias: string) => Effect.Effect<boolean>;
  readonly listGrants: () => Effect.Effect<Grant[]>;
}

interface RegistryState {
  readonly grants: Map<string, Grant>;
  readonly revokedTargets: Set<string>;
}

type ConsumeOutcome =
  | { readonly kind: "consumed"; readonly grant: Grant }
  | { readonly kind: "expired"; readonly grantId: string }
  | { readonly kind: "revoked"; readonly grantId: string }
  | { readonly kind: "gone"; readonly grantId: string };

function withGrant(state: RegistryState, grant: Grant): RegistryState {
  const grants = new Map(state.grants);
  grants.set(grant.grantId, grant);
  return { ...state, grants };
}

export function makeGrantRegistry(): Effect.Effect<GrantRegistry> {
  return SynchronizedRef.make<RegistryState>({
    grants: new Map<string, Grant>(),
    revokedTargets: new Set<string>(),
  }).pipe(
    Effect.map((ref) => {
      const registry: GrantRegistry = {
        register: (grant) => SynchronizedRef.update(ref, (state) => withGrant(state, grant)),
        get: (grantId) =>
          SynchronizedRef.get(ref).pipe(Effect.map((state) => state.grants.get(grantId))),
        consumeForExecution: (grantId, nowMs) =>
          Effect.gen(function* () {
            const outcome: ConsumeOutcome = yield* SynchronizedRef.modify(
              ref,
              (state): readonly [ConsumeOutcome, RegistryState] => {
                const grant = state.grants.get(grantId);
                if (grant === undefined) {
                  return [{ kind: "gone", grantId }, state] as const;
                }
                if (grant.status === "revoked") {
                  return [{ kind: "revoked", grantId }, state] as const;
                }
                if (grant.status !== "pending") {
                  return [{ kind: "gone", grantId }, state] as const;
                }
                if (nowMs >= grant.expiresAtMs) {
                  const expired: Grant = { ...grant, status: "expired" };
                  return [{ kind: "expired", grantId }, withGrant(state, expired)] as const;
                }
                const consumed: Grant = { ...grant, status: "executed" };
                return [{ kind: "consumed", grant: consumed }, withGrant(state, consumed)] as const;
              },
            );
            switch (outcome.kind) {
              case "consumed":
                return outcome.grant;
              case "revoked":
                return yield* Effect.fail(
                  new GrantRevoked({ grantId: outcome.grantId, message: "grant has been revoked" }),
                );
              case "expired":
                return yield* Effect.fail(
                  new GrantExpired({ grantId: outcome.grantId, message: "grant has expired" }),
                );
              case "gone":
                return yield* Effect.fail(
                  new GrantExpired({
                    grantId: outcome.grantId,
                    message: "grant not found or already consumed",
                  }),
                );
            }
          }),
        markDenied: (grantId) =>
          SynchronizedRef.modify(ref, (state): readonly [boolean, RegistryState] => {
            const grant = state.grants.get(grantId);
            if (grant === undefined || grant.status !== "pending") {
              return [false, state] as const;
            }
            return [true, withGrant(state, { ...grant, status: "denied" })] as const;
          }),
        markExpired: (grantId) =>
          SynchronizedRef.modify(ref, (state): readonly [boolean, RegistryState] => {
            const grant = state.grants.get(grantId);
            if (grant === undefined || grant.status !== "pending") {
              return [false, state] as const;
            }
            return [true, withGrant(state, { ...grant, status: "expired" })] as const;
          }),
        revokePendingFor: (target) =>
          SynchronizedRef.modify(ref, (state): readonly [Grant[], RegistryState] => {
            const revokedTargets = new Set(state.revokedTargets);
            revokedTargets.add(target);
            let next: RegistryState = { ...state, revokedTargets };
            const affected: Grant[] = [];
            for (const grant of state.grants.values()) {
              if (
                grant.status === "pending" &&
                (grant.request.agentId === target || grant.request.alias === target)
              ) {
                const revoked: Grant = { ...grant, status: "revoked" };
                next = withGrant(next, revoked);
                affected.push(revoked);
              }
            }
            return [affected, next] as const;
          }),
        invalidatePendingForAgent: (agentId) =>
          SynchronizedRef.modify(ref, (state): readonly [Grant[], RegistryState] => {
            let next = state;
            const affected: Grant[] = [];
            for (const grant of state.grants.values()) {
              if (grant.status === "pending" && grant.request.agentId === agentId) {
                const revoked: Grant = { ...grant, status: "revoked" };
                next = withGrant(next, revoked);
                affected.push(revoked);
              }
            }
            return [affected, next] as const;
          }),
        revokePendingForAlias: (alias) =>
          SynchronizedRef.modify(ref, (state): readonly [Grant[], RegistryState] => {
            let next: RegistryState = state;
            const affected: Grant[] = [];
            for (const grant of state.grants.values()) {
              if (grant.status === "pending" && grant.request.alias === alias) {
                const revoked: Grant = { ...grant, status: "revoked" };
                next = withGrant(next, revoked);
                affected.push(revoked);
              }
            }
            return [affected, next] as const;
          }),
        isRevoked: (agentId, alias) =>
          SynchronizedRef.get(ref).pipe(
            Effect.map((state) => state.revokedTargets.has(agentId) || state.revokedTargets.has(alias)),
          ),
        listGrants: () =>
          SynchronizedRef.get(ref).pipe(Effect.map((state) => [...state.grants.values()])),
      };
      return registry;
    }),
  );
}
