import { Effect } from "effect";
import { describe, expect } from "vitest";
import { it } from "@effect/vitest";
import { createGrant, makeGrantRegistry } from "../src/grants.js";
const req = {
    agentId: "cursor",
    ide: "Cursor",
    tool: "http",
    alias: "stripe",
    requestedScope: "charges.read",
    reason: "list",
};
describe("grant registry", () => {
    it.effect("consumes a pending grant exactly once, then GrantExpired", () => Effect.gen(function* () {
        const registry = yield* makeGrantRegistry();
        yield* registry.register(createGrant("g1", req, "charges.read", 1_000, 60_000));
        const consumed = yield* registry.consumeForExecution("g1", 2_000);
        expect(consumed.grantId).toBe("g1");
        expect(consumed.allowedScope).toBe("charges.read");
        const again = yield* registry.consumeForExecution("g1", 3_000).pipe(Effect.flip);
        expect(again._tag).toBe("GrantExpired");
    }));
    it.effect("fails an unknown grant as GrantExpired", () => Effect.gen(function* () {
        const registry = yield* makeGrantRegistry();
        const err = yield* registry.consumeForExecution("nope", 1_000).pipe(Effect.flip);
        expect(err._tag).toBe("GrantExpired");
    }));
    it.effect("fails a pending grant past its TTL as GrantExpired and marks it expired", () => Effect.gen(function* () {
        const registry = yield* makeGrantRegistry();
        yield* registry.register(createGrant("g1", req, "charges.read", 1_000, 60_000));
        const err = yield* registry.consumeForExecution("g1", 61_001).pipe(Effect.flip);
        expect(err._tag).toBe("GrantExpired");
        const stored = yield* registry.get("g1");
        expect(stored?.status).toBe("expired");
    }));
    it.effect("revoked pending grants fail as GrantRevoked, not GrantExpired", () => Effect.gen(function* () {
        const registry = yield* makeGrantRegistry();
        yield* registry.register(createGrant("g1", req, "charges.read", 1_000, 60_000));
        const affected = yield* registry.revokePendingFor("cursor");
        expect(affected.map((g) => g.grantId)).toEqual(["g1"]);
        const err = yield* registry.consumeForExecution("g1", 2_000).pipe(Effect.flip);
        expect(err._tag).toBe("GrantRevoked");
        expect(yield* registry.isRevoked("cursor", "stripe")).toBe(true);
        expect(yield* registry.isRevoked("other", "github")).toBe(false);
    }));
    it.effect("revoking by alias also blocks the grant", () => Effect.gen(function* () {
        const registry = yield* makeGrantRegistry();
        yield* registry.register(createGrant("g1", req, "charges.read", 1_000, 60_000));
        yield* registry.revokePendingFor("stripe");
        const err = yield* registry.consumeForExecution("g1", 2_000).pipe(Effect.flip);
        expect(err._tag).toBe("GrantRevoked");
    }));
    it.effect("a denied grant cannot be executed", () => Effect.gen(function* () {
        const registry = yield* makeGrantRegistry();
        yield* registry.register(createGrant("g1", req, "charges.read", 1_000, 60_000));
        expect(yield* registry.markDenied("g1")).toBe(true);
        const err = yield* registry.consumeForExecution("g1", 2_000).pipe(Effect.flip);
        expect(err._tag).toBe("GrantExpired");
        expect(yield* registry.markDenied("missing")).toBe(false);
    }));
});
