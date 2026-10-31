// packages/daemon/test/service.test.ts — fake Brain/Connector layers via @effect/vitest
import { Clock, Effect, Layer, TestClock } from "effect";
import { describe, expect } from "vitest";
import { it } from "@effect/vitest";
import { makeVaultServiceLive, VaultService, VaultServiceLive } from "../src/service.js";
import { Brain, MarshalUnavailable } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStoreTest } from "../../core/src/storage.js";

const BrainLowRisk = Layer.succeed(Brain, { assess: () => Effect.succeed({ risk: "low" as const, recommendedScope: "charges.read", requireApproval: true, explanation: "ok" }) });
const BrainDown = Layer.succeed(Brain, { assess: () => Effect.fail(new MarshalUnavailable()) });
const BrainAutoApprove = Layer.succeed(Brain, { assess: () => Effect.succeed({ risk: "low" as const, recommendedScope: "charges.read", requireApproval: false, explanation: "ok" }) });
const FakeConnector = Layer.succeed(Connector, { execute: (_a, _s, secret) => Effect.succeed({ echoedLength: secret.length }) });
const req = { agentId: "cursor", ide: "Cursor", tool: "http", alias: "stripe", requestedScope: "charges.read", reason: "list" };
const grantIdOf = (r: { grantId?: string }): string => {
  if (r.grantId === undefined) {
    throw new Error("expected a grantId");
  }
  return r.grantId;
};
const seeded = (brain: Layer.Layer<Brain>) => Effect.gen(function* () {
  const svc = yield* VaultService;
  yield* svc.seedCredential("stripe", "charges.read", "[REDACTED]");
  return svc;
}).pipe(Effect.provide(VaultServiceLive), Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), brain, FakeConnector)));

describe("VaultService", () => {
  it.effect("returns awaiting-approval, then executes exactly once on approve", () =>
    Effect.gen(function* () {
      const svc = yield* seeded(BrainLowRisk);
      const first = yield* svc.requestCapability(req);
      expect(first.status).toBe("awaiting-approval");
      const done = yield* svc.approve(grantIdOf(first));
      expect(done.status).toBe("executed");
      expect(JSON.stringify(done)).not.toContain("[REDACTED]");
      const again = yield* svc.approve(grantIdOf(first)).pipe(Effect.flip);
      expect(again._tag).toBe("GrantExpired");
    }));

  it.effect("revoke blocks pending and future grants for the agent", () =>
    Effect.gen(function* () {
      const svc = yield* seeded(BrainLowRisk);
      const pending = yield* svc.requestCapability(req);
      yield* svc.revoke("cursor");
      expect((yield* svc.approve(grantIdOf(pending)).pipe(Effect.flip))._tag).toBe("GrantRevoked");
      expect((yield* svc.requestCapability(req)).status).toBe("denied");
    }));

  it.effect("marshal down still returns awaiting-approval, never a silent grant", () =>
    Effect.gen(function* () {
      const svc = yield* seeded(BrainDown);
      expect((yield* svc.requestCapability(req)).status).toBe("awaiting-approval");
    }));

  it.effect("executes immediately when policy does not require approval", () =>
    Effect.gen(function* () {
      const svc = yield* seeded(BrainAutoApprove);
      const result = yield* svc.requestCapability(req);
      expect(result.status).toBe("executed");
      expect(JSON.stringify(result)).not.toContain("[REDACTED]");
      expect(result.result).toEqual({ echoedLength: "[REDACTED]".length });
    }));

  it.effect("denies an unknown alias without calling the connector", () =>
    Effect.gen(function* () {
      const svc = yield* seeded(BrainLowRisk);
      const result = yield* svc.requestCapability({ ...req, alias: "nope" });
      expect(result.status).toBe("denied");
      expect(result.reason).toBe("unknown-alias");
    }));

  it.effect("deny consumes the grant; a later approve fails GrantExpired", () =>
    Effect.gen(function* () {
      const svc = yield* seeded(BrainLowRisk);
      const pending = yield* svc.requestCapability(req);
      expect(pending.status).toBe("awaiting-approval");
      yield* svc.deny(grantIdOf(pending));
      const err = yield* svc.approve(grantIdOf(pending)).pipe(Effect.flip);
      expect(err._tag).toBe("GrantExpired");
    }));

  it.effect("audits every stage without ever writing the secret", () =>
    Effect.gen(function* () {
      const svc = yield* seeded(BrainLowRisk);
      const pending = yield* svc.requestCapability(req);
      yield* svc.approve(grantIdOf(pending));
      const audit = yield* svc.listAudit();
      const stages = audit.map((e) => e.stage);
      expect(stages).toContain("requested");
      expect(stages).toContain("marshal");
      expect(stages).toContain("policy");
      expect(stages).toContain("approved");
      expect(stages).toContain("executed");
      expect(audit.some((e) => e.modelId !== undefined)).toBe(true);
      expect(JSON.stringify(audit)).not.toContain("[REDACTED]");
      expect(yield* svc.listAliases()).toEqual(["stripe"]);
    }));

  it.effect("marshal failure is audited as recovered to a null decision", () =>
    Effect.gen(function* () {
      const svc = yield* seeded(BrainDown);
      yield* svc.requestCapability(req);
      const audit = yield* svc.listAudit();
      const marshalEvents = audit.filter((e) => e.stage === "marshal");
      expect(marshalEvents.length).toBeGreaterThan(0);
      expect(marshalEvents.some((e) => e.detail.includes("null"))).toBe(true);
    }));

  it.effect("a pending grant expires after its TTL", () =>
    Effect.gen(function* () {
      const svc = yield* Effect.gen(function* () {
        const s = yield* VaultService;
        yield* s.seedCredential("stripe", "charges.read", "[REDACTED]");
        return s;
      }).pipe(
        Effect.provide(makeVaultServiceLive({ grantTtlMs: 60_000 })),
        Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), BrainLowRisk, FakeConnector)),
      );
      const pending = yield* svc.requestCapability(req);
      expect(pending.status).toBe("awaiting-approval");
      yield* TestClock.adjust("61 seconds");
      const err = yield* svc.approve(grantIdOf(pending)).pipe(Effect.flip);
      expect(err._tag).toBe("GrantExpired");
      const now = yield* Clock.currentTimeMillis;
      expect(now).toBeGreaterThan(0);
    }));

  it.effect("revoke by alias denies future requests for that alias", () =>
    Effect.gen(function* () {
      const svc = yield* seeded(BrainLowRisk);
      yield* svc.revoke("stripe");
      expect((yield* svc.requestCapability(req)).status).toBe("denied");
    }));
});
