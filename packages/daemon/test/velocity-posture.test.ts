import { describe, expect, it } from "vitest";
import { Effect, Layer } from "effect";
import { makeVaultServiceLive, VaultService } from "../src/service.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import type { CapabilityRequest } from "../../core/src/types.js";

describe("Daemon Granular Rate Limiting & Posture Integration", () => {
  const masterKey = Buffer.alloc(32, 7);

  const mockBrain = Layer.succeed(Brain, {
    assess: () =>
      Effect.succeed({
        risk: "low" as const,
        recommendedScope: "charges.read",
        requireApproval: true,
        explanation: "integration test",
      }),
  });

  const mockConnector = Layer.succeed(Connector, {
    execute: () => Effect.succeed({ ok: true }),
  });

  it("burst protection trips circuit breaker on repeated failed attempts", async () => {
    const testLayer = Layer.mergeAll(
      VaultStoreTest(masterKey),
      mockBrain,
      mockConnector,
    );

    await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* VaultService;
        yield* service.seedCredential("stripe", "charges.read", "sk_test_123");

        const badReq: CapabilityRequest = {
          agentId: "rogue-agent",
          ide: "Test",
          tool: "request_capability",
          alias: "stripe",
          requestedScope: "charges.write", // above ceiling -> fails policy
          reason: "malicious escalation",
        };

        // Attempt 1 -> denied
        const res1 = yield* service.requestCapability(badReq);
        expect(res1.status).toBe("denied");

        // Attempt 2 -> denied
        const res2 = yield* service.requestCapability(badReq);
        expect(res2.status).toBe("denied");

        // Attempt 3 -> denied (trips circuit breaker)
        const res3 = yield* service.requestCapability(badReq);
        expect(res3.status).toBe("denied");

        // Attempt 4 -> immediate circuit-breaker-tripped
        const res4 = yield* service.requestCapability(badReq);
        expect(res4.status).toBe("denied");
        expect(res4.reason).toBe("circuit-breaker-tripped");
      }).pipe(
        Effect.provide(makeVaultServiceLive({ masterKey })),
        Effect.provide(testLayer),
      ),
    );
  });

  it("calculates live security posture report through daemon service", async () => {
    const testLayer = Layer.mergeAll(
      VaultStoreTest(masterKey),
      mockBrain,
      mockConnector,
    );

    await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* VaultService;
        yield* service.seedCredential("stripe", "charges.read", "sk_test_123");

        const posture = yield* service.getSecurityPosture();
        expect(posture.score).toBeGreaterThan(0);
        expect(posture.score).toBeLessThanOrEqual(100);
        expect(posture.grade).toBeDefined();
        expect(posture.checks.length).toBeGreaterThan(0);
      }).pipe(
        Effect.provide(makeVaultServiceLive({ masterKey })),
        Effect.provide(testLayer),
      ),
    );
  });
});
