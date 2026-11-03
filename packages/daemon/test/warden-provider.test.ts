import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../src/service.js";

const FakeConnector = Layer.succeed(Connector, {
  execute: (_a, _s, secret) => Effect.succeed({ echoedLength: secret.length }),
});
const req = {
  agentId: "cursor",
  ide: "Cursor",
  tool: "http",
  alias: "stripe",
  requestedScope: "charges.read",
  reason: "list",
};

async function makeService(brain: Layer.Layer<Brain>): Promise<VaultServiceService> {
  return Effect.runPromise(
    Effect.gen(function* () {
      return yield* VaultService;
    }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 7) })),
      Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), brain, FakeConnector)),
    ),
  );
}

describe("warden provider none", () => {
  it("skips the marshal entirely, reads settings per request, and records no marshal event", async () => {
    let calls = 0;
    const counting = Layer.succeed(Brain, {
      assess: () => {
        calls += 1;
        return Effect.succeed({
          risk: "low" as const,
          recommendedScope: "charges.read",
          requireApproval: false,
          explanation: "ok",
        });
      },
    });
    const service = await makeService(counting);
    await Effect.runPromise(service.seedCredential("stripe", "charges.read", "sk-test-secret"));
    await Effect.runPromise(service.updateWardenSettings({ provider: "none" }));
    const result = await Effect.runPromise(service.requestCapability(req));
    expect(calls).toBe(0);
    // Null decision: deterministic policy requires approval.
    expect(result.status).toBe("awaiting-approval");
    const audit = await Effect.runPromise(service.listAudit());
    expect(audit.filter((e) => e.stage === "marshal")).toHaveLength(0);
    expect(JSON.stringify(audit)).not.toContain("sk-test-secret");

    // Settings are read per request: switching back re-enables the marshal.
    await Effect.runPromise(service.updateWardenSettings({ provider: "ollama" }));
    const second = await Effect.runPromise(
      service.requestCapability({ ...req, reason: "again" }),
    );
    expect(calls).toBe(1);
    expect(second.status).toBe("executed");
  });

  it("audit modelId reflects the settings model for Meta verdicts", async () => {
    const brain = Layer.succeed(Brain, {
      assess: () =>
        Effect.succeed({
          risk: "low" as const,
          recommendedScope: "charges.read",
          requireApproval: false,
          explanation: "ok",
        }),
    });
    const service = await makeService(brain);
    await Effect.runPromise(service.seedCredential("stripe", "charges.read", "[REDACTED]"));
    await Effect.runPromise(
      service.updateWardenSettings({
        provider: "meta-api",
        model: "muse-spark-1.2",
      }),
    );
    const result = await Effect.runPromise(service.requestCapability(req));
    expect(result.status).toBe("executed");
    const audit = await Effect.runPromise(service.listAudit());
    const marshal = audit.filter((e) => e.stage === "marshal");
    expect(marshal.length).toBeGreaterThan(0);
    expect(marshal.every((e) => e.modelId === "muse-spark-1.2")).toBe(
      true,
    );
  });
});
