import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { handleVaultRequest } from "../src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../src/service.js";

const CANARY = "sk-pending-canary-1234567890";

const FakeConnector = Layer.succeed(Connector, {
  execute: (_a, _s, secret) => Effect.succeed({ echoedLength: secret.length }),
});

const brainReturning = (
  risk: "low" | "medium" | "high",
  recommendedScope: string,
  requireApproval: boolean,
) =>
  Layer.succeed(Brain, {
    assess: () =>
      Effect.succeed({ risk, recommendedScope, requireApproval, explanation: `risk is ${risk}` }),
  });

async function makeService(
  brain: Layer.Layer<Brain>,
  alias = "stripe",
  ceiling = "charges.read",
): Promise<VaultServiceService> {
  return Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* VaultService;
      yield* svc.seedCredential(alias, ceiling, CANARY);
      return svc;
    }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 7) })),
      Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), brain, FakeConnector)),
    ),
  );
}

const req = {
  agentId: "cursor",
  ide: "Cursor",
  tool: "http",
  alias: "stripe",
  requestedScope: "charges.read",
  reason: "list charges",
};

describe("pending approvals queue", () => {
  it("lists a pending approval with marshal decision and expiry, never the secret", async () => {
    const service = await makeService(brainReturning("low", "charges.read", true));
    const created = await handleVaultRequest(service, "POST", "/request", req);
    expect(created.status).toBe(200);
    const pending = await handleVaultRequest(service, "GET", "/pending");
    expect(pending.status).toBe(200);
    const body = pending.body as { approvals: Record<string, unknown>[] };
    expect(body.approvals).toHaveLength(1);
    const first = body.approvals[0] as Record<string, unknown>;
    expect(first["agentId"]).toBe("cursor");
    expect(first["alias"]).toBe("stripe");
    expect(first["allowedScope"]).toBe("charges.read");
    expect(first["reason"]).toBe("list charges");
    expect(first["risk"]).toBe("low");
    expect(first["marshalExplanation"]).toBe("risk is low");
    expect(typeof first["expiresAtMs"]).toBe("number");
    expect(JSON.stringify(pending.body)).not.toContain(CANARY);
  });

  it("approve-always executes once and makes the next identical request standing", async () => {
    const service = await makeService(brainReturning("low", "charges.read", true));
    const created = await handleVaultRequest(service, "POST", "/request", req);
    const grantId = (created.body as Record<string, unknown>)["grantId"] as string;
    const always = await handleVaultRequest(service, "POST", "/approve-always", { grantId });
    expect(always.status).toBe(200);
    expect((always.body as Record<string, unknown>)["status"]).toBe("executed");
    expect(JSON.stringify(always.body)).not.toContain(CANARY);

    const second = await handleVaultRequest(service, "POST", "/request", req);
    expect((second.body as Record<string, unknown>)["status"]).toBe("executed");
    const pending = await handleVaultRequest(service, "GET", "/pending");
    expect((pending.body as { approvals: unknown[] }).approvals).toHaveLength(0);
  });

  it("approve-always refuses write scopes and non-low risk with 403", async () => {
    const writeService = await makeService(brainReturning("low", "charges.write", true), "stripe", "charges.write");
    const writeReq = { ...req, requestedScope: "charges.write" };
    const writeCreated = await handleVaultRequest(writeService, "POST", "/request", writeReq);
    const writeGrant = (writeCreated.body as Record<string, unknown>)["grantId"] as string;
    expect(typeof writeGrant).toBe("string");
    const writeAlways = await handleVaultRequest(writeService, "POST", "/approve-always", {
      grantId: writeGrant,
    });
    expect(writeAlways.status).toBe(403);
    expect(JSON.stringify(writeAlways.body)).toContain("PolicyDenied");

    const mediumService = await makeService(brainReturning("medium", "charges.read", true));
    const mediumCreated = await handleVaultRequest(mediumService, "POST", "/request", req);
    const mediumGrant = (mediumCreated.body as Record<string, unknown>)["grantId"] as string;
    const mediumAlways = await handleVaultRequest(mediumService, "POST", "/approve-always", {
      grantId: mediumGrant,
    });
    expect(mediumAlways.status).toBe(403);
  });

  it("approve-always on a consumed grant maps to 409; pending drains after deny", async () => {
    const service = await makeService(brainReturning("low", "charges.read", true));
    const created = await handleVaultRequest(service, "POST", "/request", req);
    const grantId = (created.body as Record<string, unknown>)["grantId"] as string;
    const denied = await handleVaultRequest(service, "POST", "/deny", { grantId });
    expect(denied.status).toBe(200);
    const pending = await handleVaultRequest(service, "GET", "/pending");
    expect((pending.body as { approvals: unknown[] }).approvals).toHaveLength(0);
    const always = await handleVaultRequest(service, "POST", "/approve-always", { grantId });
    expect(always.status).toBe(409);
  });
});
