import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { ConnectorFailed } from "../../core/src/errors.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { handleVaultRequest } from "../src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../src/service.js";

const CANARY = "[REDACTED]";
const TOKEN = "policies-test-token";
const withToken = { daemonToken: TOKEN, providedToken: TOKEN };

const FakeConnector = Layer.succeed(Connector, {
  execute: (_a, _s, secret) => Effect.succeed({ echoedLength: secret.length }),
});

const FailingConnector = Layer.succeed(Connector, {
  execute: () => Effect.fail(new ConnectorFailed({ message: "connector boom" })),
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
  connector: Layer.Layer<Connector> = FakeConnector,
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
      Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), brain, connector)),
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

describe("GET /policies (real policy state, metadata only)", () => {
  it("exposes configured ceilings and empty standing approvals before any approval", async () => {
    const service = await makeService(brainReturning("low", "charges.read", true));
    const res = await handleVaultRequest(service, "GET", "/policies");
    expect(res.status).toBe(200);
    const body = res.body as {
      ceilings: Record<string, string>;
      standingApprovals: { agentId: string; alias: string; scope: string }[];
    };
    expect(body.ceilings).toEqual({ stripe: "charges.read" });
    expect(body.standingApprovals).toEqual([]);
    expect(JSON.stringify(res.body)).not.toContain(CANARY);
  });

  it("reflects a standing approval created by approve-always, still without secrets", async () => {
    const service = await makeService(brainReturning("low", "charges.read", true));
    const created = await handleVaultRequest(service, "POST", "/request", req);
    const grantId = (created.body as Record<string, unknown>)["grantId"] as string;
    const always = await handleVaultRequest(service, "POST", "/approve-always", { grantId }, withToken);
    expect(always.status).toBe(200);

    const res = await handleVaultRequest(service, "GET", "/policies");
    expect(res.status).toBe(200);
    const body = res.body as {
      ceilings: Record<string, string>;
      standingApprovals: { agentId: string; alias: string; scope: string }[];
    };
    expect(body.ceilings).toEqual({ stripe: "charges.read" });
    expect(body.standingApprovals).toEqual([
      { agentId: "cursor", alias: "stripe", scope: "charges.read" },
    ]);
    expect(JSON.stringify(res.body)).not.toContain(CANARY);
  });

  it("returns 404-free metadata for multiple aliases with distinct ceilings", async () => {
    const service = await Effect.runPromise(
      Effect.gen(function* () {
        const svc = yield* VaultService;
        yield* svc.seedCredential("stripe", "charges.read", CANARY);
        yield* svc.seedCredential("github", "repos.read", CANARY);
        return svc;
      }).pipe(
        Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 7) })),
        Effect.provide(
          Layer.mergeAll(
            VaultStoreTest(Buffer.alloc(32, 7)),
            brainReturning("low", "charges.read", true),
            FakeConnector,
          ),
        ),
      ),
    );
    const res = await handleVaultRequest(service, "GET", "/policies");
    expect(res.status).toBe(200);
    const body = res.body as { ceilings: Record<string, string> };
    expect(body.ceilings).toEqual({ github: "repos.read", stripe: "charges.read" });
    expect(JSON.stringify(res.body)).not.toContain(CANARY);
  });
});

describe("approve-always ordering (standing approval only after successful execution)", () => {
  it("leaves no standing approval when execution fails", async () => {
    const service = await makeService(
      brainReturning("low", "charges.read", true),
      FailingConnector,
    );
    const created = await handleVaultRequest(service, "POST", "/request", req);
    const grantId = (created.body as Record<string, unknown>)["grantId"] as string;
    expect(typeof grantId).toBe("string");

    const always = await handleVaultRequest(service, "POST", "/approve-always", { grantId }, withToken);
    expect(always.status).toBe(502);
    expect(JSON.stringify(always.body)).toContain("ConnectorFailed");

    const res = await handleVaultRequest(service, "GET", "/policies");
    const body = res.body as { standingApprovals: unknown[] };
    expect(body.standingApprovals).toEqual([]);

    // A later identical request must still require approval (no standing grant leaked).
    const second = await handleVaultRequest(service, "POST", "/request", req);
    expect((second.body as Record<string, unknown>)["status"]).toBe("awaiting-approval");
  });
});

describe("GET /policies token hygiene (F2 regression)", () => {
  it("never exposes agent bearer tokens on the open /policies route", async () => {
    const service = await makeService(brainReturning("low", "charges.read", true));
    const res = await handleVaultRequest(service, "GET", "/policies");
    expect(res.status).toBe(200);
    const body = res.body as {
      agents: { id: string; name: string; createdAt: string; revoked: boolean }[];
    };
    expect(body.agents.length).toBeGreaterThanOrEqual(4);
    for (const agent of body.agents) {
      expect(agent).not.toHaveProperty("token");
      expect(typeof agent.id).toBe("string");
      expect(typeof agent.name).toBe("string");
    }
    expect(JSON.stringify(res.body)).not.toContain("ov_agent_");
  });

  it("lists only metadata even through guarded GET /agents", async () => {
    const service = await makeService(brainReturning("low", "charges.read", true));
    const denied = await handleVaultRequest(service, "GET", "/agents");
    expect(denied.status).toBe(401);

    const allowed = await handleVaultRequest(service, "GET", "/agents", undefined, withToken);
    expect(allowed.status).toBe(200);
    const agents = allowed.body as { id: string; token: string }[];
    expect(agents.length).toBeGreaterThanOrEqual(4);
    const cursor = agents.find((a) => a.id === "cursor");
    expect(cursor?.token).toBe("");
  });
});
