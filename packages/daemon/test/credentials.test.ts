import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { handleVaultRequest } from "../src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../src/service.js";

const SECRET = "[REDACTED]";
const TOKEN = "test-daemon-token-credentials";

const BrainLowRisk = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({
      risk: "low" as const,
      recommendedScope: "charges.read",
      requireApproval: true,
      explanation: "ok",
    }),
});
const FakeConnector = Layer.succeed(Connector, {
  execute: (_a, _s, secret) => Effect.succeed({ echoedLength: secret.length }),
});

async function makeService(): Promise<VaultServiceService> {
  return Effect.runPromise(
    Effect.gen(function* () {
      return yield* VaultService;
    }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 7) })),
      Effect.provide(
        Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), BrainLowRisk, FakeConnector),
      ),
    ),
  );
}

describe("POST /credentials", () => {
  it("returns 401 without token and does not add the credential", async () => {
    const service = await makeService();
    const res = await handleVaultRequest(
      service,
      "POST",
      "/credentials",
      { alias: "stripe", scope: "charges.read", secret: SECRET },
      { daemonToken: TOKEN },
    );
    expect(res.status).toBe(401);
    expect(JSON.stringify(res.body)).not.toContain(SECRET);
    const aliases = await handleVaultRequest(service, "GET", "/aliases", undefined, {
      daemonToken: TOKEN,
      providedToken: TOKEN,
    });
    expect((aliases.body as { aliases: string[] }).aliases).not.toContain("stripe");
  });

  it("adds credential with token, GET /aliases reflects it, secret absent from response and audit", async () => {
    const service = await makeService();
    const res = await handleVaultRequest(
      service,
      "POST",
      "/credentials",
      { alias: "stripe", scope: "charges.read", secret: SECRET },
      { daemonToken: TOKEN, providedToken: TOKEN },
    );
    expect(res.status).toBe(201);
    expect(res.body).toEqual({ alias: "stripe", scope: "charges.read" });
    expect(JSON.stringify(res.body)).not.toContain(SECRET);

    const aliases = await handleVaultRequest(service, "GET", "/aliases");
    expect((aliases.body as { aliases: string[] }).aliases).toContain("stripe");

    const audit = await handleVaultRequest(service, "GET", "/audit");
    expect(JSON.stringify(audit.body)).not.toContain(SECRET);
    const events = (audit.body as { events: { stage: string; alias: string; scope: string; detail: string }[] }).events;
    const added = events.find((e) => e.stage === "credential-added");
    expect(added).toBeDefined();
    expect(added?.alias).toBe("stripe");
    expect(added?.scope).toBe("charges.read");
    expect(added?.detail).toContain("stripe");
    expect(added?.detail).toContain("charges.read");
    expect(added?.detail).not.toContain(SECRET);
  });

  it("returns 409 alias-exists on duplicate alias and keeps the original credential", async () => {
    const service = await makeService();
    const firstSecret = "first-secret-value";
    const secondSecret = "second-secret-value-much-longer";
    const first = await handleVaultRequest(
      service,
      "POST",
      "/credentials",
      { alias: "stripe", scope: "charges.read", secret: firstSecret },
      { daemonToken: TOKEN, providedToken: TOKEN },
    );
    expect(first.status).toBe(201);

    const dup = await handleVaultRequest(
      service,
      "POST",
      "/credentials",
      { alias: "stripe", scope: "charges.read", secret: secondSecret },
      { daemonToken: TOKEN, providedToken: TOKEN },
    );
    expect(dup.status).toBe(409);
    expect(JSON.stringify(dup.body)).toContain("alias-exists");
    expect(JSON.stringify(dup.body)).not.toContain(firstSecret);
    expect(JSON.stringify(dup.body)).not.toContain(secondSecret);

    // Original credential still decrypts/executes as before: requesting and
    // approving must echo the FIRST secret's length, not the second's.
    const requested = await handleVaultRequest(service, "POST", "/request", {
      agentId: "cursor",
      ide: "Cursor",
      tool: "http",
      alias: "stripe",
      requestedScope: "charges.read",
      reason: "check original credential",
    });
    expect(requested.status).toBe(200);
    const grantId = (requested.body as { grantId?: string }).grantId;
    expect(grantId).toBeDefined();
    const approved = await handleVaultRequest(
      service,
      "POST",
      "/approve",
      { grantId },
      { daemonToken: TOKEN, providedToken: TOKEN },
    );
    expect(approved.status).toBe(200);
    expect((approved.body as { result?: { echoedLength?: number } }).result?.echoedLength).toBe(
      firstSecret.length,
    );

    // Only one credential-added audit event: the duplicate added nothing.
    const audit = await handleVaultRequest(service, "GET", "/audit");
    const events = (audit.body as { events: { stage: string }[] }).events;
    expect(events.filter((e) => e.stage === "credential-added")).toHaveLength(1);
  });

  it("rejects a whitespace-only secret with 400", async () => {
    const service = await makeService();
    const res = await handleVaultRequest(
      service,
      "POST",
      "/credentials",
      { alias: "stripe", scope: "charges.read", secret: "   " },
      { daemonToken: TOKEN, providedToken: TOKEN },
    );
    expect(res.status).toBe(400);
    const aliases = await handleVaultRequest(service, "GET", "/aliases");
    expect((aliases.body as { aliases: string[] }).aliases).not.toContain("stripe");
  });

  it("rejects malformed bodies with 400", async () => {
    const service = await makeService();
    const bad = await handleVaultRequest(
      service,
      "POST",
      "/credentials",
      { alias: 42 },
      { daemonToken: TOKEN, providedToken: TOKEN },
    );
    expect(bad.status).toBe(400);
    const empty = await handleVaultRequest(
      service,
      "POST",
      "/credentials",
      { alias: "", scope: "charges.read", secret: SECRET },
      { daemonToken: TOKEN, providedToken: TOKEN },
    );
    expect(empty.status).toBe(400);
  });
});
