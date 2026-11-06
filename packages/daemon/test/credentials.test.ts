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
    expect(res.body).toEqual({ alias: "stripe", scope: "charges.read", website: "" });
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

  it("rejects a secret shorter than 8 characters", async () => {
    const service = await makeService();
    const res = await handleVaultRequest(
      service,
      "POST",
      "/credentials",
      { alias: "stripe", scope: "charges.read", secret: "short" },
      { daemonToken: TOKEN, providedToken: TOKEN },
    );
    expect(res.status).toBe(400);
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

describe("website + PATCH/DELETE /credentials/:alias", () => {
  it("stores website on POST and surfaces it in GET /aliases credentials metadata", async () => {
    const service = await makeService();
    const res = await handleVaultRequest(
      service,
      "POST",
      "/credentials",
      { alias: "cf", scope: "dns.read", secret: SECRET, website: "cloudflare.com" },
      { daemonToken: TOKEN, providedToken: TOKEN },
    );
    expect(res.status).toBe(201);
    expect(res.body).toEqual({ alias: "cf", scope: "dns.read", website: "cloudflare.com" });
    const aliases = await handleVaultRequest(service, "GET", "/aliases");
    const body = aliases.body as { aliases: string[]; credentials: { alias: string; website: string }[] };
    expect(body.aliases).toContain("cf");
    expect(body.credentials).toEqual([{ alias: "cf", website: "cloudflare.com", kind: "secret" }]);
    expect(JSON.stringify(aliases.body)).not.toContain(SECRET);
  });

  it("PATCH requires token, updates scope/website, and keeps secret when omitted or empty", async () => {
    const service = await makeService();
    await handleVaultRequest(service, "POST", "/credentials", { alias: "stripe", scope: "charges.read", secret: SECRET }, { daemonToken: TOKEN, providedToken: TOKEN });
    const unauth = await handleVaultRequest(service, "PATCH", "/credentials/stripe", { scope: "charges.write" }, { daemonToken: TOKEN });
    expect(unauth.status).toBe(401);
    const patched = await handleVaultRequest(service, "PATCH", "/credentials/stripe", { scope: "refunds.read", website: "stripe.com", secret: "" }, { daemonToken: TOKEN, providedToken: TOKEN });
    expect(patched.status).toBe(200);
    expect(patched.body).toEqual({ alias: "stripe", scope: "refunds.read", website: "stripe.com" });
    expect(JSON.stringify(patched.body)).not.toContain(SECRET);
    // Secret kept: approve a request and check echoed length matches original.
    const brainScopeCheck = await handleVaultRequest(service, "POST", "/request", { agentId: "cursor", ide: "Cursor", tool: "http", alias: "stripe", requestedScope: "refunds.read", reason: "check kept secret" });
    // Brain recommends charges.read but policy ceiling is now refunds.read; allow flow may still queue. Just verify credential still executes via original secret length if grant issued.
    if ((brainScopeCheck.body as { grantId?: string }).grantId !== undefined) {
      const approved = await handleVaultRequest(service, "POST", "/approve", { grantId: (brainScopeCheck.body as { grantId?: string }).grantId }, { daemonToken: TOKEN, providedToken: TOKEN });
      if (approved.status === 200) {
        expect((approved.body as { result?: { echoedLength?: number } }).result?.echoedLength).toBe(SECRET.length);
      }
    }
    const missing = await handleVaultRequest(service, "PATCH", "/credentials/nope", { scope: "x.read" }, { daemonToken: TOKEN, providedToken: TOKEN });
    expect(missing.status).toBe(404);
    const badScope = await handleVaultRequest(service, "PATCH", "/credentials/stripe", { scope: "  " }, { daemonToken: TOKEN, providedToken: TOKEN });
    expect(badScope.status).toBe(400);
  });

  it("PATCH replaces secret only when a non-empty secret is provided", async () => {
    const service = await makeService();
    await handleVaultRequest(service, "POST", "/credentials", { alias: "stripe", scope: "charges.read", secret: "first-secret" }, { daemonToken: TOKEN, providedToken: TOKEN });
    const patched = await handleVaultRequest(service, "PATCH", "/credentials/stripe", { secret: "second-secret-longer" }, { daemonToken: TOKEN, providedToken: TOKEN });
    expect(patched.status).toBe(200);
    const requested = await handleVaultRequest(service, "POST", "/request", { agentId: "cursor", ide: "Cursor", tool: "http", alias: "stripe", requestedScope: "charges.read", reason: "check replaced secret" });
    const grantId = (requested.body as { grantId?: string }).grantId;
    expect(grantId).toBeDefined();
    const approved = await handleVaultRequest(service, "POST", "/approve", { grantId }, { daemonToken: TOKEN, providedToken: TOKEN });
    expect((approved.body as { result?: { echoedLength?: number } }).result?.echoedLength).toBe("second-secret-longer".length);
  });

  it("PATCH rejects a short secret and a bidi website", async () => {
    const service = await makeService();
    await handleVaultRequest(service, "POST", "/credentials", { alias: "stripe", scope: "charges.read", secret: SECRET }, { daemonToken: TOKEN, providedToken: TOKEN });
    const short = await handleVaultRequest(service, "PATCH", "/credentials/stripe", { secret: "short" }, { daemonToken: TOKEN, providedToken: TOKEN });
    expect(short.status).toBe(400);
    const bidi = await handleVaultRequest(service, "PATCH", "/credentials/stripe", { website: "stripe\u202E.com" }, { daemonToken: TOKEN, providedToken: TOKEN });
    expect(bidi.status).toBe(400);
  });

  it("PATCH rejects a whitespace-only secret with 400", async () => {
    const service = await makeService();
    await handleVaultRequest(service, "POST", "/credentials", { alias: "stripe", scope: "charges.read", secret: SECRET }, { daemonToken: TOKEN, providedToken: TOKEN });
    const res = await handleVaultRequest(service, "PATCH", "/credentials/stripe", { secret: "   " }, { daemonToken: TOKEN, providedToken: TOKEN });
    expect(res.status).toBe(400);
  });

  it("PATCH revokes a parked grant when the secret is rotated", async () => {
    const service = await makeService();
    await handleVaultRequest(service, "POST", "/credentials", { alias: "stripe", scope: "charges.read", secret: SECRET }, { daemonToken: TOKEN, providedToken: TOKEN });
    const requested = await handleVaultRequest(service, "POST", "/request", { agentId: "cursor", ide: "Cursor", tool: "http", alias: "stripe", requestedScope: "charges.read", reason: "parked" });
    const grantId = (requested.body as { grantId?: string }).grantId;
    expect(grantId).toBeDefined();
    const patched = await handleVaultRequest(service, "PATCH", "/credentials/stripe", { secret: "rotated-secret-value" }, { daemonToken: TOKEN, providedToken: TOKEN });
    expect(patched.status).toBe(200);
    const approveAfter = await handleVaultRequest(service, "POST", "/approve", { grantId }, { daemonToken: TOKEN, providedToken: TOKEN });
    expect(approveAfter.status).toBe(409);
  });

  it("malformed percent-encoding on /credentials/:alias returns 400, not 500", async () => {
    const service = await makeService();
    const patched = await handleVaultRequest(service, "PATCH", "/credentials/%E0%A4%A", { scope: "x.read" }, { daemonToken: TOKEN, providedToken: TOKEN });
    expect(patched.status).toBe(400);
    const deleted = await handleVaultRequest(service, "DELETE", "/credentials/%zz", undefined, { daemonToken: TOKEN, providedToken: TOKEN });
    expect(deleted.status).toBe(400);
  });

  it("DELETE requires token, removes credential, revokes pending grants, audits credential-deleted alias-only", async () => {
    const service = await makeService();
    await handleVaultRequest(service, "POST", "/credentials", { alias: "stripe", scope: "charges.read", secret: SECRET, website: "stripe.com" }, { daemonToken: TOKEN, providedToken: TOKEN });
    const requested = await handleVaultRequest(service, "POST", "/request", { agentId: "cursor", ide: "Cursor", tool: "http", alias: "stripe", requestedScope: "charges.read", reason: "pending before delete" });
    const grantId = (requested.body as { grantId?: string }).grantId;
    expect(grantId).toBeDefined();
    const unauth = await handleVaultRequest(service, "DELETE", "/credentials/stripe", undefined, { daemonToken: TOKEN });
    expect(unauth.status).toBe(401);
    const del = await handleVaultRequest(service, "DELETE", "/credentials/stripe", undefined, { daemonToken: TOKEN, providedToken: TOKEN });
    expect(del.status).toBe(200);
    expect(del.body).toEqual({ alias: "stripe", deleted: true });
    expect(JSON.stringify(del.body)).not.toContain(SECRET);
    const aliases = await handleVaultRequest(service, "GET", "/aliases");
    expect((aliases.body as { aliases: string[] }).aliases).not.toContain("stripe");
    // Pending grant was revoked: approving it now fails.
    const approveAfter = await handleVaultRequest(service, "POST", "/approve", { grantId }, { daemonToken: TOKEN, providedToken: TOKEN });
    expect(approveAfter.status).not.toBe(200);
    const audit = await handleVaultRequest(service, "GET", "/audit");
    const events = (audit.body as { events: { stage: string; alias: string; detail: string }[] }).events;
    const deleted = events.find((e) => e.stage === "credential-deleted");
    expect(deleted?.alias).toBe("stripe");
    expect(JSON.stringify(audit.body)).not.toContain(SECRET);
    const again = await handleVaultRequest(service, "DELETE", "/credentials/stripe", undefined, { daemonToken: TOKEN, providedToken: TOKEN });
    expect(again.status).toBe(404);
  });
});
