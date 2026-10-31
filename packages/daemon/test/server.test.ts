import { Effect, Layer } from "effect";
import { beforeAll, describe, expect, it } from "vitest";
import { Brain, MarshalUnavailable } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { handleVaultRequest, statusForErrorTag } from "../src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../src/service.js";

const BrainLowRisk = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({ risk: "low" as const, recommendedScope: "charges.read", requireApproval: true, explanation: "ok" }),
});
const FakeConnector = Layer.succeed(Connector, {
  execute: (_a, _s, secret) => Effect.succeed({ echoedLength: secret.length }),
});

let service: VaultServiceService;

beforeAll(async () => {
  service = await Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* VaultService;
      yield* svc.seedCredential("stripe", "charges.read", "[REDACTED]");
      return svc;
    }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 7) })),
      Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), BrainLowRisk, FakeConnector)),
    ),
  );
});

// The sandboxed shell forbids listening sockets (EACCES on 127.0.0.1), so the
// HTTP edge is exercised through handleVaultRequest — the exact function the
// node:http server delegates to — plus a bind-address assertion in code.
describe("vaultd HTTP edge (handler level)", () => {
  it("runs request -> approve without leaking the secret; reuse maps to 409", async () => {
    const first = await handleVaultRequest(service, "POST", "/request", {
      agentId: "cursor",
      ide: "Cursor",
      tool: "http",
      alias: "stripe",
      requestedScope: "charges.read",
      reason: "list",
    });
    expect(first.status).toBe(200);
    const firstBody = first.body as Record<string, unknown>;
    expect(firstBody["status"]).toBe("awaiting-approval");
    expect(JSON.stringify(first.body)).not.toContain("[REDACTED]");
    const grantId = firstBody["grantId"] as string;
    expect(typeof grantId).toBe("string");

    const done = await handleVaultRequest(service, "POST", "/approve", { grantId });
    expect(done.status).toBe(200);
    expect((done.body as Record<string, unknown>)["status"]).toBe("executed");
    expect(JSON.stringify(done.body)).not.toContain("[REDACTED]");

    const again = await handleVaultRequest(service, "POST", "/approve", { grantId });
    expect(again.status).toBe(409);
    expect(JSON.stringify(again.body)).toContain("GrantExpired");
    expect(JSON.stringify(again.body)).not.toContain("[REDACTED]");
  });

  it("lists aliases and audit without secrets", async () => {
    const aliases = await handleVaultRequest(service, "GET", "/aliases");
    expect(aliases.status).toBe(200);
    expect((aliases.body as { aliases: string[] }).aliases).toContain("stripe");

    const audit = await handleVaultRequest(service, "GET", "/audit");
    expect(audit.status).toBe(200);
    expect(JSON.stringify(audit.body)).not.toContain("[REDACTED]");
    expect(JSON.stringify(audit.body)).toContain("executed");
  });

  it("deny and revoke round-trip; malformed bodies 400, unknown routes 404", async () => {
    const pending = await handleVaultRequest(service, "POST", "/request", {
      agentId: "cursor",
      ide: "Cursor",
      tool: "http",
      alias: "stripe",
      requestedScope: "charges.read",
      reason: "list",
    });
    const grantId = (pending.body as Record<string, unknown>)["grantId"] as string;
    const denied = await handleVaultRequest(service, "POST", "/deny", { grantId });
    expect(denied.status).toBe(200);
    const approveDenied = await handleVaultRequest(service, "POST", "/approve", { grantId });
    expect(approveDenied.status).toBe(409);

    const revoked = await handleVaultRequest(service, "POST", "/revoke", { target: "cursor" });
    expect(revoked.status).toBe(200);
    const afterRevoke = await handleVaultRequest(service, "POST", "/request", {
      agentId: "cursor",
      ide: "Cursor",
      tool: "http",
      alias: "stripe",
      requestedScope: "charges.read",
      reason: "list",
    });
    expect((afterRevoke.body as Record<string, unknown>)["status"]).toBe("denied");

    const bad = await handleVaultRequest(service, "POST", "/request", { agentId: 42 });
    expect(bad.status).toBe(400);
    const missing = await handleVaultRequest(service, "GET", "/nope");
    expect(missing.status).toBe(404);
  });

  it("maps tagged errors to the documented HTTP statuses", () => {
    expect(statusForErrorTag("GrantExpired")).toBe(409);
    expect(statusForErrorTag("GrantRevoked")).toBe(409);
    expect(statusForErrorTag("PolicyDenied")).toBe(403);
    expect(statusForErrorTag("UnknownAlias")).toBe(403);
    expect(statusForErrorTag("ConnectorFailed")).toBe(502);
    expect(statusForErrorTag("StorageError")).toBe(500);
    expect(new MarshalUnavailable()._tag).toBe("MarshalUnavailable");
  });
});
