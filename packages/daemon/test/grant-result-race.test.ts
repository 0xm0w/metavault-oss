import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { ConnectorFailed } from "../../core/src/errors.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { handleVaultRequest } from "../src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../src/service.js";

// The registry marks a grant executed before the connector returns. A client
// that picks up the result in that window must be told to wait, not that the
// result is gone.

const SECRET = "cf-token-value";

describe("grant result pickup", () => {
  it("stays non-terminal while the connector is still running, then delivers the body once", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const brain = Layer.succeed(Brain, {
      assess: () =>
        Effect.succeed({
          risk: "low" as const,
          recommendedScope: "dns.read",
          requireApproval: true,
          explanation: "read",
        }),
    });
    const connector = Layer.succeed(Connector, {
      execute: () =>
        Effect.promise(async () => {
          await gate;
          return { zoneId: "0123456789abcdef0123456789abcdef" };
        }),
    });
    const service: VaultServiceService = await Effect.runPromise(
      Effect.gen(function* () {
        const svc = yield* VaultService;
        yield* svc.seedCredential("cloudflare", "dns.read", SECRET, "cloudflare.com");
        return svc;
      }).pipe(
        Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 7) })),
        Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), brain, connector)),
      ),
    );
    const agent = await Effect.runPromise(service.registerAgent("cursor", "Cursor"));
    const created = await handleVaultRequest(service, "POST", "/request", {
      agentId: "cursor",
      ide: "Cursor",
      tool: "cloudflare.dns",
      alias: "cloudflare",
      requestedScope: "dns.read",
      reason: "find the zone",
      agentToken: agent.token,
      payload: { method: "GET", path: "/zones", query: { name: "goodrecmovies.com" } },
    });
    const createdBody = created.body as { status: string; grantId: string; receipt: string };
    expect(createdBody.status).toBe("awaiting-approval");
    const grantId = createdBody.grantId;
    const receipt = createdBody.receipt;
    const approval = Effect.runPromise(service.approve(grantId));
    let executed = false;
    for (let i = 0; i < 50; i++) {
      const grant = await Effect.runPromise(service.getGrant(grantId));
      if (grant?.status === "executed") {
        executed = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(executed).toBe(true);

    const mid = await handleVaultRequest(service, "GET", `/grants/${grantId}`, undefined, { providedGrantReceipt: receipt });
    expect(mid.status).toBe(200);
    expect(mid.body).toMatchObject({ grantId, status: "executed", terminal: false });

    const early = await handleVaultRequest(service, "POST", `/grants/${grantId}/result`, undefined, { providedGrantReceipt: receipt });
    expect(early.status).not.toBe(410);
    expect(early.body).toMatchObject({ grantId, status: "pending" });

    release();
    const approved = await approval;
    expect(approved.result).toMatchObject({ zoneId: "0123456789abcdef0123456789abcdef" });
    expect(JSON.stringify(approved)).not.toContain(SECRET);

    const taken = await handleVaultRequest(service, "POST", `/grants/${grantId}/result`, undefined, { providedGrantReceipt: receipt });
    expect(taken.status).toBe(200);
    expect(taken.body).toMatchObject({
      grantId,
      status: "delivered",
      result: { zoneId: "0123456789abcdef0123456789abcdef" },
    });
    expect(JSON.stringify(taken.body)).not.toContain(SECRET);
  });

  it("delivers a connector failure to the pickup instead of reporting the result gone", async () => {
    let release: (failed: boolean) => void = () => {};
    const gate = new Promise<boolean>((resolve) => {
      release = resolve;
    });
    const brain = Layer.succeed(Brain, {
      assess: () =>
        Effect.succeed({
          risk: "low" as const,
          recommendedScope: "dns.read",
          requireApproval: true,
          explanation: "read",
        }),
    });
    const connector = Layer.succeed(Connector, {
      execute: () =>
        Effect.tryPromise({
          try: async () => {
            const failed = await gate;
            if (failed) throw new ConnectorFailed({ status: 401, message: "upstream 401" });
            return { ok: true };
          },
          catch: (err) => (err instanceof ConnectorFailed ? err : new ConnectorFailed({ message: "connector failed" })),
        }),
    });
    const service: VaultServiceService = await Effect.runPromise(
      Effect.gen(function* () {
        const svc = yield* VaultService;
        yield* svc.seedCredential("cloudflare", "dns.read", SECRET, "cloudflare.com");
        return svc;
      }).pipe(
        Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 7) })),
        Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), brain, connector)),
      ),
    );
    const agent = await Effect.runPromise(service.registerAgent("cursor", "Cursor"));
    const created = await handleVaultRequest(service, "POST", "/request", {
      agentId: "cursor",
      ide: "Cursor",
      tool: "cloudflare.dns",
      alias: "cloudflare",
      requestedScope: "dns.read",
      reason: "find the zone",
      agentToken: agent.token,
    });
    const createdBody = created.body as { grantId: string; receipt: string };
    const approval = Effect.runPromise(service.approve(createdBody.grantId)).then(
      () => "ok" as const,
      () => "failed" as const,
    );
    let executed = false;
    for (let i = 0; i < 50; i++) {
      const grant = await Effect.runPromise(service.getGrant(createdBody.grantId));
      if (grant?.status === "executed") {
        executed = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(executed).toBe(true);
    release(true);
    expect(await approval).toBe("failed");
    const taken = await handleVaultRequest(service, "POST", `/grants/${createdBody.grantId}/result`, undefined, {
      providedGrantReceipt: createdBody.receipt,
    });
    expect(taken.status).toBe(200);
    expect(taken.body).toMatchObject({
      status: "delivered",
      result: { status: "denied", reason: "connector-failed", upstreamStatus: 401 },
    });
    expect(JSON.stringify(taken.body)).not.toContain(SECRET);
  });
});
