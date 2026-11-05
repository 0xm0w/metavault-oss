import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { ConnectorFailed } from "../../core/src/errors.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { handleVaultRequest } from "../src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../src/service.js";

const SECRET = "cf-token-value";

interface SeenCall {
  readonly alias: string;
  readonly scope: string;
  readonly tool: string | undefined;
  readonly payload: unknown;
}

async function makeService(
  seen: SeenCall[],
  failStatus?: number,
): Promise<{ readonly service: VaultServiceService; readonly token: string }> {
  const brain = Layer.succeed(Brain, {
    assess: () =>
      Effect.succeed({
        risk: "low" as const,
        recommendedScope: "dns.read",
        requireApproval: false,
        explanation: "read",
      }),
  });
  const connector = Layer.succeed(Connector, {
    execute: (alias, scope, _secret, payload, tool) => {
      seen.push({ alias, scope, tool, payload });
      return failStatus === undefined
        ? Effect.succeed({ ok: true })
        : Effect.fail(new ConnectorFailed({ status: failStatus, message: `ConnectorFailed: upstream returned HTTP ${String(failStatus)}` }));
    },
  });
  const service = await Effect.runPromise(
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
  return { service, token: agent.token };
}

describe("capability payload", () => {
  it("forwards tool and payload to the connector on an executed read", async () => {
    const seen: SeenCall[] = [];
    const { service, token } = await makeService(seen);
    const payload = { method: "GET", path: "/zones", query: { name: "goodrecmovies.com" } };
    const res = await handleVaultRequest(service, "POST", "/request", {
      agentId: "cursor",
      ide: "Cursor",
      tool: "cloudflare.dns",
      alias: "cloudflare",
      requestedScope: "dns.read",
      reason: "find the zone",
      agentToken: token,
      payload,
    });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: "executed", result: { ok: true } });
    expect(JSON.stringify(res.body)).not.toContain(SECRET);
    expect(seen).toEqual([
      { alias: "cloudflare", scope: "dns.read", tool: "cloudflare.dns", payload },
    ]);
  });

  it("returns the upstream status when the connector fails, and not the secret", async () => {
    const seen: SeenCall[] = [];
    const { service, token } = await makeService(seen, 401);
    const res = await handleVaultRequest(service, "POST", "/request", {
      agentId: "cursor",
      ide: "Cursor",
      tool: "http",
      alias: "cloudflare",
      requestedScope: "dns.read",
      reason: "verify token",
      agentToken: token,
    });
    expect(res.body).toMatchObject({ status: "denied", reason: "connector-failed", upstreamStatus: 401 });
    expect(JSON.stringify(res.body)).not.toContain(SECRET);
  });
});
