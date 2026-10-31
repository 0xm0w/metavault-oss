import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { createVaultHttpServer, handleVaultRequest } from "../src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../src/service.js";

const TOKEN = "test-daemon-token-settings";
const META_KEY = "meta-api-key-abcdef1234";
const auth = { daemonToken: TOKEN };
const withToken = { daemonToken: TOKEN, providedToken: TOKEN };

const BrainLowRisk = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({
      risk: "low" as const,
      recommendedScope: "charges.read",
      requireApproval: false,
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

const DEFAULTS = {
  provider: "ollama",
  model: "llama3.2:3b",
  effort: "standard",
  metaApiBaseUrl: "https://api.llama.com/v1",
};

describe("warden settings routes", () => {
  it("returns defaults on GET /settings/warden and requires the token", async () => {
    const service = await makeService();
    const noToken = await handleVaultRequest(service, "GET", "/settings/warden", undefined, auth);
    expect(noToken.status).toBe(401);
    const wrong = await handleVaultRequest(service, "GET", "/settings/warden", undefined, {
      daemonToken: TOKEN,
      providedToken: "wrong",
    });
    expect(wrong.status).toBe(401);
    const ok = await handleVaultRequest(service, "GET", "/settings/warden", undefined, withToken);
    expect(ok.status).toBe(200);
    expect(ok.body).toEqual(DEFAULTS);
  });

  it("PATCH persists provider/model/effort/baseUrl, validates input, and audits settings-changed with provider/model only", async () => {
    const service = await makeService();
    const noToken = await handleVaultRequest(
      service,
      "PATCH",
      "/settings/warden",
      { provider: "meta-api" },
      auth,
    );
    expect(noToken.status).toBe(401);

    const patched = await handleVaultRequest(
      service,
      "PATCH",
      "/settings/warden",
      {
        provider: "meta-api",
        model: "Llama-4-Maverick-17B-128E-Instruct-FP8",
        effort: "deep",
        metaApiBaseUrl: "https://api.llama.com/v1",
      },
      withToken,
    );
    expect(patched.status).toBe(200);
    expect(patched.body).toEqual({
      provider: "meta-api",
      model: "Llama-4-Maverick-17B-128E-Instruct-FP8",
      effort: "deep",
      metaApiBaseUrl: "https://api.llama.com/v1",
    });

    const reread = await handleVaultRequest(service, "GET", "/settings/warden", undefined, withToken);
    expect(reread.body).toEqual(patched.body);

    const partial = await handleVaultRequest(
      service,
      "PATCH",
      "/settings/warden",
      { effort: "fast" },
      withToken,
    );
    expect(partial.status).toBe(200);
    expect(partial.body).toEqual({ ...(patched.body as object), effort: "fast" });

    const badProvider = await handleVaultRequest(
      service,
      "PATCH",
      "/settings/warden",
      { provider: "openai" },
      withToken,
    );
    expect(badProvider.status).toBe(400);
    const badModel = await handleVaultRequest(
      service,
      "PATCH",
      "/settings/warden",
      { model: "   " },
      withToken,
    );
    expect(badModel.status).toBe(400);
    const badEffort = await handleVaultRequest(
      service,
      "PATCH",
      "/settings/warden",
      { effort: "turbo" },
      withToken,
    );
    expect(badEffort.status).toBe(400);

    const audit = await handleVaultRequest(service, "GET", "/audit");
    expect(JSON.stringify(audit.body)).not.toContain(META_KEY);
    const events = (
      audit.body as { events: { stage: string; detail: string }[] }
    ).events;
    const changed = events.filter((e) => e.stage === "settings-changed");
    expect(changed.length).toBeGreaterThanOrEqual(1);
    expect(changed[0]?.detail).toContain("meta-api");
    expect(changed[0]?.detail).toContain("Llama-4-Maverick-17B-128E-Instruct-FP8");
    expect(changed[0]?.detail).not.toContain("deep");
    expect(changed[0]?.detail).not.toContain("api.llama.com");
  });

  it("PUT key stores it encrypted: status is exactly {configured,last4}, raw key appears nowhere, DELETE clears", async () => {
    const service = await makeService();

    const statusBefore = await handleVaultRequest(
      service,
      "GET",
      "/settings/warden/key",
      undefined,
      withToken,
    );
    expect(statusBefore.status).toBe(200);
    expect(statusBefore.body).toEqual({ configured: false, last4: null });

    const putNoToken = await handleVaultRequest(
      service,
      "PUT",
      "/settings/warden/key",
      { key: META_KEY },
      auth,
    );
    expect(putNoToken.status).toBe(401);
    expect(JSON.stringify(putNoToken.body)).not.toContain(META_KEY);

    const put = await handleVaultRequest(
      service,
      "PUT",
      "/settings/warden/key",
      { key: META_KEY },
      withToken,
    );
    expect(put.status).toBe(200);
    expect(put.body).toEqual({ configured: true, last4: "1234" });
    expect(JSON.stringify(put.body)).not.toContain(META_KEY);

    const status = await handleVaultRequest(
      service,
      "GET",
      "/settings/warden/key",
      undefined,
      withToken,
    );
    expect(status.body).toEqual({ configured: true, last4: "1234" });
    expect(Object.keys(status.body as object).sort()).toEqual(["configured", "last4"]);

    const settings = await handleVaultRequest(service, "GET", "/settings/warden", undefined, withToken);
    expect(JSON.stringify(settings.body)).not.toContain(META_KEY);
    expect(JSON.stringify(settings.body)).not.toContain("warden-meta-api");

    // The warden key alias must never be agent-visible.
    const aliases = await handleVaultRequest(service, "GET", "/aliases");
    expect(JSON.stringify(aliases.body)).not.toContain("warden-meta-api");
    expect(JSON.stringify(aliases.body)).not.toContain(META_KEY);

    const audit = await handleVaultRequest(service, "GET", "/audit");
    expect(JSON.stringify(audit.body)).not.toContain(META_KEY);

    // An agent cannot spend the warden key through a capability request.
    const spend = await handleVaultRequest(service, "POST", "/request", {
      agentId: "cursor",
      ide: "Cursor",
      tool: "http",
      alias: "warden-meta-api",
      requestedScope: "warden.meta",
      reason: "try to spend warden key",
    });
    expect(spend.status).toBe(200);
    expect((spend.body as { status: string }).status).toBe("denied");
    expect(JSON.stringify(spend.body)).not.toContain(META_KEY);

    const empty = await handleVaultRequest(
      service,
      "PUT",
      "/settings/warden/key",
      { key: "   " },
      withToken,
    );
    expect(empty.status).toBe(400);
    const malformed = await handleVaultRequest(
      service,
      "PUT",
      "/settings/warden/key",
      { key: 42 },
      withToken,
    );
    expect(malformed.status).toBe(400);

    const delNoToken = await handleVaultRequest(
      service,
      "DELETE",
      "/settings/warden/key",
      undefined,
      auth,
    );
    expect(delNoToken.status).toBe(401);
    const del = await handleVaultRequest(service, "DELETE", "/settings/warden/key", undefined, withToken);
    expect(del.status).toBe(200);
    expect(del.body).toEqual({ configured: false, last4: null });
    const after = await handleVaultRequest(
      service,
      "GET",
      "/settings/warden/key",
      undefined,
      withToken,
    );
    expect(after.body).toEqual({ configured: false, last4: null });
  });

  it("serves PUT /settings/warden/key over real HTTP (body is read for PUT)", async () => {
    const service = await makeService();
    const server = createVaultHttpServer(service, { daemonToken: TOKEN });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (address === null || typeof address === "string") throw new Error("no port");
      const base = `http://127.0.0.1:${String(address.port)}`;
      const noToken = await fetch(`${base}/settings/warden/key`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ key: META_KEY }),
      });
      expect(noToken.status).toBe(401);
      const put = await fetch(`${base}/settings/warden/key`, {
        method: "PUT",
        headers: { "content-type": "application/json", "x-openvault-token": TOKEN },
        body: JSON.stringify({ key: META_KEY }),
      });
      expect(put.status).toBe(200);
      const body: unknown = await put.json();
      expect(body).toEqual({ configured: true, last4: "1234" });
      expect(JSON.stringify(body)).not.toContain(META_KEY);
    } finally {
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve();
        });
      });
    }
  });

  it("all settings routes are 401 without a token (MCP-side fetch cannot read settings)", async () => {
    const service = await makeService();
    const attempts: [string, string, unknown][] = [
      ["GET", "/settings/warden", undefined],
      ["PATCH", "/settings/warden", { provider: "none" }],
      ["GET", "/settings/warden/key", undefined],
      ["PUT", "/settings/warden/key", { key: META_KEY }],
      ["DELETE", "/settings/warden/key", undefined],
    ];
    for (const [method, path, body] of attempts) {
      const res = await handleVaultRequest(service, method, path, body, auth);
      expect(res.status, `${method} ${path}`).toBe(401);
      expect(JSON.stringify(res.body)).not.toContain(META_KEY);
    }
    // Nothing was mutated by the unauthenticated attempts.
    const settings = await handleVaultRequest(service, "GET", "/settings/warden", undefined, withToken);
    expect(settings.body).toEqual(DEFAULTS);
    const status = await handleVaultRequest(service, "GET", "/settings/warden/key", undefined, withToken);
    expect(status.body).toEqual({ configured: false, last4: null });
  });
});
