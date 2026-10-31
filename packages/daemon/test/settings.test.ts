import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";
import { Brain, MarshalUnavailable } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { encryptSecret } from "../../core/src/crypto.js";
import { WARDEN_KEY_ALIAS, WARDEN_KEY_SCOPE } from "../../core/src/settings.js";
import { VaultStore, VaultStoreTest } from "../../core/src/storage.js";
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

async function makeService(brain: Layer.Layer<Brain> = BrainLowRisk): Promise<VaultServiceService> {
  return Effect.runPromise(
    Effect.gen(function* () {
      return yield* VaultService;
    }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 7) })),
      Effect.provide(
        Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), brain, FakeConnector),
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

  it("rejects short warden keys (<=4 chars and <8 chars) with 400, stores nothing, and echoes nothing", async () => {
    const service = await makeService();
    for (const shortKey of ["abcd", "abc", "abcdefg"]) {
      const put = await handleVaultRequest(
        service,
        "PUT",
        "/settings/warden/key",
        { key: shortKey },
        withToken,
      );
      expect(put.status, `key length ${String(shortKey.length)}`).toBe(400);
      expect(JSON.stringify(put.body)).not.toContain(shortKey);
      const status = await handleVaultRequest(
        service,
        "GET",
        "/settings/warden/key",
        undefined,
        withToken,
      );
      expect(status.body).toEqual({ configured: false, last4: null });
      expect(JSON.stringify(status.body)).not.toContain(shortKey);
    }
    // Service-level callers must not be able to store/echo a short key either.
    const exit = await Effect.runPromiseExit(service.setWardenKey("abcd"));
    expect(exit._tag).toBe("Failure");
    const status = await handleVaultRequest(service, "GET", "/settings/warden/key", undefined, withToken);
    expect(status.body).toEqual({ configured: false, last4: null });
  });

  it("status never echoes a pre-existing short warden key in full (last4 is null when length <= 4)", async () => {
    const masterKey = Buffer.alloc(32, 7);
    const planted = await Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* VaultStore;
        const svc = yield* VaultService;
        yield* store.addCredential(
          WARDEN_KEY_ALIAS,
          WARDEN_KEY_SCOPE,
          encryptSecret(masterKey, "abcd"),
          "",
        );
        return yield* svc.wardenKeyStatus();
      }).pipe(
        Effect.provide(makeVaultServiceLive({ masterKey })),
        Effect.provide(Layer.mergeAll(VaultStoreTest(masterKey), BrainLowRisk, FakeConnector)),
      ),
    );
    expect(planted).toEqual({ configured: true, last4: null });
    expect(JSON.stringify(planted)).not.toContain("abcd");
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

  it("POST /settings/warden/test runs one synthetic marshal assessment, with no audit rows or grants", async () => {
    const seen: unknown[] = [];
    const capturing = Layer.succeed(Brain, {
      assess: (req) => {
        seen.push(req);
        return Effect.succeed({ risk: "low" as const, recommendedScope: "selfcheck.read", requireApproval: false, explanation: "ok" });
      },
    });
    const service = await makeService(capturing);
    const auditBefore = await Effect.runPromise(service.listAudit());
    const noToken = await handleVaultRequest(service, "POST", "/settings/warden/test", undefined, auth);
    expect(noToken.status).toBe(401);
    expect(seen).toHaveLength(0);
    const res = await handleVaultRequest(service, "POST", "/settings/warden/test", undefined, withToken);
    expect(res.status).toBe(200);
    expect(Object.keys(res.body as object).sort()).toEqual(["detail", "latencyMs", "model", "ok", "provider"]);
    const body = res.body as { ok: boolean; provider: string; model: string; latencyMs: number; detail: string };
    expect(body.ok).toBe(true);
    expect(body.provider).toBe("ollama");
    expect(body.model).toBe("llama3.2:3b");
    expect(typeof body.latencyMs).toBe("number");
    expect(body.latencyMs).toBeGreaterThanOrEqual(0);
    expect(body.detail).toBe("ok");
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ agentId: "openvault-selfcheck", alias: "selfcheck", requestedScope: "selfcheck.read", reason: "warden connection test" });
    const auditAfter = await Effect.runPromise(service.listAudit());
    expect(auditAfter).toHaveLength(auditBefore.length);
    expect(await Effect.runPromise(service.listPendingApprovals())).toHaveLength(0);
  });

  it("POST /settings/warden/test maps brain failure to ok:false with a fixed safe detail", async () => {
    const failing = Layer.succeed(Brain, {
      assess: () => Effect.fail(new MarshalUnavailable({ message: "MarshalUnavailable: provider exploded apiKey=canary-secret-9999" })),
    });
    const service = await makeService(failing);
    const auditBefore = await Effect.runPromise(service.listAudit());
    const res = await handleVaultRequest(service, "POST", "/settings/warden/test", undefined, withToken);
    expect(res.status).toBe(200);
    const body = res.body as { ok: boolean; provider: string; model: string; latencyMs: number; detail: string };
    expect(body.ok).toBe(false);
    expect(body.provider).toBe("ollama");
    expect(body.detail).toBe("warden unavailable");
    expect(JSON.stringify(res.body)).not.toContain("canary");
    expect(JSON.stringify(res.body)).not.toContain("provider exploded");
    expect(await Effect.runPromise(service.listAudit())).toHaveLength(auditBefore.length);
    expect(await Effect.runPromise(service.listPendingApprovals())).toHaveLength(0);
  });

  it("POST /settings/warden/test returns policy-only for provider none without calling the brain", async () => {
    let calls = 0;
    const counting = Layer.succeed(Brain, {
      assess: () => { calls += 1; return Effect.succeed({ risk: "low" as const, recommendedScope: "selfcheck.read", requireApproval: false, explanation: "ok" }); },
    });
    const service = await makeService(counting);
    await handleVaultRequest(service, "PATCH", "/settings/warden", { provider: "none" }, withToken);
    const auditBefore = await Effect.runPromise(service.listAudit());
    const res = await handleVaultRequest(service, "POST", "/settings/warden/test", undefined, withToken);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ ok: true, provider: "none", detail: "policy-only" });
    expect(typeof (res.body as { latencyMs: unknown }).latencyMs).toBe("number");
    expect(calls).toBe(0);
    expect(await Effect.runPromise(service.listAudit())).toHaveLength(auditBefore.length);
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
