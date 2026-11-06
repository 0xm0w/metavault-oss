import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { createKeySession } from "../../core/src/key-session.js";
import { wrapMasterKey } from "../../core/src/keywrap.js";
import { DEFAULT_WARDEN_SETTINGS } from "../../core/src/settings.js";
import { VaultStore, VaultStoreScoped, VaultStoreTest } from "../../core/src/storage.js";
import { subscribeVaultEvents, vaultEventData, type VaultLiveEvent } from "../src/live-events.js";
import { inspectProcess } from "../src/process-inspector.js";
import { handleVaultRequest } from "../src/server.js";
import { makeVaultServiceLive, VaultService } from "../src/service.js";
import {
  invalidateWardenCache,
  readCachedWardenKey,
  readCachedWardenSettings,
  writeCachedWardenKey,
  writeCachedWardenSettings,
} from "../src/warden-cache.js";

const CANARY = "sk-canary-speed-standing-99887766";

describe("SQLite velocity stats, persistent standing fast-path, and live SSE/long-poll events", () => {
  it("computes exact 1h / 24h velocity counts via getAgentAuditStats", async () => {
    const now = Date.parse("2026-11-06T12:00:00.000Z");
    const since1h = new Date(now - 3_600_000).toISOString();
    const since24h = new Date(now - 86_400_000).toISOString();

    const stats = await Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* VaultStore;
        yield* store.appendAudit({
          ts: new Date(now - 10 * 60_000).toISOString(),
          agentId: "cursor",
          alias: "openai",
          scope: "models.read",
          stage: "requested",
          detail: "recent",
        });
        yield* store.appendAudit({
          ts: new Date(now - 5 * 60_000).toISOString(),
          agentId: "cursor",
          alias: "openai",
          scope: "models.read",
          stage: "denied",
          detail: "denied recent",
        });
        yield* store.appendAudit({
          ts: new Date(now - 3 * 3_600_000).toISOString(),
          agentId: "cursor",
          alias: "openai",
          scope: "models.read",
          stage: "requested",
          detail: "3h ago",
        });
        yield* store.appendAudit({
          ts: new Date(now - 48 * 3_600_000).toISOString(),
          agentId: "cursor",
          alias: "openai",
          scope: "models.read",
          stage: "requested",
          detail: "48h ago",
        });
        return yield* store.getAgentAuditStats("cursor", since1h, since24h);
      }).pipe(Effect.provide(VaultStoreTest())),
    );

    expect(stats.requests1h).toBe(1);
    expect(stats.denials1h).toBe(1);
    expect(stats.requests24h).toBe(2);
    expect(stats.denials24h).toBe(1);
  });

  it("persists standing_approvals across SQLite reopen and executes GET rest.call via standingFastPath without Brain.assess", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mv-standing-"));
    const dbPath = join(dir, "vault.db");
    const masterKey = Buffer.alloc(32, 5);
    let brainAssessCalls = 0;

    const CountingBrain = Layer.succeed(Brain, {
      assess: () => {
        brainAssessCalls += 1;
        return Effect.succeed({
          risk: "low" as const,
          recommendedScope: "models.read",
          requireApproval: true,
          explanation: "initial approval required",
        });
      },
    });
    const FastConnector = Layer.succeed(Connector, {
      execute: (alias, scope, secret) =>
        Effect.succeed({ alias, scope, ok: true, secretLen: secret.length }),
    });

    const ADMIN_AUTH = { daemonToken: "admin-tok-test", providedToken: "admin-tok-test" };
    try {
      let agentToken = "";
      // Session 1: seed credential, enable warden, register verified agent, request & approve-always
      await Effect.runPromise(
        Effect.scoped(
          Effect.gen(function* () {
            const svc = yield* VaultService;
            yield* svc.updateWardenSettings({ provider: "local", model: "qwen2.5:3b" });
            yield* svc.seedCredential("openai", "models.read", CANARY, "https://api.openai.com/v1");
            const minted = yield* svc.registerAgent("cursor", "Cursor");
            agentToken = minted.token;

            const reqRes = yield* Effect.promise(() =>
              handleVaultRequest(
                svc,
                "POST",
                "/request",
                {
                  agentId: "cursor",
                  ide: "Cursor",
                  tool: "rest.call",
                  alias: "openai",
                  requestedScope: "models.read",
                  reason: "List models",
                  payload: { method: "GET", path: "/models" },
                },
                { providedAgentToken: agentToken, grantWaitMs: 0 },
              ),
            );
            expect(reqRes.status).toBe(200);
            expect((reqRes.body as { status: string }).status).toBe("awaiting-approval");
            const grantId = (reqRes.body as { grantId: string }).grantId;
            expect(brainAssessCalls).toBe(1);

            const alwaysRes = yield* Effect.promise(() =>
              handleVaultRequest(svc, "POST", "/approve-always", { grantId }, ADMIN_AUTH),
            );
            expect(alwaysRes.status).toBe(200);
          }).pipe(
            Effect.provide(makeVaultServiceLive({ masterKey })),
            Effect.provide(Layer.mergeAll(VaultStoreScoped(dbPath), CountingBrain, FastConnector)),
          ),
        ),
      );

      // Session 2: fresh VaultService over reopened SQLite DB — standingFastPath executes immediately with 0 Brain calls!
      brainAssessCalls = 0;
      await Effect.runPromise(
        Effect.scoped(
          Effect.gen(function* () {
            const svc = yield* VaultService;
            const aliasesOut = yield* Effect.promise(() => handleVaultRequest(svc, "GET", "/aliases"));
            expect(aliasesOut.status).toBe(200);
            const creds = (aliasesOut.body as { credentials: Record<string, unknown>[] }).credentials;
            expect(creds[0]).toMatchObject({
              alias: "openai",
              scopeCeiling: "models.read",
              baseUrl: "https://api.openai.com/v1",
              authStyle: "bearer",
              supportedTools: ["rest.call", "graphql.call"],
            });
            expect(JSON.stringify(aliasesOut.body)).not.toContain(CANARY);

            const fastRes = yield* Effect.promise(() =>
              handleVaultRequest(
                svc,
                "POST",
                "/request",
                {
                  agentId: "cursor",
                  ide: "Cursor",
                  tool: "rest.call",
                  alias: "openai",
                  requestedScope: "models.read",
                  reason: "List models again",
                  payload: { method: "GET", path: "/models" },
                },
                { providedAgentToken: agentToken, grantWaitMs: 0 },
              ),
            );
            expect(fastRes.status).toBe(200);
            expect((fastRes.body as { status: string }).status).toBe("executed");
            expect(brainAssessCalls).toBe(0);
            expect(JSON.stringify(fastRes.body)).not.toContain(CANARY);
          }).pipe(
            Effect.provide(makeVaultServiceLive({ masterKey })),
            Effect.provide(Layer.mergeAll(VaultStoreScoped(dbPath), CountingBrain, FastConnector)),
          ),
        ),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("emits live events (pending.changed, vault.lock_changed) and resolves enrollment & registration long-polls immediately", async () => {
    const key = Buffer.alloc(32, 11);
    const passphrase = "alpha-bravo-charlie-delta";
    const wrapped = await wrapMasterKey(key, passphrase);
    const session = createKeySession({ mode: "passphrase", wrapped });
    await session.unlock(passphrase);

    const seenEvents: VaultLiveEvent[] = [];
    const unsubscribe = subscribeVaultEvents((ev) => {
      seenEvents.push(ev);
    });

    const StubBrain = Layer.succeed(Brain, {
      assess: () =>
        Effect.succeed({
          risk: "low" as const,
          recommendedScope: "dns.read",
          requireApproval: true,
          explanation: "needs approval",
        }),
    });
    const StubConnector = Layer.succeed(Connector, {
      execute: () => Effect.succeed({ ok: true }),
    });

    try {
      const svc = await Effect.runPromise(
        Effect.gen(function* () {
          const s = yield* VaultService;
          yield* s.seedCredential("cloudflare", "dns.read", CANARY);
          return s;
        }).pipe(
          Effect.provide(makeVaultServiceLive({ keySession: session })),
          Effect.provide(Layer.mergeAll(VaultStoreTest(key), StubBrain, StubConnector)),
        ),
      );

      // 1. Trigger pending.changed
      await handleVaultRequest(
        svc,
        "POST",
        "/request",
        {
          agentId: "claude-code",
          ide: "Claude Code",
          tool: "cloudflare.dns",
          alias: "cloudflare",
          requestedScope: "dns.read",
          reason: "check zones",
        },
        { grantWaitMs: 0 },
      );
      expect(seenEvents.some((e) => e.type === "pending.changed" && e.pendingCount === 1)).toBe(true);

      const ADMIN_AUTH = { daemonToken: "admin-tok-live", providedToken: "admin-tok-live" };
      // 2. Enrollment long-poll wakes immediately when credential is seeded
      const enrCreated = await handleVaultRequest(svc, "POST", "/enrollments", {
        alias: "custom-api",
        scope: "items.read",
        website: "https://api.example.com/v1",
      });
      const enrollmentId = (enrCreated.body as { enrollmentId: string }).enrollmentId;
      const startedEnr = Date.now();
      const waitEnrPromise = handleVaultRequest(
        svc,
        "GET",
        `/enrollments/${enrollmentId}`,
        undefined,
        { grantWaitMs: 5_000 },
      );
      setTimeout(() => {
        void handleVaultRequest(
          svc,
          "POST",
          "/credentials",
          {
            alias: "custom-api",
            scope: "items.read",
            secret: "sk-enrolled-secret-9999",
            website: "https://api.example.com/v1",
            enrollmentId,
          },
          ADMIN_AUTH,
        );
      }, 40);
      const waitedEnr = await waitEnrPromise;
      expect((waitedEnr.body as { status: string }).status).toBe("completed");
      expect(Date.now() - startedEnr).toBeLessThan(2_000);

      // 3. Registration claim long-poll wakes immediately when approved
      const claimSecret = randomBytes(24).toString("hex");
      const claimHash = createHash("sha256").update(claimSecret).digest("hex");
      const regCreated = await handleVaultRequest(svc, "POST", "/agent-registrations", {
        agentId: "antigravity",
        name: "Antigravity",
        ide: "Antigravity",
        claimHash,
      });
      const regBody = regCreated.body as { registrationId: string; code: string };
      const startedReg = Date.now();
      const claimPromise = handleVaultRequest(
        svc,
        "POST",
        `/agent-registrations/${regBody.registrationId}/claim`,
        { claim: claimSecret, waitMs: 5_000 },
      );
      setTimeout(() => {
        void handleVaultRequest(
          svc,
          "POST",
          `/agent-registrations/${regBody.registrationId}/approve`,
          { code: regBody.code },
          ADMIN_AUTH,
        );
      }, 40);
      const claimed = await claimPromise;
      expect(claimed.status).toBe(200);
      expect((claimed.body as { status: string }).status).toBe("claimed");
      expect(Date.now() - startedReg).toBeLessThan(2_000);

      // 4. Trigger vault.lock_changed
      await handleVaultRequest(svc, "POST", "/lock", {}, ADMIN_AUTH);
      expect(seenEvents.some((e) => e.type === "vault.lock_changed" && e.daemonLocked)).toBe(true);
      expect(JSON.stringify(seenEvents)).not.toContain(CANARY);
    } finally {
      unsubscribe();
    }
  });

  it("serializes vaultEventData safely, caches & zeroes warden key, and caches inspectProcess lookups", async () => {
    expect(
      vaultEventData({
        type: "pending.changed",
        pendingCount: 2,
        addedGrantId: "g-1",
        risk: "high",
        origin: "remote",
      }),
    ).toEqual({ pendingCount: 2, addedGrantId: "g-1", risk: "high", origin: "remote" });
    expect(
      vaultEventData({
        type: "registration.changed",
        pendingRegistrationsCount: 1,
        addedRegistrationId: "reg-1",
      }),
    ).toEqual({ pendingRegistrationsCount: 1, addedRegistrationId: "reg-1" });
    expect(
      vaultEventData({
        type: "enrollment.changed",
        enrollmentId: "enr-1",
        status: "completed",
      }),
    ).toEqual({ enrollmentId: "enr-1", status: "completed" });
    expect(vaultEventData({ type: "vault.lock_changed", daemonLocked: true })).toEqual({ daemonLocked: true });
    expect(vaultEventData({ type: "audit.appended", stage: "executed", requestId: "req-1" })).toEqual({
      stage: "executed",
      requestId: "req-1",
    });

    invalidateWardenCache();
    expect(readCachedWardenSettings()).toBeNull();
    expect(readCachedWardenKey()).toBeNull();
    writeCachedWardenSettings(DEFAULT_WARDEN_SETTINGS);
    writeCachedWardenKey("meta-key-1");
    writeCachedWardenKey("meta-key-2");
    expect(readCachedWardenSettings()).toEqual(DEFAULT_WARDEN_SETTINGS);
    expect(readCachedWardenKey()).toBe("meta-key-2");
    invalidateWardenCache();
    expect(readCachedWardenSettings()).toBeNull();
    expect(readCachedWardenKey()).toBeNull();

    const first = await inspectProcess(process.pid);
    const second = await inspectProcess(process.pid);
    expect(second).toEqual(first);
  });
});
