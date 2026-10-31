// packages/daemon/test/audit-trail.test.ts — Task 4 structured audit trails
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { Effect, Layer } from "effect";
import { describe, expect } from "vitest";
import { it } from "@effect/vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStore, VaultStoreLive, VaultStoreTest } from "../../core/src/storage.js";
import { makeVaultServiceLive, VaultService } from "../src/service.js";

const CANARY = "canary-secret-audit-trail-9f27";
const EXPLANATION = "low-risk read of charges";

const BrainApproval = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({
      risk: "low" as const,
      recommendedScope: "charges.read",
      requireApproval: true,
      explanation: EXPLANATION,
    }),
});
const BrainAuto = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({
      risk: "low" as const,
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: EXPLANATION,
    }),
});
const FakeConnector = Layer.succeed(Connector, {
  execute: (_a, _s, secret) => Effect.succeed({ echoedLength: secret.length }),
});
const req = {
  agentId: "cursor",
  ide: "Cursor",
  tool: "http",
  alias: "stripe",
  requestedScope: "charges.read",
  reason: "list",
};
const grantIdOf = (r: { grantId?: string }): string => {
  if (r.grantId === undefined) throw new Error("expected a grantId");
  return r.grantId;
};
const seeded = (brain: Layer.Layer<Brain>) =>
  Effect.gen(function* () {
    const svc = yield* VaultService;
    yield* svc.seedCredential("stripe", "charges.read", CANARY);
    return svc;
  }).pipe(
    Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 7) })),
    Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), brain, FakeConnector)),
  );

describe("structured audit trails (Task 4)", () => {
  it.effect("one requestId threads requested→marshal→policy→approved→executed via human approve", () =>
    Effect.gen(function* () {
      const svc = yield* seeded(BrainApproval);
      yield* svc.updateWardenSettings({ model: "audit-model-1" });
      const pending = yield* svc.requestCapability(req);
      expect(pending.status).toBe("awaiting-approval");
      yield* svc.approve(grantIdOf(pending));
      const audit = yield* svc.listAudit();
      const chain = audit.filter((e) => e.requestId !== undefined);
      expect(chain.map((e) => e.stage)).toEqual([
        "requested",
        "marshal",
        "policy",
        "approved",
        "executed",
      ]);
      expect(new Set(chain.map((e) => e.requestId)).size).toBe(1);
      const marshal = chain.find((e) => e.stage === "marshal");
      expect(marshal?.risk).toBe("low");
      expect(marshal?.recommendedScope).toBe("charges.read");
      expect(marshal?.modelId).toBe("audit-model-1");
      expect(marshal?.decisionSource).toBe("marshal");
      expect(typeof marshal?.latencyMs).toBe("number");
      expect(marshal?.latencyMs).toBeGreaterThanOrEqual(0);
      expect(marshal?.explanation).toBe(EXPLANATION);
      expect(marshal?.detail).toBe("marshal decision");
      expect(chain.find((e) => e.stage === "policy")?.decisionSource).toBe("marshal+policy");
      expect(chain.find((e) => e.stage === "approved")?.decisionSource).toBe("human");
      expect(JSON.stringify(chain)).not.toContain(CANARY);
      expect(JSON.stringify(audit)).not.toContain(CANARY);
    }));

  it.effect("auto-approved execution shares one requestId with marshal+policy source", () =>
    Effect.gen(function* () {
      const svc = yield* seeded(BrainAuto);
      const result = yield* svc.requestCapability(req);
      expect(result.status).toBe("executed");
      const chain = (yield* svc.listAudit()).filter((e) => e.requestId !== undefined);
      expect(chain.map((e) => e.stage)).toEqual([
        "requested",
        "marshal",
        "policy",
        "approved",
        "executed",
      ]);
      expect(new Set(chain.map((e) => e.requestId)).size).toBe(1);
      expect(chain.find((e) => e.stage === "approved")?.decisionSource).toBe("marshal+policy");
      expect(chain.find((e) => e.stage === "executed")?.decisionSource).toBe("marshal+policy");
      expect(JSON.stringify(chain)).not.toContain(CANARY);
      // A second request gets a different requestId.
      const second = yield* svc.requestCapability(req);
      expect(second.status).toBe("executed");
      const chains = (yield* svc.listAudit()).filter((e) => e.requestId !== undefined);
      expect(new Set(chains.map((e) => e.requestId)).size).toBe(2);
    }));

  it.effect("provider none: policy-denied chain has decisionSource policy and no marshal event", () =>
    Effect.gen(function* () {
      const svc = yield* seeded(BrainApproval);
      yield* svc.updateWardenSettings({ provider: "none" });
      const denied = yield* svc.requestCapability({ ...req, requestedScope: "charges.write" });
      expect(denied.status).toBe("denied");
      const chain = (yield* svc.listAudit()).filter((e) => e.requestId !== undefined);
      expect(chain.map((e) => e.stage)).toEqual(["requested", "policy", "denied"]);
      expect(chain.some((e) => e.stage === "marshal")).toBe(false);
      expect(chain.find((e) => e.stage === "policy")?.decisionSource).toBe("policy");
      expect(chain.find((e) => e.stage === "denied")?.decisionSource).toBe("policy");
      expect(new Set(chain.map((e) => e.requestId)).size).toBe(1);
      expect(JSON.stringify(chain)).not.toContain(CANARY);
    }));

  it.effect("human deny of a parked grant reuses the same requestId with decisionSource human", () =>
    Effect.gen(function* () {
      const svc = yield* seeded(BrainApproval);
      yield* svc.updateWardenSettings({ provider: "none" });
      const pending = yield* svc.requestCapability(req);
      expect(pending.status).toBe("awaiting-approval");
      yield* svc.deny(grantIdOf(pending));
      const chain = (yield* svc.listAudit()).filter((e) => e.requestId !== undefined);
      expect(chain.map((e) => e.stage)).toEqual(["requested", "policy", "denied"]);
      expect(new Set(chain.map((e) => e.requestId)).size).toBe(1);
      const denied = chain.find((e) => e.stage === "denied");
      expect(denied?.decisionSource).toBe("human");
      expect(denied?.detail).toBe("denied by human");
      expect(JSON.stringify(chain)).not.toContain(CANARY);
    }));

  it("migrates a legacy audit table in place and round-trips new fields", () => {
    const dir = mkdtempSync(join(tmpdir(), "openvault-audit-migrate-"));
    const dbPath = join(dir, "vault.db");
    const raw = new Database(dbPath);
    raw.exec(
      "CREATE TABLE credentials (alias TEXT PRIMARY KEY, ceiling TEXT NOT NULL, ciphertext TEXT NOT NULL); CREATE TABLE audit (ts TEXT NOT NULL, agent TEXT NOT NULL, alias TEXT NOT NULL, scope TEXT NOT NULL, stage TEXT NOT NULL, detail TEXT NOT NULL, model_id TEXT);",
    );
    raw
      .prepare(
        "INSERT INTO audit (ts, agent, alias, scope, stage, detail, model_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run("2026-01-01T00:00:00.000Z", "legacy-agent", "stripe", "charges.read", "executed", "old row", null);
    raw.close();
    return Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* VaultStore;
        yield* store.appendAudit({
          ts: "2026-01-01T00:01:00.000Z",
          agentId: "cursor",
          alias: "stripe",
          scope: "charges.read",
          stage: "marshal",
          detail: "marshal decision",
          modelId: "audit-model-1",
          requestId: "req-1",
          risk: "low",
          recommendedScope: "charges.read",
          decisionSource: "marshal",
          latencyMs: 12,
          explanation: EXPLANATION,
        });
        const listed = yield* store.listAudit();
        expect(listed).toHaveLength(2);
        expect(listed[0]?.requestId).toBeUndefined();
        expect(listed[1]).toEqual({
          ts: "2026-01-01T00:01:00.000Z",
          agentId: "cursor",
          alias: "stripe",
          scope: "charges.read",
          stage: "marshal",
          detail: "marshal decision",
          modelId: "audit-model-1",
          requestId: "req-1",
          risk: "low",
          recommendedScope: "charges.read",
          decisionSource: "marshal",
          latencyMs: 12,
          explanation: EXPLANATION,
        });
        expect(JSON.stringify(listed)).not.toContain(CANARY);
      })
        .pipe(Effect.provide(VaultStoreLive(dbPath, Buffer.alloc(32, 7))))
        .pipe(
          Effect.ensuring(
            Effect.sync(() => {
              try {
                rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
              } catch {
                // Windows may hold the SQLite file until exit; temp reaper cleans up.
              }
            }),
          ),
        ),
    );
  });
});
