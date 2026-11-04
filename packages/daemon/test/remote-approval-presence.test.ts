import { Effect, Layer, TestClock, TestContext } from "effect";
import { describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStore, VaultStoreTest } from "../../core/src/storage.js";
import { handleVaultRequest } from "../src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../src/service.js";

// Daemon-side presence enforcement for remote approvals (WP5/WP6): the
// trusted boundary is the daemon itself, so a direct token-authenticated
// /approve of a remote-origin grant must also require a fresh, single-use
// presence proof minted by a real PIN verification (or attested Hello).

const CANARY = "sk-presence-canary-1234567890";
const TOKEN = "presence-test-token";
const withToken = { daemonToken: TOKEN, providedToken: TOKEN };
const GATEWAY = { gatewaySecret: "gw-secret", gatewayStampValid: true, deviceId: "dev-test", transport: "mtls" } as const;

const FakeConnector = Layer.succeed(Connector, {
  execute: (_a, _s, secret) => Effect.succeed({ echoedLength: secret.length }),
});

const brainNeedsApproval = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({ risk: "low" as const, recommendedScope: "charges.read", requireApproval: true, explanation: "risk is low" }),
});

const req = {
  agentId: "cursor",
  ide: "Cursor",
  tool: "http",
  alias: "stripe",
  requestedScope: "charges.read",
  reason: "list charges",
};

interface Harness {
  readonly svc: VaultServiceService;
  readonly store: import("../../core/src/storage.js").VaultStoreService;
}

async function makeHarness(): Promise<Harness> {
  return Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* VaultService;
      const store = yield* VaultStore;
      yield* svc.seedCredential("stripe", "charges.read", CANARY);
      yield* store.addDevice({
        id: "dev-test",
        name: "test phone",
        platform: "ios",
        certFingerprint: "fp-test",
        transport: "mtls",
        createdAt: new Date().toISOString(),
        lastSeenAt: null,
        revoked: false,
      });
      return { svc, store };
    }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 7) })),
      Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), brainNeedsApproval, FakeConnector)),
    ),
  );
}

async function createRemoteGrant(svc: VaultServiceService): Promise<string> {
  const created = await handleVaultRequest(svc, "POST", "/request", req, GATEWAY);
  expect(created.status).toBe(200);
  const body = created.body as Record<string, unknown>;
  expect(body["status"]).toBe("awaiting-approval");
  expect(body["origin"]).toBeUndefined(); // grantId response; origin shows on /pending
  return body["grantId"] as string;
}

describe("daemon-side remote approval presence enforcement", () => {
  it("rejects a direct token-authenticated /approve of a remote grant without a proof", async () => {
    const { svc } = await makeHarness();
    const grantId = await createRemoteGrant(svc);
    const denied = await handleVaultRequest(svc, "POST", "/approve", { grantId }, withToken);
    expect(denied.status).toBe(403);
    expect((denied.body as { error: { _tag: string } }).error._tag).toBe("PresenceRequired");
    const deniedAlways = await handleVaultRequest(svc, "POST", "/approve-always", { grantId }, withToken);
    expect(deniedAlways.status).toBe(403);
    // The grant is still pending: nothing was consumed.
    const pending = await handleVaultRequest(svc, "GET", "/pending", undefined, withToken);
    expect((pending.body as { approvals: unknown[] }).approvals).toHaveLength(1);
  });

  it("executes with a proof from a real PIN verify, and rejects its replay", async () => {
    const { svc } = await makeHarness();
    await Effect.runPromise(svc.setLocalPin("4321"));
    const verified = await Effect.runPromise(svc.verifyLocalPin("4321"));
    expect(verified.ok).toBe(true);
    const proof = verified.presenceProof;
    expect(typeof proof).toBe("string");

    const grantId = await createRemoteGrant(svc);
    const approved = await handleVaultRequest(svc, "POST", "/approve", { grantId, presenceProof: proof }, withToken);
    expect(approved.status).toBe(200);
    expect((approved.body as Record<string, unknown>)["status"]).toBe("executed");
    expect(JSON.stringify(approved.body)).not.toContain(CANARY);

    // Replay: a fresh remote grant with the same proof is rejected.
    const grantId2 = await createRemoteGrant(svc);
    const replay = await handleVaultRequest(svc, "POST", "/approve", { grantId: grantId2, presenceProof: proof }, withToken);
    expect(replay.status).toBe(403);
    expect((replay.body as { error: { _tag: string } }).error._tag).toBe("PresenceRequired");
  });

  it("mints no proof from a vacuous PIN verify when no PIN is configured (fail closed)", async () => {
    const { svc } = await makeHarness();
    const verified = await Effect.runPromise(svc.verifyLocalPin("whatever"));
    expect(verified.ok).toBe(true);
    expect(verified.presenceProof).toBeUndefined();
    const grantId = await createRemoteGrant(svc);
    const denied = await handleVaultRequest(svc, "POST", "/approve", { grantId }, withToken);
    expect(denied.status).toBe(403);
  });

  it("honors the opt-out only while requireAuthForRemoteApproval is explicitly off", async () => {
    const { svc, store } = await makeHarness();
    await Effect.runPromise(
      store.setRemoteSettingsRow({ enabled: true, host: "127.0.0.1", port: 7078, requireAuthForRemoteApproval: false }),
    );
    const grantId = await createRemoteGrant(svc);
    const approved = await handleVaultRequest(svc, "POST", "/approve", { grantId }, withToken);
    expect(approved.status).toBe(200);

    // Back on: the next remote approval is gated again.
    await Effect.runPromise(
      store.setRemoteSettingsRow({ enabled: true, host: "127.0.0.1", port: 7078, requireAuthForRemoteApproval: true }),
    );
    const grantId2 = await createRemoteGrant(svc);
    const denied = await handleVaultRequest(svc, "POST", "/approve", { grantId: grantId2 }, withToken);
    expect(denied.status).toBe(403);
  });

  it("rejects an expired proof", async () => {
    const { svc } = await makeHarness();
    const err = await Effect.runPromise(
      Effect.gen(function* () {
        yield* svc.setLocalPin("4321");
        const verified = yield* svc.verifyLocalPin("4321");
        const proof = verified.presenceProof;
        if (proof === undefined) throw new Error("expected a minted proof");
        const created = yield* svc.requestCapability(req, undefined, { deviceId: "dev-test", transport: "mtls" });
        const grantId = created.status === "awaiting-approval" ? created.grantId : undefined;
        if (grantId === undefined) throw new Error("expected awaiting-approval");
        yield* TestClock.adjust("61 seconds");
        return yield* Effect.flip(svc.approve(grantId, proof));
      }).pipe(Effect.provide(TestContext.TestContext)),
    );
    expect(err._tag).toBe("PresenceRequired");
  });

  it("a direct daemon-token settings PATCH cannot disable the presence requirement without a proof", async () => {
    const { svc } = await makeHarness();
    await Effect.runPromise(svc.setLocalPin("4321"));
    // Direct, token-authenticated, no proof: rejected.
    const denied = await handleVaultRequest(
      svc,
      "PATCH",
      "/settings/remote",
      { requireAuthForRemoteApproval: false },
      withToken,
    );
    expect(denied.status).toBe(403);
    expect((denied.body as { error: { _tag: string } }).error._tag).toBe("PresenceRequired");
    // The setting is still on.
    const row = await handleVaultRequest(svc, "GET", "/settings/remote", undefined, withToken);
    expect((row.body as Record<string, unknown>)["requireAuthForRemoteApproval"]).toBe(true);
    // With a real PIN-verify proof the same direct call succeeds.
    const verified = await Effect.runPromise(svc.verifyLocalPin("4321"));
    const allowed = await handleVaultRequest(
      svc,
      "PATCH",
      "/settings/remote",
      { requireAuthForRemoteApproval: false, presenceProof: verified.presenceProof },
      withToken,
    );
    expect(allowed.status).toBe(200);
    const row2 = await handleVaultRequest(svc, "GET", "/settings/remote", undefined, withToken);
    expect((row2.body as Record<string, unknown>)["requireAuthForRemoteApproval"]).toBe(false);
  });

  it("a daemon-token holder cannot replace an existing PIN without the current PIN", async () => {
    const { svc } = await makeHarness();
    await Effect.runPromise(svc.setLocalPin("4321"));
    // Attempted silent replacement via the direct route: rejected.
    const replaced = await handleVaultRequest(svc, "POST", "/settings/local-auth/pin", { pin: "9999" }, withToken);
    expect(replaced.status).not.toBe(200);
    // The original PIN still verifies (and mints); the attempted one does not.
    const oldPin = await Effect.runPromise(svc.verifyLocalPin("4321"));
    expect(oldPin.ok).toBe(true);
    expect(typeof oldPin.presenceProof).toBe("string");
    const newPin = await Effect.runPromise(svc.verifyLocalPin("9999"));
    expect(newPin.ok).toBe(false);
    expect(newPin.presenceProof).toBeUndefined();
  });

  it("a daemon-token holder cannot mint a proof through the biometric route", async () => {
    const { svc, store } = await makeHarness();
    await Effect.runPromise(svc.setLocalPin("4321"));
    const current = await Effect.runPromise(store.getLocalAuthRecord());
    await Effect.runPromise(store.setLocalAuthRecord({ ...current, enabled: true, biometricEnabled: true }));
    const bio = await handleVaultRequest(svc, "POST", "/settings/local-auth/verify-biometric", undefined, withToken);
    expect(bio.status).toBe(200);
    expect((bio.body as Record<string, unknown>)["presenceProof"]).toBeUndefined();
    // ...and a remote approval still fails closed without a real PIN proof.
    const grantId = await createRemoteGrant(svc);
    const denied = await handleVaultRequest(svc, "POST", "/approve", { grantId }, withToken);
    expect(denied.status).toBe(403);
  });

  it("disabling local-auth keeps the PIN hash, so proofs still need the real PIN", async () => {
    const { svc } = await makeHarness();
    await Effect.runPromise(svc.setLocalPin("4321"));
    await handleVaultRequest(svc, "PATCH", "/settings/local-auth", { enabled: false }, withToken);
    const wrong = await Effect.runPromise(svc.verifyLocalPin("0000"));
    expect(wrong.ok).toBe(false);
    expect(wrong.presenceProof).toBeUndefined();
    const right = await Effect.runPromise(svc.verifyLocalPin("4321"));
    expect(right.ok).toBe(true);
    expect(typeof right.presenceProof).toBe("string");
  });

  it("pairing confirm/cancel with an unknown pairingId is 4xx, never 500", async () => {
    const { svc } = await makeHarness();
    const confirm = await handleVaultRequest(svc, "POST", "/devices/pairing/confirm", { pairingId: "no-such-pairing" }, withToken);
    expect(confirm.status).toBe(409);
    expect((confirm.body as { error: { _tag: string } }).error._tag).toBe("PairingNotConfirmable");
  });

  it("does not gate local grants", async () => {
    const { svc } = await makeHarness();
    const created = await handleVaultRequest(svc, "POST", "/request", req);
    const grantId = (created.body as Record<string, unknown>)["grantId"] as string;
    const approved = await handleVaultRequest(svc, "POST", "/approve", { grantId }, withToken);
    expect(approved.status).toBe(200);
    expect((approved.body as Record<string, unknown>)["status"]).toBe("executed");
  });
});
