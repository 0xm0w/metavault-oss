import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { handleVaultRequest } from "../src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../src/service.js";

const TOKEN = "test-daemon-token-auth";
const auth = { daemonToken: TOKEN };
const withToken = { daemonToken: TOKEN, providedToken: TOKEN };

const BrainStub = Layer.succeed(Brain, {
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
      Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 5) })),
      Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 5)), BrainStub, FakeConnector)),
    ),
  );
}

describe("Local Authentication & Biometric API (#19)", () => {
  it("GET /settings/local-auth returns status without leaking salt or hash", async () => {
    const service = await makeService();
    const res = await handleVaultRequest(service, "GET", "/settings/local-auth", undefined, auth);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      enabled: false,
      configured: false,
      biometricEnabled: false,
      requireOnApproval: false,
      requireOnLaunch: false,
      requireOnSettings: false,
      autoLockMinutes: 0,
    });
    // Never leaks cryptographic state
    expect((res.body as Record<string, unknown>)["pinHash"]).toBeUndefined();
    expect((res.body as Record<string, unknown>)["salt"]).toBeUndefined();
  });

  it("POST /settings/local-auth/pin sets PIN and enables verification", async () => {
    const service = await makeService();
    // Setting PIN requires token
    const noToken = await handleVaultRequest(
      service,
      "POST",
      "/settings/local-auth/pin",
      { pin: "1234" },
      auth,
    );
    expect(noToken.status).toBe(401);

    // Set PIN with token
    const res = await handleVaultRequest(
      service,
      "POST",
      "/settings/local-auth/pin",
      { pin: "1234" },
      withToken,
    );
    expect(res.status).toBe(200);

    // Verify PIN works
    const checkValid = await handleVaultRequest(
      service,
      "POST",
      "/settings/local-auth/verify",
      { pin: "1234" },
      auth,
    );
    expect(checkValid.status).toBe(200);
    expect(checkValid.body).toEqual({ ok: true });

    const checkInvalid = await handleVaultRequest(
      service,
      "POST",
      "/settings/local-auth/verify",
      { pin: "0000" },
      auth,
    );
    expect(checkInvalid.status).toBe(200);
    expect(checkInvalid.body).toEqual({ ok: false });
  });

  it("PATCH /settings/local-auth updates configuration", async () => {
    const service = await makeService();
    const res = await handleVaultRequest(
      service,
      "PATCH",
      "/settings/local-auth",
      { enabled: true, autoLockMinutes: 15, requireOnLaunch: true, biometricEnabled: true, requireOnSettings: true },
      withToken,
    );
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      enabled: true,
      configured: false,
      biometricEnabled: true,
      requireOnApproval: false,
      requireOnLaunch: true,
      requireOnSettings: true,
      autoLockMinutes: 15,
    });
  });
});
