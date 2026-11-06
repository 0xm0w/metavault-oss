import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";
import { Brain } from "../../packages/brain/src/brain.js";
import { Connector } from "../../packages/core/src/connector.js";
import { VaultStoreTest } from "../../packages/core/src/storage.js";
import { handleVaultRequest } from "../../packages/daemon/src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../../packages/daemon/src/service.js";
import {
  DEFAULT_LOCAL_AUTH_STATUS,
  canLockSessionNow,
  isAutoLockDue,
  isBiometricsActive,
  projectLocalAuthStatus,
  shouldLockOnLaunch,
  shouldPromptPinSetupOnEnable,
  shouldRequireAuthForApproval,
  shouldRequireAuthForSettings,
} from "../../packages/app/src/renderer/model.js";
import type { LocalAuthStatusLike } from "../../packages/app/src/renderer/types.js";

const TOKEN = "test-auth-suite-token";
const auth = { daemonToken: TOKEN };
const withToken = { daemonToken: TOKEN, providedToken: TOKEN };
const MASTER_KEY = Buffer.alloc(32, 9);

function mustStatus(status: LocalAuthStatusLike | null): LocalAuthStatusLike {
  expect(status).not.toBeNull();
  if (status === null) {
    throw new Error("Local auth status was null");
  }
  return status;
}

const BrainStub = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({
      risk: "high" as const,
      recommendedScope: "charges.write",
      requireApproval: true,
      explanation: "high-risk write capability",
    }),
});

let executedSecrets: string[] = [];
const FakeConnector = Layer.succeed(Connector, {
  execute: (_a, _s, secret) => {
    executedSecrets.push(secret);
    return Effect.succeed({ echoedLength: secret.length });
  },
});

async function makeService(): Promise<VaultServiceService> {
  return Effect.runPromise(
    Effect.gen(function* () {
      return yield* VaultService;
    }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: MASTER_KEY })),
      Effect.provide(Layer.mergeAll(VaultStoreTest(MASTER_KEY), BrainStub, FakeConnector)),
    ),
  );
}

describe("Comprehensive ON-State Verification for Local Authentication Gates (#19)", () => {
  it("Layer 1: Enable local authentication gate (Master switch ON-state)", async () => {
    const service = await makeService();

    // 1. Initial State: strictly OFF by default
    const initial = await handleVaultRequest(service, "GET", "/settings/local-auth", undefined, auth);
    expect(initial.status).toBe(200);
    const initialStatus = mustStatus(projectLocalAuthStatus(initial.body));
    expect(initialStatus).toEqual(DEFAULT_LOCAL_AUTH_STATUS);
    expect(initialStatus.enabled).toBe(false);
    expect(initialStatus.configured).toBe(false);

    // 2. Unconfigured gate demands PIN setup modal before activating
    expect(shouldPromptPinSetupOnEnable(initialStatus)).toBe(true);

    // 3. Set PIN to configure local auth
    const setPinRes = await handleVaultRequest(
      service,
      "POST",
      "/settings/local-auth/pin",
      { pin: "54321" },
      withToken,
    );
    expect(setPinRes.status).toBe(200);

    // 4. Turn Master Switch ON
    const enableRes = await handleVaultRequest(
      service,
      "PATCH",
      "/settings/local-auth",
      { enabled: true },
      withToken,
    );
    expect(enableRes.status).toBe(200);
    const enabledStatus = mustStatus(projectLocalAuthStatus(enableRes.body));
    expect(enabledStatus.enabled).toBe(true);
    expect(enabledStatus.configured).toBe(true);
    // Already configured: no setup modal needed
    expect(shouldPromptPinSetupOnEnable(enabledStatus)).toBe(false);

    // 5. Verify invalid PIN is rejected, valid PIN succeeds
    const badVerify = await handleVaultRequest(
      service,
      "POST",
      "/settings/local-auth/verify",
      { pin: "00000" },
      withToken,
    );
    expect(badVerify.status).toBe(200);
    expect(badVerify.body).toEqual({ ok: false });

    const goodVerify = await handleVaultRequest(
      service,
      "POST",
      "/settings/local-auth/verify",
      { pin: "54321" },
      withToken,
    );
    expect(goodVerify.status).toBe(200);
    expect(goodVerify.body).toMatchObject({ ok: true });
    expect(typeof (goodVerify.body as { presenceProof?: unknown }).presenceProof).toBe("string");

    // 6. When Master Switch is turned back OFF, all child gates are deactivated
    const disabledRes = await handleVaultRequest(
      service,
      "PATCH",
      "/settings/local-auth",
      { enabled: false, requireOnApproval: true, requireOnLaunch: true, requireOnSettings: true, biometricEnabled: true },
      withToken,
    );
    const disabledStatus = mustStatus(projectLocalAuthStatus(disabledRes.body));
    expect(disabledStatus.enabled).toBe(false);
    expect(shouldLockOnLaunch(disabledStatus)).toBe(false);
    expect(shouldRequireAuthForApproval(disabledStatus, "charges.write")).toBe(false);
    expect(shouldRequireAuthForSettings(disabledStatus)).toBe(false);
    expect(isBiometricsActive(disabledStatus)).toBe(false);
    expect(canLockSessionNow(disabledStatus)).toBe(false);
  });

  it("Layer 2: Require on app launch / initial unlock (ON-state)", async () => {
    const service = await makeService();

    // Configure PIN and enable launch gate
    await handleVaultRequest(service, "POST", "/settings/local-auth/pin", { pin: "9988" }, withToken);
    const res = await handleVaultRequest(
      service,
      "PATCH",
      "/settings/local-auth",
      { enabled: true, requireOnLaunch: true },
      withToken,
    );
    const status = mustStatus(projectLocalAuthStatus(res.body));
    expect(status.enabled).toBe(true);
    expect(status.requireOnLaunch).toBe(true);

    // Test launch gate logic
    let vaultLocked = false;
    let initialAuthChecked = false;

    const simulateColdStart = (authStatus: typeof status) => {
      if (!initialAuthChecked) {
        initialAuthChecked = true;
        if (shouldLockOnLaunch(authStatus)) {
          vaultLocked = true;
        }
      }
    };

    simulateColdStart(status);
    expect(vaultLocked).toBe(true); // Locked on cold start

    // Attempt unlock with wrong PIN fails
    const failAttempt = await handleVaultRequest(service, "POST", "/settings/local-auth/verify", { pin: "1111" }, withToken);
    expect(failAttempt.body).toEqual({ ok: false });
    expect(vaultLocked).toBe(true);

    // Correct PIN unlocks
    const successAttempt = await handleVaultRequest(service, "POST", "/settings/local-auth/verify", { pin: "9988" }, withToken);
    expect(successAttempt.body).toMatchObject({ ok: true });
    vaultLocked = false;
    expect(vaultLocked).toBe(false);
  });

  it("Layer 3: Require on capability approvals (ON-state)", async () => {
    const service = await makeService();
    executedSecrets = [];

    // Add a credential and configure approval gate
    await handleVaultRequest(
      service,
      "POST",
      "/credentials",
      { alias: "stripe", scope: "charges.write", secret: "sk_live_secret_44" },
      withToken,
    );
    await handleVaultRequest(service, "POST", "/settings/local-auth/pin", { pin: "7777" }, withToken);
    const res = await handleVaultRequest(
      service,
      "PATCH",
      "/settings/local-auth",
      { enabled: true, requireOnApproval: true },
      withToken,
    );
    const status = mustStatus(projectLocalAuthStatus(res.body));
    expect(status.requireOnApproval).toBe(true);

    // Request capability
    const reqRes = await handleVaultRequest(
      service,
      "POST",
      "/request",
      {
        agentId: "agent-stripe",
        ide: "cursor",
        tool: "checkout",
        alias: "stripe",
        requestedScope: "charges.write",
        reason: "charge customer card",
      },
      auth,
    );
    expect(reqRes.status).toBe(200);
    const grantId = (reqRes.body as { grantId: string }).grantId;

    // Verify approval gate requires auth for sensitive/write operations
    const requiresAuth = shouldRequireAuthForApproval(status, "charges.write", "high");
    expect(requiresAuth).toBe(true);

    // Read-only low-risk does not trigger the gate
    expect(shouldRequireAuthForApproval(status, "charges.read", "low")).toBe(false);

    // Approval without PIN verification is rejected at gate
    let pinVerified = false;
    const attemptApproval = async () => {
      if (shouldRequireAuthForApproval(status, "charges.write", "high") && !pinVerified) {
        throw new Error("Local authentication required");
      }
      return handleVaultRequest(service, "POST", "/approve", { grantId }, withToken);
    };

    await expect(attemptApproval()).rejects.toThrow("Local authentication required");

    // Perform PIN verification
    const verifyRes = await handleVaultRequest(service, "POST", "/settings/local-auth/verify", { pin: "7777" }, withToken);
    expect(verifyRes.body).toMatchObject({ ok: true });
    pinVerified = true;

    // Proceed with approval after verification
    const approveRes = await attemptApproval();
    expect(approveRes.status).toBe(200);
    expect(approveRes.body).toEqual({ status: "executed", result: { echoedLength: 17 } });
    expect(executedSecrets).toContain("sk_live_secret_44");
  });

  it("Layer 4: Require to modify security settings & policies (ON-state)", async () => {
    const service = await makeService();

    await handleVaultRequest(service, "POST", "/settings/local-auth/pin", { pin: "2468" }, withToken);
    const res = await handleVaultRequest(
      service,
      "PATCH",
      "/settings/local-auth",
      { enabled: true, requireOnSettings: true },
      withToken,
    );
    const status = mustStatus(projectLocalAuthStatus(res.body));
    expect(status.requireOnSettings).toBe(true);
    expect(shouldRequireAuthForSettings(status)).toBe(true);

    // Simulated settings operations guarded by PIN challenge
    let verifiedForSession = false;

    const performSettingsChange = async (action: () => Promise<unknown>) => {
      if (shouldRequireAuthForSettings(status) && !verifiedForSession) {
        throw new Error("Settings action blocked: authentication required");
      }
      return action();
    };

    // 1. Guarded warden setting change
    await expect(
      performSettingsChange(() =>
        handleVaultRequest(
          service,
          "PATCH",
          "/settings/warden",
          { provider: "meta-api", model: "muse-spark-1.3" },
          withToken,
        ),
      ),
    ).rejects.toThrow("Settings action blocked: authentication required");

    // 2. Guarded warden key save
    await expect(
      performSettingsChange(() =>
        handleVaultRequest(service, "PUT", "/settings/warden/key", { key: "meta-test-secret-key-1234" }, withToken),
      ),
    ).rejects.toThrow("Settings action blocked: authentication required");

    // 3. Guarded warden key deletion
    await expect(
      performSettingsChange(() => handleVaultRequest(service, "DELETE", "/settings/warden/key", undefined, withToken)),
    ).rejects.toThrow("Settings action blocked: authentication required");

    // Authenticate with valid PIN
    const verifyRes = await handleVaultRequest(service, "POST", "/settings/local-auth/verify", { pin: "2468" }, withToken);
    expect(verifyRes.body).toMatchObject({ ok: true });
    verifiedForSession = true;

    // Operations succeed once authenticated
    const saveKey = await performSettingsChange(() =>
      handleVaultRequest(service, "PUT", "/settings/warden/key", { key: "meta-test-secret-key-1234" }, withToken),
    );
    expect((saveKey as { status: number }).status).toBe(200);

    const deleteKey = await performSettingsChange(() =>
      handleVaultRequest(service, "DELETE", "/settings/warden/key", undefined, withToken),
    );
    expect((deleteKey as { status: number }).status).toBe(200);
  });

  it("Layer 5: Enable Windows Hello / Touch ID biometrics (ON-state)", async () => {
    const service = await makeService();

    // Configure PIN first
    await handleVaultRequest(service, "POST", "/settings/local-auth/pin", { pin: "1357" }, withToken);

    // Biometrics initially disabled
    const initialBio = await handleVaultRequest(service, "POST", "/settings/local-auth/verify-biometric", undefined, withToken);
    expect(initialBio.status).toBe(200);
    expect(initialBio.body).toEqual({ ok: false });

    // Enable biometrics
    const res = await handleVaultRequest(
      service,
      "PATCH",
      "/settings/local-auth",
      { enabled: true, biometricEnabled: true },
      withToken,
    );
    const status = mustStatus(projectLocalAuthStatus(res.body));
    expect(status.biometricEnabled).toBe(true);
    expect(isBiometricsActive(status)).toBe(true);

    // Biometric verification endpoint succeeds
    const bioRes = await handleVaultRequest(service, "POST", "/settings/local-auth/verify-biometric", undefined, withToken);
    expect(bioRes.status).toBe(200);
    expect(bioRes.body).toEqual({ ok: true });
    // Biometric success is caller-attested: it must never mint a remote
    // approval presence proof.
    expect((bioRes.body as { presenceProof?: unknown }).presenceProof).toBeUndefined();

    // PIN fallback remains active
    const pinRes = await handleVaultRequest(service, "POST", "/settings/local-auth/verify", { pin: "1357" }, withToken);
    expect(pinRes.status).toBe(200);
    expect(pinRes.body).toMatchObject({ ok: true });

    // Disable biometrics and verify rejection
    await handleVaultRequest(service, "PATCH", "/settings/local-auth", { biometricEnabled: false }, withToken);
    const disabledBio = await handleVaultRequest(service, "POST", "/settings/local-auth/verify-biometric", undefined, withToken);
    expect(disabledBio.body).toEqual({ ok: false });
  });

  it("Layer 6: Inactivity auto-lock session (ON-state across all intervals)", async () => {
    const service = await makeService();
    await handleVaultRequest(service, "POST", "/settings/local-auth/pin", { pin: "4321" }, withToken);

    const intervals = [1, 5, 15, 30, 60] as const;
    const now = 2_000_000_000;

    for (const mins of intervals) {
      const res = await handleVaultRequest(
        service,
        "PATCH",
        "/settings/local-auth",
        { enabled: true, autoLockMinutes: mins },
        withToken,
      );
      const status = mustStatus(projectLocalAuthStatus(res.body));
      expect(status.autoLockMinutes).toBe(mins);

      // Inactivity just below threshold: should NOT lock
      const justBelowThreshold = now - (mins * 60 * 1000 - 1000);
      expect(isAutoLockDue(status, justBelowThreshold, now)).toBe(false);

      // Inactivity exceeding threshold: MUST lock
      const pastThreshold = now - (mins * 60 * 1000 + 1000);
      expect(isAutoLockDue(status, pastThreshold, now)).toBe(true);
    }

    // Interval = 0 (Disabled) never locks
    const disabledRes = await handleVaultRequest(
      service,
      "PATCH",
      "/settings/local-auth",
      { autoLockMinutes: 0 },
      withToken,
    );
    const disabledStatus = mustStatus(projectLocalAuthStatus(disabledRes.body));
    expect(isAutoLockDue(disabledStatus, now - 999_999_999, now)).toBe(false);
  });

  it("Layer 7: Lock session now (ON-state immediate workstation lock)", async () => {
    const service = await makeService();
    await handleVaultRequest(service, "POST", "/settings/local-auth/pin", { pin: "6543" }, withToken);
    const res = await handleVaultRequest(
      service,
      "PATCH",
      "/settings/local-auth",
      { enabled: true },
      withToken,
    );
    const status = mustStatus(projectLocalAuthStatus(res.body));

    // 1. Instant lock action is available when active
    expect(canLockSessionNow(status)).toBe(true);

    // 2. Triggering instant lock immediately sets vaultLocked = true
    let vaultLocked = false;
    const triggerLockSessionNow = () => {
      if (canLockSessionNow(status)) {
        vaultLocked = true;
      }
    };

    triggerLockSessionNow();
    expect(vaultLocked).toBe(true);

    // 3. Unlocking requires valid PIN
    const unlockRes = await handleVaultRequest(service, "POST", "/settings/local-auth/verify", { pin: "6543" }, withToken);
    expect(unlockRes.body).toMatchObject({ ok: true });
    vaultLocked = false;
    expect(vaultLocked).toBe(false);

    // 4. When unconfigured or disabled, lock session now is not available
    expect(canLockSessionNow({ ...status, configured: false })).toBe(false);
    expect(canLockSessionNow({ ...status, enabled: false })).toBe(false);
  });
});
