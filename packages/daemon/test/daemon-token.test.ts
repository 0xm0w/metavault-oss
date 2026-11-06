import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect, Layer } from "effect";
import { afterEach, describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import {
  daemonTokenFilePath,
  handleVaultRequest,
  resolveDaemonToken,
} from "../src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../src/service.js";

const CANARY = "[REDACTED]";
const TOKEN = "test-daemon-token-0123456789abcdef";

const BrainLowRisk = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({
      risk: "low" as const,
      recommendedScope: "charges.read",
      requireApproval: true,
      explanation: "ok",
    }),
});
const FakeConnector = Layer.succeed(Connector, {
  execute: (_a, _s, secret) => Effect.succeed({ echoedLength: secret.length }),
});

async function makeService(): Promise<VaultServiceService> {
  return Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* VaultService;
      yield* svc.seedCredential("stripe", "charges.read", CANARY);
      return svc;
    }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 7) })),
      Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), BrainLowRisk, FakeConnector)),
    ),
  );
}

const req = {
  agentId: "cursor",
  ide: "Cursor",
  tool: "http",
  alias: "stripe",
  requestedScope: "charges.read",
  reason: "list charges",
};

const auth = { daemonToken: TOKEN };
const withToken = { daemonToken: TOKEN, providedToken: TOKEN };

async function pendingGrant(service: VaultServiceService): Promise<string> {
  const created = await handleVaultRequest(service, "POST", "/request", req, auth);
  expect(created.status).toBe(200);
  const grantId = (created.body as Record<string, unknown>)["grantId"];
  if (typeof grantId !== "string") {
    throw new Error("expected a grantId");
  }
  return grantId;
}

describe("daemon token guard (handler level)", () => {
  it("approve without or with a wrong token is 401 with only an error tag; with the token it executes", async () => {
    const service = await makeService();
    const grantId = await pendingGrant(service);

    const missing = await handleVaultRequest(service, "POST", "/approve", { grantId }, auth);
    expect(missing.status).toBe(401);
    expect(missing.body).toEqual({
      error: { _tag: "Unauthorized", message: "unauthorized" },
    });
    expect(JSON.stringify(missing.body)).not.toContain(CANARY);
    expect(JSON.stringify(missing.body)).not.toContain(TOKEN);

    const wrong = await handleVaultRequest(service, "POST", "/approve", { grantId }, {
      daemonToken: TOKEN,
      providedToken: "wrong-token",
    });
    expect(wrong.status).toBe(401);

    // The grant survived the rejected attempts and still executes once.
    const ok = await handleVaultRequest(service, "POST", "/approve", { grantId }, withToken);
    expect(ok.status).toBe(200);
    expect((ok.body as Record<string, unknown>)["status"]).toBe("executed");
    expect(JSON.stringify(ok.body)).not.toContain(CANARY);
  });

  it("guards /approve-always, /deny and GET /pending the same way", async () => {
    const service = await makeService();

    const first = await pendingGrant(service);
    // Create the second grant up front: approve-always makes later identical
    // requests execute immediately via the standing approval.
    const second = await pendingGrant(service);
    const alwaysNoToken = await handleVaultRequest(
      service,
      "POST",
      "/approve-always",
      { grantId: first },
      auth,
    );
    expect(alwaysNoToken.status).toBe(401);
    const alwaysOk = await handleVaultRequest(
      service,
      "POST",
      "/approve-always",
      { grantId: first },
      withToken,
    );
    expect(alwaysOk.status).toBe(200);

    const denyNoToken = await handleVaultRequest(service, "POST", "/deny", { grantId: second }, auth);
    expect(denyNoToken.status).toBe(401);
    const pendingNoToken = await handleVaultRequest(service, "GET", "/pending", undefined, auth);
    expect(pendingNoToken.status).toBe(401);
    const pendingOk = await handleVaultRequest(service, "GET", "/pending", undefined, withToken);
    expect(pendingOk.status).toBe(200);
    const denyOk = await handleVaultRequest(service, "POST", "/deny", { grantId: second }, withToken);
    expect(denyOk.status).toBe(200);
  });

  it("leaves /request, /aliases, /audit and /policies open and requires a token for /revoke", async () => {
    const service = await makeService();
    const created = await handleVaultRequest(service, "POST", "/request", req, auth);
    expect(created.status).toBe(200);
    expect((created.body as Record<string, unknown>)["status"]).toBe("awaiting-approval");

    for (const path of ["/aliases", "/audit", "/policies"] as const) {
      const res = await handleVaultRequest(service, "GET", path, undefined, auth);
      expect(res.status).toBe(200);
    }
    const revoked = await handleVaultRequest(service, "POST", "/revoke", { target: "cursor" }, auth);
    expect(revoked.status).toBe(401);
    const revokedOk = await handleVaultRequest(service, "POST", "/revoke", { target: "cursor" }, withToken);
    expect(revokedOk.status).toBe(200);
  });
});

describe("resolveDaemonToken", () => {
  const saved = process.env["METAVAULT_DAEMON_TOKEN"];
  afterEach(() => {
    if (saved === undefined) {
      delete process.env["METAVAULT_DAEMON_TOKEN"];
    } else {
      process.env["METAVAULT_DAEMON_TOKEN"] = saved;
    }
  });

  it("prefers METAVAULT_DAEMON_TOKEN from the environment and destroys any legacy token file", () => {
    process.env["METAVAULT_DAEMON_TOKEN"] = "env-token-value";
    const dir = mkdtempSync(join(tmpdir(), "metavault-token-"));
    try {
      const dbPath = join(dir, "metavault.db");
      writeFileSync(daemonTokenFilePath(dbPath), "legacy-on-disk-token", "utf8");
      expect(resolveDaemonToken(dbPath)).toBe("env-token-value");
      expect(existsSync(daemonTokenFilePath(dbPath))).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("never writes a token file and removes leftovers, with or without the env var", () => {
    delete process.env["METAVAULT_DAEMON_TOKEN"];
    const dir = mkdtempSync(join(tmpdir(), "metavault-token-"));
    try {
      const dbPath = join(dir, "metavault.db");
      // A legacy file the daemon must clean even without an env token.
      writeFileSync(daemonTokenFilePath(dbPath), "legacy-on-disk-token", "utf8");
      const token = resolveDaemonToken(dbPath);
      expect(token.length).toBeGreaterThanOrEqual(32);
      expect(existsSync(daemonTokenFilePath(dbPath))).toBe(false);
      // A second resolve still never materializes the token on disk.
      resolveDaemonToken(dbPath);
      expect(existsSync(daemonTokenFilePath(dbPath))).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
