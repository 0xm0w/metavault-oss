import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect, Layer } from "effect";
import { afterEach, describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { createFirstRunKeySession, createKeySession, type KeySession } from "../../core/src/key-session.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { firstRunSetupEnabled, handleVaultRequest } from "../src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../src/service.js";

const TOKEN = "first-run-token-0123456789abcdef";
const withToken = { daemonToken: TOKEN, providedToken: TOKEN };
const PASS = "first run passphrase 01";

const NoBrain = Layer.succeed(Brain, {
  assess: () => Effect.die("warden must not be called in these tests"),
});
const NoConnector = Layer.succeed(Connector, {
  execute: () => Effect.die("connector must not be called in these tests"),
});

async function serviceWith(keySession: KeySession): Promise<VaultServiceService> {
  return Effect.runPromise(
    Effect.gen(function* () {
      return yield* VaultService;
    }).pipe(
      Effect.provide(makeVaultServiceLive({ keySession })),
      Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 1)), NoBrain, NoConnector)),
    ),
  );
}

const dirs: string[] = [];
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "mv-first-run-"));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("GET /health", () => {
  it("answers 200 without a token and says nothing about the vault", async () => {
    const dir = tempDir();
    const service = await serviceWith(createFirstRunKeySession({ wrappedKeyPath: join(dir, "k.json"), sweepMs: 0 }));
    const res = await handleVaultRequest(service, "GET", "/health", undefined, { daemonToken: TOKEN });
    expect(res).toEqual({ status: 200, body: { status: "ok", service: "vaultd" } });
  });
});

describe("POST /setup (first run)", () => {
  it("needs the daemon token", async () => {
    const dir = tempDir();
    const service = await serviceWith(createFirstRunKeySession({ wrappedKeyPath: join(dir, "k.json"), sweepMs: 0 }));
    const res = await handleVaultRequest(service, "POST", "/setup", { passphrase: PASS }, { daemonToken: TOKEN });
    expect(res.status).toBe(401);
    expect(existsSync(join(dir, "k.json"))).toBe(false);
  });

  it("rejects a short passphrase with 400 and a bad body with 400", async () => {
    const dir = tempDir();
    const service = await serviceWith(createFirstRunKeySession({ wrappedKeyPath: join(dir, "k.json"), sweepMs: 0 }));
    const short = await handleVaultRequest(service, "POST", "/setup", { passphrase: "short" }, withToken);
    expect(short.status).toBe(400);
    expect(JSON.stringify(short.body)).toContain("PassphraseTooShort");
    const bad = await handleVaultRequest(service, "POST", "/setup", { nope: 1 }, withToken);
    expect(bad.status).toBe(400);
  });

  it("creates the key file, reports the vault unlocked, then refuses a second setup", async () => {
    const dir = tempDir();
    const keyPath = join(dir, "k.json");
    const service = await serviceWith(createFirstRunKeySession({ wrappedKeyPath: keyPath, sweepMs: 0 }));
    const before = await handleVaultRequest(service, "GET", "/key/status", undefined, withToken);
    expect(before.body).toMatchObject({ mode: "uninitialized", locked: true });
    const unlockFirst = await handleVaultRequest(service, "POST", "/unlock", { passphrase: PASS }, withToken);
    expect(unlockFirst.status).toBe(409);
    const created = await handleVaultRequest(service, "POST", "/setup", { passphrase: PASS }, withToken);
    expect(created).toEqual({ status: 200, body: { status: "initialized" } });
    expect(existsSync(keyPath)).toBe(true);
    const after = await handleVaultRequest(service, "GET", "/key/status", undefined, withToken);
    expect(after.body).toMatchObject({ mode: "passphrase", locked: false });
    const again = await handleVaultRequest(service, "POST", "/setup", { passphrase: PASS }, withToken);
    expect(again.status).toBe(409);
    expect(JSON.stringify(again.body)).toContain("AlreadyInitialized");
  });

  it("is unavailable (409) on a daemon whose key session has no setup step", async () => {
    const service = await serviceWith(createKeySession({ mode: "injected", key: Buffer.alloc(32, 2) }));
    const res = await handleVaultRequest(service, "POST", "/setup", { passphrase: PASS }, withToken);
    expect(res.status).toBe(409);
    expect(JSON.stringify(res.body)).toContain("SetupUnavailable");
  });
});

describe("daemon key resolution", () => {
  it("first-run mode is opt-in through METAVAULT_FIRST_RUN_SETUP=1", () => {
    expect(firstRunSetupEnabled({ METAVAULT_FIRST_RUN_SETUP: "1" })).toBe(true);
    expect(firstRunSetupEnabled({ METAVAULT_FIRST_RUN_SETUP: "true" })).toBe(false);
    expect(firstRunSetupEnabled({})).toBe(false);
  });

});
