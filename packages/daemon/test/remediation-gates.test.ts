import { request as httpRequest } from "node:http";
import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { createKeySession } from "../../core/src/key-session.js";
import { wrapMasterKey } from "../../core/src/keywrap.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { createVaultHttpServer } from "../src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../src/service.js";

const KEY = Buffer.alloc(32, 4);

const ask = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({
      risk: "low" as const,
      recommendedScope: "charges.read",
      requireApproval: true,
      explanation: "needs a person",
    }),
});

const allow = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({
      risk: "low" as const,
      recommendedScope: "charges.read",
      requireApproval: false,
      explanation: "safe read",
    }),
});

function connector(calls: { n: number }) {
  return Layer.succeed(Connector, {
    execute: () => {
      calls.n += 1;
      return Effect.succeed({ ok: true });
    },
  });
}

async function build(brain: Layer.Layer<Brain>, calls: { n: number }, keySession?: ReturnType<typeof createKeySession>): Promise<VaultServiceService> {
  return Effect.runPromise(
    Effect.gen(function* () {
      return yield* VaultService;
    }).pipe(
      Effect.provide(makeVaultServiceLive(keySession !== undefined ? { keySession } : { masterKey: KEY })),
      Effect.provide(Layer.mergeAll(VaultStoreTest(keySession !== undefined ? Buffer.alloc(32, 1) : KEY), brain, connector(calls))),
    ),
  );
}

const readReq = {
  agentId: "cursor",
  ide: "Cursor",
  tool: "http",
  alias: "stripe",
  requestedScope: "charges.read",
  reason: "list charges",
};

function rawPost(
  port: number,
  headers: Record<string, string | number>,
  body: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/request",
        method: "POST",
        headers: { ...headers, "content-length": Buffer.byteLength(body) },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") });
        });
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

describe("loopback header gate", () => {
  it("rejects a rebound host, a browser origin, and a non-JSON body", async () => {
    const calls = { n: 0 };
    const service = await build(ask, calls);
    const server = createVaultHttpServer(service, { daemonToken: "tok" });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("no port");
    try {
      const host = await rawPost(address.port, { host: "rebind.attacker.com", "content-type": "application/json" }, "{}");
      expect(host.status).toBe(403);
      expect(host.body).toContain("forbidden host header");
      const origin = await rawPost(
        address.port,
        { host: `127.0.0.1:${String(address.port)}`, origin: "https://evil.example", "content-type": "application/json" },
        "{}",
      );
      expect(origin.status).toBe(403);
      expect(origin.body).toContain("browser origin header not permitted");
      for (const value of ["null", "file://"]) {
        const blocked = await rawPost(
          address.port,
          { host: `127.0.0.1:${String(address.port)}`, origin: value, "content-type": "application/json" },
          "{}",
        );
        expect(blocked.status).toBe(403);
      }
      const type = await rawPost(
        address.port,
        { host: `127.0.0.1:${String(address.port)}`, "content-type": "text/plain" },
        "not-json",
      );
      expect(type.status).toBe(415);
      expect(type.body).toContain("content-type must be application/json");
      expect(calls.n).toBe(0);
    } finally {
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve();
        });
      });
    }
  });
});

describe("session lease and locked hold", () => {
  it("executes nine more calls after approve-session, then asks again", async () => {
    const calls = { n: 0 };
    const service = await build(ask, calls);
    await Effect.runPromise(service.seedCredential("stripe", "charges.read", "sk_test_lease"));
    const verified = { ...readReq, verified: true };
    const first = await Effect.runPromise(service.requestCapability(verified));
    expect(first.status).toBe("awaiting-approval");
    const approved = await Effect.runPromise(service.approveSession(first.grantId ?? ""));
    expect(approved.status).toBe("executed");
    expect(calls.n).toBe(1);
    for (let i = 0; i < 9; i += 1) {
      const next = await Effect.runPromise(service.requestCapability(verified));
      expect(next.status).toBe("executed");
    }
    expect(calls.n).toBe(10);
    const eleventh = await Effect.runPromise(service.requestCapability(verified));
    expect(eleventh.status).toBe("awaiting-approval");
    expect(calls.n).toBe(10);
  });

  it("holds an auto-approved request while the vault is locked and still denies an unknown alias", async () => {
    const calls = { n: 0 };
    const pass = "correct horse battery";
    const wrapped = await wrapMasterKey(Buffer.alloc(32, 1), pass, { params: { N: 2 ** 12, r: 8, p: 1 }, allowWeakParams: true });
    const keySession = createKeySession({ mode: "passphrase", wrapped, sweepMs: 0 });
    const service = await build(allow, calls, keySession);
    expect(await Effect.runPromise(service.unlockVault(pass))).toBe("unlocked");
    await Effect.runPromise(service.seedCredential("stripe", "charges.read", "sk_test_locked"));
    const open = await Effect.runPromise(service.requestCapability(readReq));
    expect(open.status).toBe("executed");
    expect(calls.n).toBe(1);
    await Effect.runPromise(service.lockVault());
    const held = await Effect.runPromise(service.requestCapability(readReq));
    expect(held.status).toBe("awaiting-approval");
    expect(calls.n).toBe(1);
    const pending = await Effect.runPromise(service.listPendingApprovals());
    expect(pending[0]?.marshalExplanation.startsWith("Vault is locked. Unlock MetaVault to continue.")).toBe(true);
    const missing = await Effect.runPromise(service.requestCapability({ ...readReq, alias: "nope" }));
    expect(missing).toMatchObject({ status: "denied", reason: "unknown-alias" });
    keySession.dispose();
  });

  it("wakes a grant waiter when the human denies", async () => {
    const calls = { n: 0 };
    const service = await build(ask, calls);
    await Effect.runPromise(service.seedCredential("stripe", "charges.read", "sk_test_wait"));
    const first = await Effect.runPromise(service.requestCapability(readReq));
    expect(first.grantId).toBeDefined();
    const grantId = first.grantId ?? "";
    const started = Date.now();
    const waiting = Effect.runPromise(service.waitForGrant(grantId, 5_000));
    await Effect.runPromise(service.deny(grantId));
    await waiting;
    expect(Date.now() - started).toBeLessThan(1_000);
    const grant = await Effect.runPromise(service.getGrant(grantId));
    expect(grant?.status).toBe("denied");
  });
});
