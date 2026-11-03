import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { createKeySession } from "../../core/src/key-session.js";
import { wrapMasterKey } from "../../core/src/keywrap.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { handleVaultRequest } from "../src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../src/service.js";

const TOKEN = "test-daemon-token-cards";
const auth = { daemonToken: TOKEN, providedToken: TOKEN };
const NUMBER = "4242424242424242";
const CARD = { alias: "corp-visa", number: "4242 4242 4242 4242", name: "Ada Lovelace", expMonth: 12, expYear: 2039, cvv: "123" };

// A marshal that tries to auto-approve everything: cards must still wait.
const BrainPermissive = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({ risk: "low" as const, recommendedScope: "card.payment:write", requireApproval: false, explanation: "looks fine" }),
});
let connectorCalls = 0;
const CountingConnector = Layer.succeed(Connector, {
  execute: () => {
    connectorCalls += 1;
    return Effect.succeed({ ok: true });
  },
});

async function makeService(options: Parameters<typeof makeVaultServiceLive>[0] = { masterKey: Buffer.alloc(32, 7) }): Promise<VaultServiceService> {
  return Effect.runPromise(
    Effect.gen(function* () {
      return yield* VaultService;
    }).pipe(
      Effect.provide(makeVaultServiceLive(options)),
      Effect.provide(Layer.mergeAll(VaultStoreTest(), BrainPermissive, CountingConnector)),
    ),
  );
}

const cardRequest = { agentId: "cursor", ide: "Cursor", tool: "http", alias: "corp-visa", requestedScope: "card.payment:write", reason: "pay invoice" };

describe("payment card credentials", () => {
  it("POST /cards needs the token, validates, and returns only masked metadata", async () => {
    const service = await makeService();
    expect((await handleVaultRequest(service, "POST", "/cards", CARD, { daemonToken: TOKEN })).status).toBe(401);
    const bad = await handleVaultRequest(service, "POST", "/cards", { ...CARD, number: "4242424242424241" }, auth);
    expect(bad.status).toBe(400);
    expect(JSON.stringify(bad.body)).toContain("CardInvalid");
    const res = await handleVaultRequest(service, "POST", "/cards", CARD, auth);
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ alias: "corp-visa", kind: "card", card: { brand: "visa", last4: "4242" } });
    const dup = await handleVaultRequest(service, "POST", "/cards", CARD, auth);
    expect(dup.status).toBe(409);

    for (const path of ["/aliases", "/audit"]) {
      const text = JSON.stringify((await handleVaultRequest(service, "GET", path, undefined, auth)).body);
      expect(text).not.toContain(NUMBER);
      expect(text).not.toContain("Ada Lovelace");
      expect(text).not.toContain("2039");
      expect(text).not.toContain('"123"');
    }
    const aliases = (await handleVaultRequest(service, "GET", "/aliases")).body as { credentials: { alias: string; kind: string; card?: { last4: string } }[] };
    const entry = aliases.credentials.find((c) => c.alias === "corp-visa");
    expect(entry?.kind).toBe("card");
    expect(entry?.card?.last4).toBe("4242");
  });

  it("a card request always awaits a human even when the warden says low risk", async () => {
    const service = await makeService();
    await handleVaultRequest(service, "POST", "/cards", CARD, auth);
    const first = await handleVaultRequest(service, "POST", "/request", cardRequest);
    expect(first.status).toBe(200);
    const body = first.body as Record<string, unknown>;
    expect(body["status"]).toBe("awaiting-approval");
    expect(JSON.stringify(body)).not.toContain(NUMBER);
  });

  it("refuses approve-always for cards and refuses to execute with no payment connector", async () => {
    connectorCalls = 0;
    const service = await makeService();
    await handleVaultRequest(service, "POST", "/cards", CARD, auth);
    const first = await handleVaultRequest(service, "POST", "/request", cardRequest);
    const grantId = (first.body as { grantId: string }).grantId;
    const always = await handleVaultRequest(service, "POST", "/approve-always", { grantId }, auth);
    expect(always.status).toBeGreaterThanOrEqual(400);
    const approved = await handleVaultRequest(service, "POST", "/approve", { grantId }, auth);
    expect(approved.status).toBeGreaterThanOrEqual(400);
    expect(JSON.stringify(approved.body)).toContain("no payment connector");
    expect(JSON.stringify(approved.body)).not.toContain(NUMBER);
    expect(connectorCalls).toBe(0);
  });

  it("rejects a card number pasted in as a plain secret", async () => {
    const service = await makeService();
    const res = await handleVaultRequest(
      service,
      "POST",
      "/credentials",
      { alias: "sneaky", scope: "x.read", secret: JSON.stringify({ type: "payment-card", v: 1, number: NUMBER }) },
      auth,
    );
    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});

describe("passphrase key session over HTTP", () => {
  it("is locked (423) until /unlock, then relocks on /lock", async () => {
    const pass = "daemon unlock passphrase";
    const wrapped = await wrapMasterKey(Buffer.alloc(32, 1), pass, { params: { N: 2 ** 12, r: 8, p: 1 }, allowWeakParams: true });
    const keySession = createKeySession({ mode: "passphrase", wrapped, sweepMs: 0 });
    const service = await makeService({ keySession });
    const status = await handleVaultRequest(service, "GET", "/key/status", undefined, auth);
    expect(status.body).toMatchObject({ mode: "passphrase", locked: true });

    const locked = await handleVaultRequest(service, "POST", "/credentials", { alias: "gh", scope: "repo.read", secret: "s3cret-value" }, auth);
    expect(locked.status).toBe(423);
    expect(JSON.stringify(locked.body)).toContain("VaultLocked");

    // /unlock is token-protected.
    expect((await handleVaultRequest(service, "POST", "/unlock", { passphrase: pass }, { daemonToken: TOKEN })).status).toBe(401);
    const wrong = await handleVaultRequest(service, "POST", "/unlock", { passphrase: "wrong passphrase here" }, auth);
    expect(wrong.status).toBe(401);
    expect(JSON.stringify(wrong.body)).toContain("WrongPassphrase");
    expect((await handleVaultRequest(service, "POST", "/unlock", { passphrase: pass }, auth)).status).toBe(200);
    const added = await handleVaultRequest(service, "POST", "/credentials", { alias: "gh", scope: "repo.read", secret: "s3cret-value" }, auth);
    expect(added.status).toBe(201);
    expect((await handleVaultRequest(service, "POST", "/lock", undefined, auth)).status).toBe(200);
    expect((await handleVaultRequest(service, "GET", "/key/status", undefined, auth)).body).toMatchObject({ locked: true });
    keySession.dispose();
  });
});
