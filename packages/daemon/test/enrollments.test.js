import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { handleVaultRequest } from "../src/server.js";
import { makeVaultServiceLive, VaultService } from "../src/service.js";
const SECRET = "[REDACTED]";
const TOKEN = "test-daemon-token-enroll";
const BrainLowRisk = Layer.succeed(Brain, { assess: () => Effect.succeed({ risk: "low", recommendedScope: "charges.read", requireApproval: true, explanation: "ok" }) });
const FakeConnector = Layer.succeed(Connector, { execute: (_a, _s, secret) => Effect.succeed({ echoedLength: secret.length }) });
async function makeService(ttl) {
    return Effect.runPromise(Effect.gen(function* () { return yield* VaultService; }).pipe(Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 7), ...(ttl !== undefined ? { enrollmentTtlMs: ttl } : {}) })), Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), BrainLowRisk, FakeConnector))));
}
describe("enrollments", () => {
    it("create -> pending -> credential save completes -> status completed, audit alias-only, no token needed", async () => {
        const service = await makeService();
        const created = await handleVaultRequest(service, "POST", "/enrollments", { alias: "stripe", scope: "charges.read", website: "stripe.com" });
        expect(created.status).toBe(201);
        const body = created.body;
        expect(body.deeplink).toContain("openvault://add?");
        expect(body.deeplink).toContain("alias=stripe");
        expect(body.deeplink).toContain(`enrollment=${body.enrollmentId}`);
        expect(JSON.stringify(created.body)).not.toContain(SECRET);
        const pending = await handleVaultRequest(service, "GET", `/enrollments/${body.enrollmentId}`);
        expect(pending.body).toEqual({ status: "pending", alias: "stripe", scope: "charges.read" });
        const saved = await handleVaultRequest(service, "POST", "/credentials", { alias: "stripe", scope: "charges.read", secret: SECRET, website: "stripe.com", enrollmentId: body.enrollmentId }, { daemonToken: TOKEN, providedToken: TOKEN });
        expect(saved.status).toBe(201);
        const done = await handleVaultRequest(service, "GET", `/enrollments/${body.enrollmentId}`);
        expect(done.body).toEqual({ status: "completed", alias: "stripe", scope: "charges.read" });
        const audit = await handleVaultRequest(service, "GET", "/audit");
        const stages = audit.body.events.map((e) => e.stage);
        expect(stages).toContain("enrollment-created");
        expect(stages).toContain("enrollment-completed");
        expect(JSON.stringify(audit.body)).not.toContain(SECRET);
    });
    it("mismatched alias does not complete; unknown id 404; bad body 400", async () => {
        const service = await makeService();
        const created = await handleVaultRequest(service, "POST", "/enrollments", { alias: "stripe", scope: "charges.read" });
        const id = created.body.enrollmentId;
        await handleVaultRequest(service, "POST", "/credentials", { alias: "other", scope: "x.read", secret: SECRET, enrollmentId: id }, { daemonToken: TOKEN, providedToken: TOKEN });
        expect((await handleVaultRequest(service, "GET", `/enrollments/${id}`)).body).toMatchObject({ status: "pending" });
        expect((await handleVaultRequest(service, "GET", "/enrollments/nope")).status).toBe(404);
        expect((await handleVaultRequest(service, "POST", "/enrollments", { alias: "" })).status).toBe(400);
    });
    it("scope mismatch does not complete the enrollment", async () => {
        const service = await makeService();
        const created = await handleVaultRequest(service, "POST", "/enrollments", { alias: "stripe", scope: "charges.read" });
        const id = created.body.enrollmentId;
        const saved = await handleVaultRequest(service, "POST", "/credentials", { alias: "stripe", scope: "refunds.read", secret: SECRET, enrollmentId: id }, { daemonToken: TOKEN, providedToken: TOKEN });
        expect(saved.status).toBe(201);
        expect((await handleVaultRequest(service, "GET", `/enrollments/${id}`)).body).toMatchObject({ status: "pending" });
    });
    it("purges expired enrollments on create and on status read", async () => {
        const service = await makeService(40);
        const a = await handleVaultRequest(service, "POST", "/enrollments", { alias: "a", scope: "a.read" });
        const b = await handleVaultRequest(service, "POST", "/enrollments", { alias: "b", scope: "b.read" });
        const aId = a.body.enrollmentId;
        const bId = b.body.enrollmentId;
        await new Promise((r) => setTimeout(r, 60));
        // Status read of b purges other expired records (a).
        expect((await handleVaultRequest(service, "GET", `/enrollments/${bId}`)).body).toMatchObject({ status: "expired" });
        expect((await handleVaultRequest(service, "GET", `/enrollments/${aId}`)).status).toBe(404);
        // Create also purges: b (expired, retained only as the last-read record) is gone after a new create.
        await handleVaultRequest(service, "POST", "/enrollments", { alias: "c", scope: "c.read" });
        expect((await handleVaultRequest(service, "GET", `/enrollments/${bId}`)).status).toBe(404);
    });
    it("forwards reason into the enrollment-created audit detail, capped", async () => {
        const service = await makeService();
        const reason = "need-access-" + "x".repeat(500);
        const created = await handleVaultRequest(service, "POST", "/enrollments", { alias: "stripe", scope: "charges.read", reason });
        expect(created.status).toBe(201);
        const audit = await handleVaultRequest(service, "GET", "/audit");
        const events = audit.body.events;
        const ev = events.find((e) => e.stage === "enrollment-created");
        expect(ev?.detail).toContain("need-access-");
        expect(ev?.detail.length).toBeLessThanOrEqual(300);
        expect(ev?.detail).not.toContain(SECRET);
    });
    it("malformed percent-encoding on /enrollments/:id returns 400, not 500", async () => {
        const service = await makeService();
        expect((await handleVaultRequest(service, "GET", "/enrollments/%E0%A4%A")).status).toBe(400);
        expect((await handleVaultRequest(service, "GET", "/enrollments/%zz")).status).toBe(400);
    });
    it("expires after TTL", async () => {
        const service = await makeService(1);
        const created = await handleVaultRequest(service, "POST", "/enrollments", { alias: "stripe", scope: "charges.read" });
        const id = created.body.enrollmentId;
        await new Promise((r) => setTimeout(r, 10));
        expect((await handleVaultRequest(service, "GET", `/enrollments/${id}`)).body).toMatchObject({ status: "expired" });
    });
});
