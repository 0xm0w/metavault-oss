import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect, Layer } from "effect";
import { afterEach, describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { daemonTokenFilePath, handleVaultRequest, resolveDaemonToken, } from "../src/server.js";
import { makeVaultServiceLive, VaultService } from "../src/service.js";
const CANARY = "[REDACTED]";
const TOKEN = "test-daemon-token-0123456789abcdef";
const BrainLowRisk = Layer.succeed(Brain, {
    assess: () => Effect.succeed({
        risk: "low",
        recommendedScope: "charges.read",
        requireApproval: true,
        explanation: "ok",
    }),
});
const FakeConnector = Layer.succeed(Connector, {
    execute: (_a, _s, secret) => Effect.succeed({ echoedLength: secret.length }),
});
async function makeService() {
    return Effect.runPromise(Effect.gen(function* () {
        const svc = yield* VaultService;
        yield* svc.seedCredential("stripe", "charges.read", CANARY);
        return svc;
    }).pipe(Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 7) })), Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), BrainLowRisk, FakeConnector))));
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
async function pendingGrant(service) {
    const created = await handleVaultRequest(service, "POST", "/request", req, auth);
    expect(created.status).toBe(200);
    const grantId = created.body["grantId"];
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
        expect(ok.body["status"]).toBe("executed");
        expect(JSON.stringify(ok.body)).not.toContain(CANARY);
    });
    it("guards /approve-always, /deny and GET /pending the same way", async () => {
        const service = await makeService();
        const first = await pendingGrant(service);
        // Create the second grant up front: approve-always makes later identical
        // requests execute immediately via the standing approval.
        const second = await pendingGrant(service);
        const alwaysNoToken = await handleVaultRequest(service, "POST", "/approve-always", { grantId: first }, auth);
        expect(alwaysNoToken.status).toBe(401);
        const alwaysOk = await handleVaultRequest(service, "POST", "/approve-always", { grantId: first }, withToken);
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
    it("leaves /request, /aliases, /audit, /policies and /revoke open without a token", async () => {
        const service = await makeService();
        const created = await handleVaultRequest(service, "POST", "/request", req, auth);
        expect(created.status).toBe(200);
        expect(created.body["status"]).toBe("awaiting-approval");
        for (const path of ["/aliases", "/audit", "/policies"]) {
            const res = await handleVaultRequest(service, "GET", path, undefined, auth);
            expect(res.status).toBe(200);
        }
        const revoked = await handleVaultRequest(service, "POST", "/revoke", { target: "cursor" }, auth);
        expect(revoked.status).toBe(200);
    });
});
describe("resolveDaemonToken", () => {
    const saved = process.env["OPENVAULT_DAEMON_TOKEN"];
    afterEach(() => {
        if (saved === undefined) {
            delete process.env["OPENVAULT_DAEMON_TOKEN"];
        }
        else {
            process.env["OPENVAULT_DAEMON_TOKEN"] = saved;
        }
    });
    it("prefers OPENVAULT_DAEMON_TOKEN from the environment", () => {
        process.env["OPENVAULT_DAEMON_TOKEN"] = "env-token-value";
        const dir = mkdtempSync(join(tmpdir(), "openvault-token-"));
        try {
            expect(resolveDaemonToken(join(dir, "openvault.db"))).toBe("env-token-value");
            expect(existsSync(daemonTokenFilePath(join(dir, "openvault.db")))).toBe(false);
        }
        finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
    it("generates a random token and writes it next to the DB file otherwise", () => {
        delete process.env["OPENVAULT_DAEMON_TOKEN"];
        const dir = mkdtempSync(join(tmpdir(), "openvault-token-"));
        try {
            const dbPath = join(dir, "openvault.db");
            const token = resolveDaemonToken(dbPath);
            expect(token.length).toBeGreaterThanOrEqual(32);
            expect(readFileSync(daemonTokenFilePath(dbPath), "utf8")).toBe(token);
            // A second resolve generates a fresh token (the file is the record).
            expect(resolveDaemonToken(dbPath)).not.toBe(token);
        }
        finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
});
