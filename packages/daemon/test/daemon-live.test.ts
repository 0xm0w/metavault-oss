import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Effect, Layer } from "effect";
import { afterAll, describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { encryptSecret } from "../../core/src/crypto.js";
import { VaultStore, VaultStoreLive } from "../../core/src/storage.js";
import { startVaultDaemon } from "../src/server.js";

const SECRET = "[REDACTED]";
const MASTER_KEY = Buffer.alloc(32, 7);
const TOKEN = "live-daemon-token-0123456789abcdef";

const BrainLowRisk = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({
      risk: "low" as const,
      recommendedScope: "charges.read",
      requireApproval: true,
      explanation: "ok",
    }),
});

const closers: (() => Promise<void>)[] = [];
afterAll(async () => {
  await Promise.all(closers.splice(0).map((close) => close()));
});

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.closeAllConnections();
    server.close(() => {
      resolve();
    });
  });
}

// C1 smoke test: boot the real daemon entry point (startVaultDaemon) with
// the real ConnectorLive layer pointed at a local mock upstream via presets,
// then prove request -> approve -> executed over real HTTP. The old stub
// connector always failed with "connector not implemented yet", so an
// executed result with the upstream payload proves the real layer is wired.
describe("startVaultDaemon with the real connector layer", () => {
  it("boots on an ephemeral port and executes an approved grant against a mock upstream", async () => {
    let seenAuth = "";
    const upstream = createServer((req, res) => {
      seenAuth = req.headers.authorization ?? "";
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, charges: 5 }));
    });
    closers.push(() => closeServer(upstream));
    await new Promise<void>((resolve) => {
      upstream.listen(0, "127.0.0.1", () => {
        resolve();
      });
    });
    const upstreamAddress = upstream.address();
    if (upstreamAddress === null || typeof upstreamAddress === "string") {
      throw new Error("mock upstream has no port");
    }
    const upstreamUrl = `http://127.0.0.1:${String(upstreamAddress.port)}/charges`;

    const dir = mkdtempSync(join(tmpdir(), "metavault-live-"));
    const dbPath = join(dir, "metavault.db");
    try {
      // Seed the credential straight into the vault file the daemon will open.
      await Effect.runPromise(
        Effect.gen(function* () {
          const store = yield* VaultStore;
          yield* store.addCredential("stripe", "charges.read", encryptSecret(MASTER_KEY, SECRET));
        }).pipe(Effect.provide(VaultStoreLive(dbPath, MASTER_KEY))),
      );

      const daemon = await startVaultDaemon({
        port: 0,
        dbPath,
        masterKey: MASTER_KEY,
        daemonToken: TOKEN,
        brain: BrainLowRisk,
        connectorPresets: { stripe: upstreamUrl },
      });
      closers.push(() => closeServer(daemon));
      const address = daemon.address();
      if (address === null || typeof address === "string") {
        throw new Error("daemon has no port");
      }
      const base = `http://127.0.0.1:${String(address.port)}`;

      const requested = await fetch(`${base}/request`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          agentId: "cursor",
          ide: "Cursor",
          tool: "http",
          alias: "stripe",
          requestedScope: "charges.read",
          reason: "list charges",
        }),
      });
      expect(requested.status).toBe(200);
      const requestedBody = (await requested.json()) as Record<string, unknown>;
      expect(requestedBody["status"]).toBe("awaiting-approval");
      const grantId = requestedBody["grantId"];
      if (typeof grantId !== "string") {
        throw new Error("expected a grantId");
      }

      // The daemon token guards approval even on the live socket.
      const unauthenticated = await fetch(`${base}/approve`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ grantId }),
      });
      expect(unauthenticated.status).toBe(401);

      const approved = await fetch(`${base}/approve`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-metavault-token": TOKEN },
        body: JSON.stringify({ grantId }),
      });
      expect(approved.status).toBe(200);
      const approvedText = await approved.text();
      const approvedBody = JSON.parse(approvedText) as {
        status: string;
        result: { status: number; data: unknown };
      };
      expect(approvedBody.status).toBe("executed");
      expect(approvedBody.result).toEqual({ status: 200, data: { ok: true, charges: 5 } });
      expect(seenAuth).toBe(`Bearer ${SECRET}`);
      expect(approvedText).not.toContain(SECRET);
    } finally {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // best effort: the daemon's sqlite handle may still be open on Windows
      }
    }
  });
});
