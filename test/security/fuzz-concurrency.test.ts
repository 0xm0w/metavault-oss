import type { Server } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Effect, Layer } from "effect";
import { afterEach, describe, expect, it } from "vitest";
import { Brain } from "../../packages/brain/src/brain.js";
import { Connector } from "../../packages/core/src/connector.js";
import { VaultStoreTest } from "../../packages/core/src/storage.js";
import type { MarshalDecision } from "../../packages/core/src/types.js";
import { createOpenVaultMcpServer, type DaemonFetch } from "../../packages/mcp/src/server.js";
import { createVaultHttpServer, handleVaultRequest } from "../../packages/daemon/src/server.js";
import {
  makeVaultServiceLive,
  VaultService,
  type VaultServiceService,
} from "../../packages/daemon/src/service.js";

const TOKEN = "fuzz-test-daemon-token-abcdef";
const CANARY = "FUZZ-SECRET-CANARY-999-never-leak";
const MASTER = Buffer.alloc(32, 9);

interface Daemon {
  readonly base: string;
  readonly service: VaultServiceService;
  readonly connectorExecutions: { alias: string; scope: string }[];
  readonly close: () => Promise<void>;
}

const servers: Daemon[] = [];

async function startDaemon(): Promise<Daemon> {
  const connectorExecutions: Daemon["connectorExecutions"] = [];
  const decision: MarshalDecision = {
    risk: "low",
    recommendedScope: "charges.read",
    requireApproval: true,
    explanation: "fuzz harness",
  };

  const brain = Layer.succeed(Brain, { assess: () => Effect.succeed(decision) });
  const connector = Layer.succeed(Connector, {
    execute: (alias, scope, secret) => {
      connectorExecutions.push({ alias, scope });
      return Effect.succeed({ echoedLength: secret.length, scope });
    },
  });

  const service = await Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* VaultService;
      yield* svc.seedCredential("stripe", "charges.read", CANARY);
      return svc;
    }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: MASTER })),
      Effect.provide(Layer.mergeAll(VaultStoreTest(MASTER), brain, connector)),
    ),
  );

  const server: Server = createVaultHttpServer(service, { daemonToken: TOKEN });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port");

  const daemon: Daemon = {
    base: `http://127.0.0.1:${String(address.port)}`,
    service,
    connectorExecutions,
    close: () => new Promise<void>((resolve) => { server.close(() => { resolve(); }); }),
  };
  servers.push(daemon);
  return daemon;
}

afterEach(async () => {
  for (const s of servers.splice(0)) {
    await s.close();
  }
});

describe("Adversarial Stress Testing & Fuzzing Suite (#22)", () => {
  describe("Adversarial Payload Fuzzing", () => {
    it("rejects oversized request bodies > 64 KiB fail-closed with 413 without crashing daemon", async () => {
      const daemon = await startDaemon();
      const oversizedPayload = JSON.stringify({
        agentId: "fuzzer",
        ide: "Cursor",
        tool: "http",
        alias: "stripe",
        requestedScope: "charges.read",
        reason: "x".repeat(70 * 1024), // 70 KiB
      });

      const res = await fetch(`${daemon.base}/request`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: oversizedPayload,
      });

      expect(res.status).toBe(413);
      // Ensure daemon remains healthy and responsive after rejected attack
      const healthCheck = await fetch(`${daemon.base}/policies`);
      expect(healthCheck.status).toBe(200);
    });

    it("rejects malformed, deeply nested, and prototype pollution payloads fail-closed", async () => {
      const daemon = await startDaemon();

      const malformedCases = [
        "not json at all { { [",
        '{"agentId": "\0\0nullbytes\0\0"}',
        '{"__proto__": {"polluted": true}, "alias": "stripe"}',
        JSON.stringify({
          agentId: "fuzzer",
          nested: JSON.parse("{\"a\":".repeat(50) + "1" + "}".repeat(50)) as unknown,
        }),
      ];

      for (const payload of malformedCases) {
        const res = await fetch(`${daemon.base}/request`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: payload,
        });

        expect(res.status).toBe(400);
      }
    });

    it("safely rejects extreme string lengths and unicode homoglyphs in parameters", async () => {
      const daemon = await startDaemon();

      const res = await fetch(`${daemon.base}/request`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          agentId: "A".repeat(10_000),
          ide: "Cursor",
          tool: "http",
          alias: "stripe\u202E\u0000admin",
          requestedScope: "charges.read",
          reason: "test",
        }),
      });

      expect(res.status).toBe(400);
    });
  });

  describe("Concurrency & Race-Condition Resistance", () => {
    it("guarantees atomic single-use: exactly one execution succeeds among 50 concurrent races", async () => {
      const daemon = await startDaemon();

      // Request capability that awaits approval
      const reqRes = await fetch(`${daemon.base}/request`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          agentId: "cursor-race",
          ide: "Cursor",
          tool: "http",
          alias: "stripe",
          requestedScope: "charges.read",
          reason: "concurrency test",
        }),
      });

      expect(reqRes.status).toBe(200);
      const grantId = ((await reqRes.json()) as { grantId: string }).grantId;
      expect(grantId).toBeDefined();

      // Race 50 concurrent approve calls on the exact same grantId simultaneously
      const concurrencyLevel = 50;
      const racePromises = Array.from({ length: concurrencyLevel }, () =>
        fetch(`${daemon.base}/approve`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-openvault-token": TOKEN,
          },
          body: JSON.stringify({ grantId }),
        }),
      );

      const responses = await Promise.all(racePromises);
      const statuses = responses.map((r) => r.status);

      // Exactly ONE approval execution must return 200
      const successes = statuses.filter((s) => s === 200);
      const rejections = statuses.filter((s) => s === 400 || s === 404 || s === 409);

      expect(successes).toHaveLength(1);
      expect(rejections).toHaveLength(concurrencyLevel - 1);

      // Connector must have recorded exactly 1 execution
      expect(daemon.connectorExecutions).toHaveLength(1);
    });

    it("handles concurrent revoke vs approve races safely fail-closed", async () => {
      const daemon = await startDaemon();

      // Create a pending grant
      const reqRes = await fetch(`${daemon.base}/request`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          agentId: "agent-to-revoke",
          ide: "Cursor",
          tool: "http",
          alias: "stripe",
          requestedScope: "charges.read",
          reason: "race revoke test",
        }),
      });
      const grantId = ((await reqRes.json()) as { grantId: string }).grantId;

      // Race approve vs revoke
      const [approveRes, revokeRes] = await Promise.all([
        fetch(`${daemon.base}/approve`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-openvault-token": TOKEN,
          },
          body: JSON.stringify({ grantId }),
        }),
        fetch(`${daemon.base}/revoke`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-openvault-token": TOKEN,
          },
          body: JSON.stringify({ target: "agent-to-revoke" }),
        }),
      ]);

      expect(revokeRes.status).toBe(200);
      // Either approve won the race before revoke (200), or failed because it was revoked/expired/not found (400, 403, 404)
      expect([200, 400, 403, 404]).toContain(approveRes.status);

      // A subsequent approve attempt after revoke must ALWAYS fail
      const subsequentApprove = await fetch(`${daemon.base}/approve`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-openvault-token": TOKEN,
        },
        body: JSON.stringify({ grantId }),
      });
      expect([400, 404, 409]).toContain(subsequentApprove.status);
    });
  });

  describe("Resource Profiling & Stress Endurance", () => {
    it("executes rapid request-approve cycles with stable heap and no resource leaks", async () => {
      const daemon = await startDaemon();
      const initialMem = process.memoryUsage().heapUsed;

      // Run 100 sequential request & approve cycles with rotating agents to test endurance
      for (let i = 0; i < 100; i++) {
        const req = await fetch(`${daemon.base}/request`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            agentId: `bench-agent-${String(i)}`,
            ide: "Cursor",
            tool: "http",
            alias: "stripe",
            requestedScope: "charges.read",
            reason: "stress cycle",
          }),
        });
        expect(req.status).toBe(200);
        const data = (await req.json()) as { grantId: string };
        expect(data.grantId).toBeDefined();

        const approve = await fetch(`${daemon.base}/approve`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-openvault-token": TOKEN,
          },
          body: JSON.stringify({ grantId: data.grantId }),
        });
        expect(approve.status).toBe(200);
      }

      const finalMem = process.memoryUsage().heapUsed;
      // Assert heap growth is bounded (< 30 MB across cycles)
      const growthMb = (finalMem - initialMem) / (1024 * 1024);
      expect(growthMb).toBeLessThan(30);
    });
  });

  describe("MCP Tool Surface Adversarial Fuzzing", () => {
    it("safely handles malformed, prototype pollution, and oversized MCP tool inputs", async () => {
      const daemon = await startDaemon();

      const daemonFetch: DaemonFetch = async (input, init) => {
        const raw =
          typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
        const url = new URL(raw);
        const method = init?.method ?? "GET";
        const body: unknown =
          typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
        const out = await handleVaultRequest(daemon.service, method, url.pathname, body);
        return new Response(JSON.stringify(out.body), {
          status: out.status,
          headers: { "content-type": "application/json" },
        });
      };

      const mcpServer = createOpenVaultMcpServer({
        daemonUrl: daemon.base,
        agentId: "fuzz-agent",
        ide: "Cursor",
        fetchFn: daemonFetch,
      });

      const mcpClient = new Client({ name: "mcp-fuzzer", version: "1.0.0" });
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      await mcpServer.connect(serverTransport);
      await mcpClient.connect(clientTransport);

      const adversarialToolInputs = [
        { name: "request_capability", arguments: { alias: "stripe".repeat(500), scope: "charges.read", reason: "overflow" } },
        { name: "request_capability", arguments: { alias: "stripe\0injection", scope: "charges.read", reason: "nullbyte" } },
        { name: "request_capability", arguments: { alias: "stripe\u202Ereversed", scope: "charges.read", reason: "bidi" } },
        { name: "revoke", arguments: { target: "x".repeat(10_000) } },
        { name: "request_enrollment", arguments: { alias: "test", scope: "read", website: "https://".concat("a".repeat(1000)) } },
      ];

      for (const input of adversarialToolInputs) {
        const res = await mcpClient.callTool(input);
        // The MCP server must fail safely with an error response, never throwing uncaught exceptions or crashing
        const isErr = (res as { isError?: boolean }).isError;
        const content = (res as { content?: readonly { text?: string }[] }).content ?? [];
        const text = content.map((c) => c.text ?? "").join(" ");
        expect(isErr === true || text.includes("error") || text.includes("denied") || text.includes("invalid")).toBe(true);
      }

      await mcpClient.close();
    });
  });
});
