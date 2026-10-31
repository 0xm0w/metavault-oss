import { mkdtempSync, rmSync } from "node:fs";
import type { Server as HttpServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Effect, Layer } from "effect";
import { afterAll, describe, expect, it } from "vitest";
import { Brain } from "../../packages/brain/src/brain.js";
import { Connector } from "../../packages/core/src/connector.js";
import { parseOpenVaultUrl } from "../../packages/app/src/deeplink.js";
import { startVaultDaemon } from "../../packages/daemon/src/server.js";
import { createOpenVaultMcpServer } from "../../packages/mcp/src/server.js";

// MCP <-> daemon e2e (Task 7): a real vaultd HTTP server on an ephemeral
// port (stub Brain layer + fake connector — no network, no Ollama) driven
// by a real MCP client through the OpenVault MCP server's default fetch.
// Flow asserted end to end: enroll -> human seed -> request -> approve ->
// execute -> revoke -> denied.
const SECRET = "e2e-secret-must-stay-inside-the-daemon-1234567890";
const MASTER_KEY = Buffer.alloc(32, 7);
const TOKEN = "e2e-daemon-token-0123456789abcdef";

const BrainStub = Layer.succeed(Brain, {
  assess: (req) =>
    Effect.succeed({
      risk: "low" as const,
      recommendedScope: req.requestedScope,
      requireApproval: true,
      explanation: "e2e stub marshal",
    }),
});

const connectorSecrets: string[] = [];
const FakeConnector = Layer.succeed(Connector, {
  execute: (alias, scope, secret) => {
    connectorSecrets.push(secret);
    return Effect.succeed({ alias, scope, echoedLength: secret.length });
  },
});

interface ToolResult {
  readonly isError?: boolean;
  readonly content?: readonly { readonly type: string; readonly text?: string }[];
  readonly structuredContent?: Record<string, unknown>;
}

function textOf(result: ToolResult): string {
  return (result.content ?? []).map((c) => c.text ?? "").join("\n");
}

const closers: (() => Promise<void>)[] = [];
afterAll(async () => {
  await Promise.all(closers.splice(0).map((close) => close()));
});

function closeHttp(server: HttpServer): Promise<void> {
  return new Promise((resolve) => {
    server.closeAllConnections();
    server.close(() => {
      resolve();
    });
  });
}

describe("MCP <-> daemon e2e (ephemeral port, stub brain, fake connector)", () => {
  it(
    "enroll -> human seed -> request -> approve -> execute -> revoke, end to end",
    async () => {
      const dir = mkdtempSync(join(tmpdir(), "openvault-e2e-"));
      const dbPath = join(dir, "openvault.db");
      const daemon = await startVaultDaemon({
        port: 0,
        dbPath,
        masterKey: MASTER_KEY,
        daemonToken: TOKEN,
        brain: BrainStub,
        connector: FakeConnector,
      });
      closers.push(() => closeHttp(daemon));
      try {
        const address = daemon.address();
        if (address === null || typeof address === "string") {
          throw new Error("daemon has no port");
        }
        const base = `http://127.0.0.1:${String(address.port)}`;

        const mcpServer = createOpenVaultMcpServer({
          daemonUrl: base,
          agentId: "e2e-agent",
          ide: "Cursor",
        });
        const client = new Client({ name: "e2e-client", version: "0.0.1" });
        const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
        await mcpServer.connect(serverTransport);
        await client.connect(clientTransport);
        closers.push(async () => {
          await client.close();
        });

        // 1. Enroll: agent asks the human to add a credential it does not have.
        const enroll = (await client.callTool({
          name: "request_enrollment",
          arguments: { alias: "github", scope: "repos.read", website: "github.com", reason: "e2e" },
        })) as ToolResult;
        expect(enroll.isError).not.toBe(true);
        const enrollmentId = enroll.structuredContent?.["enrollmentId"];
        const deeplink = enroll.structuredContent?.["deeplink"];
        expect(typeof enrollmentId).toBe("string");
        expect(typeof deeplink).toBe("string");
        expect(deeplink as string).not.toContain(SECRET);
        expect(parseOpenVaultUrl(deeplink as string)).toEqual({
          alias: "github",
          scope: "repos.read",
          website: "github.com",
          enrollmentId,
        });

        const pendingStatus = (await client.callTool({
          name: "enrollment_status",
          arguments: { enrollmentId },
        })) as ToolResult;
        expect(pendingStatus.structuredContent?.["status"]).toBe("pending");

        // 2. Human seed: only the human supplies the secret, token-guarded.
        const seedNoToken = await fetch(`${base}/credentials`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ alias: "github", scope: "repos.read", secret: SECRET, enrollmentId }),
        });
        expect(seedNoToken.status).toBe(401);
        const seeded = await fetch(`${base}/credentials`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-openvault-token": TOKEN },
          body: JSON.stringify({
            alias: "github",
            scope: "repos.read",
            secret: SECRET,
            website: "github.com",
            enrollmentId,
          }),
        });
        expect(seeded.status).toBe(201);
        expect(await seeded.text()).not.toContain(SECRET);

        const completedStatus = (await client.callTool({
          name: "enrollment_status",
          arguments: { enrollmentId },
        })) as ToolResult;
        expect(completedStatus.structuredContent?.["status"]).toBe("completed");

        const aliases = (await client.callTool({ name: "list_aliases", arguments: {} })) as ToolResult;
        expect(textOf(aliases)).toContain("github");
        expect(JSON.stringify(aliases)).not.toContain(SECRET);

        // 3. Request: the stub marshal parks it for human approval.
        const requested = (await client.callTool({
          name: "request_capability",
          arguments: { alias: "github", scope: "repos.read", reason: "e2e read repos" },
        })) as ToolResult;
        expect(requested.isError).not.toBe(true);
        expect(requested.structuredContent?.["status"]).toBe("awaiting-approval");
        const grantId = requested.structuredContent?.["grantId"];
        expect(typeof grantId).toBe("string");
        expect(JSON.stringify(requested)).not.toContain(SECRET);

        // 4. Approve: token-guarded human decision; execution stays in-daemon.
        const approveNoToken = await fetch(`${base}/approve`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ grantId }),
        });
        expect(approveNoToken.status).toBe(401);
        const approved = await fetch(`${base}/approve`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-openvault-token": TOKEN },
          body: JSON.stringify({ grantId }),
        });
        expect(approved.status).toBe(200);
        const approvedText = await approved.text();
        const approvedBody = JSON.parse(approvedText) as { status: string; result: unknown };
        expect(approvedBody.status).toBe("executed");
        expect(approvedBody.result).toEqual({
          alias: "github",
          scope: "repos.read",
          echoedLength: SECRET.length,
        });
        expect(approvedText).not.toContain(SECRET);
        // Non-vacuous: the fake connector really received the secret in-daemon.
        expect(connectorSecrets).toEqual([SECRET]);

        // 5. Revoke through MCP, then prove the agent is denied afterwards.
        const revoked = (await client.callTool({
          name: "revoke",
          arguments: { target: "e2e-agent" },
        })) as ToolResult;
        expect(revoked.isError).not.toBe(true);
        expect(textOf(revoked)).toContain("revoked");

        const afterRevoke = (await client.callTool({
          name: "request_capability",
          arguments: { alias: "github", scope: "repos.read", reason: "e2e after revoke" },
        })) as ToolResult;
        expect(afterRevoke.structuredContent?.["status"]).toBe("denied");
        expect(JSON.stringify(afterRevoke)).not.toContain(SECRET);
        expect(connectorSecrets).toEqual([SECRET]);

        // Audit chain covers the whole flow and carries no secret.
        const auditResponse = await fetch(`${base}/audit`);
        expect(auditResponse.status).toBe(200);
        const auditText = await auditResponse.text();
        expect(auditText).not.toContain(SECRET);
        const stages = (
          JSON.parse(auditText) as { events: { stage: string }[] }
        ).events.map((e) => e.stage);
        expect(stages).toContain("enrollment-created");
        expect(stages).toContain("enrollment-completed");
        expect(stages).toContain("executed");
      } finally {
        try {
          rmSync(dir, { recursive: true, force: true });
        } catch {
          // best effort: the daemon's sqlite handle may still be open on Windows
        }
      }
    },
    30_000,
  );
});
