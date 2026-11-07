import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Effect, Layer } from "effect";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { createKeySession } from "../../core/src/key-session.js";
import { wrapMasterKey } from "../../core/src/keywrap.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { handleVaultRequest } from "../../daemon/src/server.js";
import {
  makeVaultServiceLive,
  VaultService,
  type VaultServiceService,
} from "../../daemon/src/service.js";
import { createMetavaultMcpServer, MCP_VERSION, type DaemonFetch } from "../src/server.js";

const SECRET = "sk-test-canary-mcp-0001";

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

let service: VaultServiceService;
let daemonCalls = 0;
let enrolledAgentToken = "";

const daemonFetch: DaemonFetch = async (input, init) => {
  daemonCalls += 1;
  const raw =
    typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  const url = new URL(raw);
  const method = init?.method ?? "GET";
  const body: unknown =
    typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
  const headers = new Headers(init?.headers);
  const receipt = headers.get("x-metavault-grant-receipt") ?? undefined;
  const agentHeader = headers.get("x-metavault-agent-token") ?? undefined;
  const waitParam = url.searchParams.get("waitMs");
  const grantWaitMs = waitParam !== null ? Number(waitParam) : undefined;
  const out = await handleVaultRequest(service, method, url.pathname, body, {
    ...(receipt !== undefined ? { providedGrantReceipt: receipt } : {}),
    ...(agentHeader !== undefined && agentHeader !== "" ? { providedAgentToken: agentHeader } : {}),
    ...(grantWaitMs !== undefined && Number.isFinite(grantWaitMs) ? { grantWaitMs } : {}),
  });
  return new Response(JSON.stringify(out.body), {
    status: out.status,
    headers: { "content-type": "application/json" },
  });
};

interface ToolResult {
  readonly isError?: boolean;
  readonly content?: readonly { readonly type: string; readonly text?: string }[];
  readonly structuredContent?: Record<string, unknown>;
}

function textOf(result: ToolResult): string {
  return (result.content ?? [])
    .map((c) => c.text ?? "")
    .join("\n");
}

let client: Client;

beforeAll(async () => {
  service = await Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* VaultService;
      yield* svc.seedCredential("stripe", "charges.read", SECRET, "https://api.stripe.com/v1");
      const agent = yield* svc.registerAgent("cursor", "Cursor");
      enrolledAgentToken = agent.token;
      return svc;
    }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 7) })),
      Effect.provide(
        Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), BrainLowRisk, FakeConnector),
      ),
    ),
  );

  const server = createMetavaultMcpServer({
    daemonUrl: "http://127.0.0.1:7077",
    agentId: "cursor",
    ide: "Cursor",
    fetchFn: daemonFetch,
    approvalWaitMs: 0,
    agentToken: enrolledAgentToken,
  });
  client = new Client({ name: "mcp-test-client", version: "0.0.1" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
});

afterAll(async () => {
  await client.close();
});

describe("MetaVault OSS MCP server (in-process client)", () => {
  it("handshake exposes instructions, resources, prompts, MCP_VERSION, and all twelve tools", async () => {
    expect(MCP_VERSION).toBe("0.1.4-alpha");
    expect(client.getServerVersion()?.version).toBe(MCP_VERSION);
    const instructions = client.getInstructions() ?? "";
    expect(instructions).toContain("list_aliases");
    expect(instructions).toContain("request_capability");
    expect(instructions).not.toContain(SECRET);

    const listed = await client.listTools();
    expect(listed.tools.map((t) => t.name).sort()).toEqual([
      "check_pulse",
      "enrollment_status",
      "grant_status",
      "handoff_context",
      "immunize_bug",
      "list_aliases",
      "register_agent",
      "registration_status",
      "request_capability",
      "request_enrollment",
      "revoke",
      "run_preflight",
    ]);

    const resources = await client.listResources();
    expect(resources.resources.map((r) => r.uri).sort()).toEqual([
      "jevault://nervous-system/handoff",
      "jevault://nervous-system/pulse",
      "jevault://project/contracts",
      "metavault://context/guide",
      "metavault://context/status",
    ]);
    const guide = await client.readResource({ uri: "metavault://context/guide" });
    expect(JSON.stringify(guide)).toContain("rest.call");
    expect(JSON.stringify(guide)).not.toContain(SECRET);

    const statusRes = await client.readResource({ uri: "metavault://context/status" });
    expect(JSON.stringify(statusRes)).toContain("stripe");
    expect(JSON.stringify(statusRes)).not.toContain(SECRET);

    const prompts = await client.listPrompts();
    expect(prompts.prompts.map((p) => p.name).sort()).toEqual(["enroll-secret", "use-secret"]);
  });

  it("lists the twelve tools with object input schemas", async () => {
    const listed = await client.listTools();
    const names = listed.tools.map((t) => t.name).sort();
    expect(names).toEqual([
      "check_pulse",
      "enrollment_status",
      "grant_status",
      "handoff_context",
      "immunize_bug",
      "list_aliases",
      "register_agent",
      "registration_status",
      "request_capability",
      "request_enrollment",
      "revoke",
      "run_preflight",
    ]);
    for (const tool of listed.tools) {
      expect(tool.inputSchema.type).toBe("object");
    }
    const requestTool = listed.tools.find((t) => t.name === "request_capability");
    const required = (requestTool?.inputSchema as { required?: string[] }).required ?? [];
    expect(required).toEqual(expect.arrayContaining(["alias", "scope", "reason"]));
  });

  it("list_aliases contains enriched metadata for stripe and never the secret", async () => {
    const result = (await client.callTool({
      name: "list_aliases",
      arguments: {},
    })) as ToolResult;
    expect(result.isError).not.toBe(true);
    const text = textOf(result);
    expect(text).toContain("stripe");
    expect(text).toContain("supportedTools");
    expect(text).not.toContain(SECRET);
    expect(text).not.toContain("sk-");
    expect(JSON.stringify(result)).not.toContain(SECRET);
  });

  it("request_capability returns grantId + metavault://approve deeplink on timeout, and allowedCeiling on scope-above-ceiling", async () => {
    const result = (await client.callTool({
      name: "request_capability",
      arguments: { alias: "stripe", scope: "charges.read", reason: "list charges" },
    })) as ToolResult;
    expect(result.isError).not.toBe(true);
    const text = textOf(result);
    expect(text).toContain("awaiting-approval");
    expect(text).not.toContain(SECRET);
    expect(result.structuredContent?.["status"]).toBe("awaiting-approval");
    const grantId = result.structuredContent?.["grantId"];
    expect(typeof grantId).toBe("string");
    expect(result.structuredContent?.["deeplink"]).toBe(`metavault://approve?grantId=${encodeURIComponent(String(grantId))}`);
    expect(String(result.structuredContent?.["instruction"])).toContain("grant_status");

    const aboveCeiling = (await client.callTool({
      name: "request_capability",
      arguments: { alias: "stripe", scope: "charges.write", reason: "create charge" },
    })) as ToolResult;
    expect(aboveCeiling.isError).not.toBe(true);
    expect(aboveCeiling.structuredContent?.["status"]).toBe("denied");
    expect(aboveCeiling.structuredContent?.["allowedCeiling"]).toBe("charges.read");
    expect(JSON.stringify(aboveCeiling)).not.toContain(SECRET);
  });

  it("register_agent works with omitted agentId (auto-filled from MCP server config)", async () => {
    const unauthServer = createMetavaultMcpServer({
      daemonUrl: "http://127.0.0.1:7077",
      agentId: "antigravity",
      ide: "Antigravity",
      fetchFn: daemonFetch,
      approvalWaitMs: 0,
      agentToken: "",
    });
    const unauthClient = new Client({ name: "ag-client", version: "0.0.1" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await unauthServer.connect(st);
    await unauthClient.connect(ct);
    try {
      const reg = (await unauthClient.callTool({
        name: "register_agent",
        arguments: {},
      })) as ToolResult;
      expect(reg.isError).not.toBe(true);
      expect(reg.structuredContent?.["agentId"]).toBe("antigravity");
      expect(String(reg.structuredContent?.["deeplink"])).toMatch(/^metavault:\/\/register\?registrationId=/);
    } finally {
      await unauthClient.close();
    }
  });

  it("returns structured vault-locked status with metavault://unlock deeplink when daemon is locked", async () => {
    const key = Buffer.alloc(32, 9);
    const passphrase = "correct-horse-battery-staple";
    const wrapped = await wrapMasterKey(key, passphrase);
    const session = createKeySession({ mode: "passphrase", wrapped });
    await session.unlock(passphrase);
    const lockedSvc = await Effect.runPromise(
      Effect.gen(function* () {
        const svc = yield* VaultService;
        yield* svc.seedCredential("stripe", "charges.read", SECRET);
        return svc;
      }).pipe(
        Effect.provide(makeVaultServiceLive({ keySession: session })),
        Effect.provide(Layer.mergeAll(VaultStoreTest(key), BrainLowRisk, FakeConnector)),
      ),
    );
    session.lock();
    const lockedFetch: DaemonFetch = async (input, init) => {
      const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const u = new URL(raw);
      const body: unknown = typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
      const out = await handleVaultRequest(lockedSvc, init?.method ?? "GET", u.pathname, body);
      return new Response(JSON.stringify(out.body), {
        status: out.status,
        headers: { "content-type": "application/json" },
      });
    };
    const lockedServer = createMetavaultMcpServer({
      daemonUrl: "http://127.0.0.1:7077",
      agentId: "cursor",
      ide: "Cursor",
      fetchFn: lockedFetch,
      approvalWaitMs: 0,
      agentToken: "",
    });
    const lockedClient = new Client({ name: "locked-client", version: "0.0.1" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await lockedServer.connect(st);
    await lockedClient.connect(ct);
    try {
      const res = (await lockedClient.callTool({
        name: "request_capability",
        arguments: { alias: "stripe", scope: "charges.read", reason: "test while locked" },
      })) as ToolResult;
      expect(res.isError).not.toBe(true);
      expect(res.structuredContent?.["status"]).toBe("vault-locked");
      expect(res.structuredContent?.["deeplink"]).toBe("metavault://unlock?target=daemon");
    } finally {
      await lockedClient.close();
    }
  });

  it("invalid inputs return MCP errors and never reach the daemon", async () => {
    const before = daemonCalls;
    const badAlias = (await client.callTool({
      name: "request_capability",
      arguments: { alias: 42, scope: "charges.read", reason: "x" },
    })) as ToolResult;
    expect(badAlias.isError).toBe(true);

    const missing = (await client.callTool({
      name: "request_capability",
      arguments: { alias: "stripe" },
    })) as ToolResult;
    expect(missing.isError).toBe(true);

    const badRevoke = (await client.callTool({
      name: "revoke",
      arguments: {},
    })) as ToolResult;
    expect(badRevoke.isError).toBe(true);

    const unknown = (await client.callTool({
      name: "no_such_tool",
      arguments: {},
    })) as ToolResult;
    expect(unknown.isError).toBe(true);

    expect(daemonCalls).toBe(before);
    expect(textOf(badAlias)).not.toContain(SECRET);
  });

  it("revoke round-trips through the daemon and blocks later requests", async () => {
    const revoked = (await client.callTool({
      name: "revoke",
      arguments: { target: "cursor" },
    })) as ToolResult;
    expect(revoked.isError).not.toBe(true);
    expect(textOf(revoked)).toContain("revoked");

    const after = (await client.callTool({
      name: "request_capability",
      arguments: { alias: "stripe", scope: "charges.read", reason: "list charges" },
    })) as ToolResult;
    expect(after.isError).not.toBe(true);
    expect(after.structuredContent?.["status"]).toBe("denied");
    expect(after.structuredContent?.["final"]).toBe(true);
    expect(JSON.stringify(after)).not.toContain(SECRET);
  });

  it("reports a daemon outage as an MCP error without secrets", async () => {
    const downServer = createMetavaultMcpServer({
      daemonUrl: "http://127.0.0.1:7077",
      agentToken: "",
      fetchFn: () => Promise.reject(new Error("connect ECONNREFUSED")),
    });
    const downClient = new Client({ name: "mcp-down-client", version: "0.0.1" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await downServer.connect(st);
    await downClient.connect(ct);
    try {
      const result = (await downClient.callTool({
        name: "list_aliases",
        arguments: {},
      })) as ToolResult;
      expect(result.isError).toBe(true);
      expect(textOf(result)).not.toContain(SECRET);
    } finally {
      await downClient.close();
    }
  });
});
