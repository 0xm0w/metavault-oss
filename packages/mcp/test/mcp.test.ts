import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Effect, Layer } from "effect";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
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

// In-process stand-in for the vaultd HTTP wire: routes fetch calls to the
// exact handler the node:http server delegates to, so no socket is needed.
const daemonFetch: DaemonFetch = async (input, init) => {
  daemonCalls += 1;
  const raw =
    typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  const url = new URL(raw);
  const method = init?.method ?? "GET";
  const body: unknown =
    typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
  const out = await handleVaultRequest(service, method, url.pathname, body);
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
      yield* svc.seedCredential("stripe", "charges.read", SECRET);
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
  it("handshake reports MCP_VERSION and tools/list is exactly the five tools", async () => {
    expect(MCP_VERSION).toBe("0.1.1-alpha");
    expect(client.getServerVersion()?.version).toBe(MCP_VERSION);
    const listed = await client.listTools();
    expect(listed.tools.map((t) => t.name).sort()).toEqual([
      "enrollment_status",
      "list_aliases",
      "request_capability",
      "request_enrollment",
      "revoke",
    ]);
  });

  it("lists the five tools with object input schemas", async () => {
    const listed = await client.listTools();
    const names = listed.tools.map((t) => t.name).sort();
    expect(names).toEqual(["enrollment_status", "list_aliases", "request_capability", "request_enrollment", "revoke"]);
    for (const tool of listed.tools) {
      expect(tool.inputSchema.type).toBe("object");
    }
    const requestTool = listed.tools.find((t) => t.name === "request_capability");
    const required = (requestTool?.inputSchema as { required?: string[] }).required ?? [];
    expect(required).toEqual(expect.arrayContaining(["alias", "scope", "reason"]));
  });

  it("list_aliases contains stripe and never the secret", async () => {
    const result = (await client.callTool({
      name: "list_aliases",
      arguments: {},
    })) as ToolResult;
    expect(result.isError).not.toBe(true);
    const text = textOf(result);
    expect(text).toContain("stripe");
    expect(text).not.toContain(SECRET);
    expect(text).not.toContain("sk-");
    expect(JSON.stringify(result)).not.toContain(SECRET);
  });

  it("request_capability returns the daemon result verbatim, incl. grantId", async () => {
    const result = (await client.callTool({
      name: "request_capability",
      arguments: { alias: "stripe", scope: "charges.read", reason: "list charges" },
    })) as ToolResult;
    expect(result.isError).not.toBe(true);
    const text = textOf(result);
    expect(text).toContain("awaiting-approval");
    expect(text).not.toContain(SECRET);
    expect(text).not.toContain("sk-");
    expect(result.structuredContent?.["status"]).toBe("awaiting-approval");
    expect(typeof result.structuredContent?.["grantId"]).toBe("string");
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
    expect(JSON.stringify(after)).not.toContain(SECRET);
  });

  it("reports a daemon outage as an MCP error without secrets", async () => {
    const downServer = createMetavaultMcpServer({
      daemonUrl: "http://127.0.0.1:7077",
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
