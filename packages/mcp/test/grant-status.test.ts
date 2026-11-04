import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Effect, Layer } from "effect";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { handleVaultRequest } from "../../daemon/src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../../daemon/src/service.js";
import { createMetavaultMcpServer, type DaemonFetch } from "../src/server.js";

// Synthetic fixtures only: a fake canary secret and fake agent ids. Covers
// the user's report that denying a request in the app left the agent with
// no way to learn the decision.
const SECRET = "sk-test-canary-grant-status-0001";
const BrainAsk = Layer.succeed(Brain, {
  assess: () => Effect.succeed({ risk: "low" as const, recommendedScope: "charges.read", requireApproval: true, explanation: "ok" }),
});
const FakeConnector = Layer.succeed(Connector, {
  execute: (_a, _s, secret) => Effect.succeed({ echoedLength: secret.length }),
});

interface ToolResult {
  readonly isError?: boolean;
  readonly structuredContent?: Record<string, unknown>;
  readonly content?: readonly { readonly type: string; readonly text?: string }[];
}

let service: VaultServiceService;
const clients: Client[] = [];

async function connect(agentId: string, agentToken?: string, waitMs = 0): Promise<Client> {
  const fetchFn: DaemonFetch = async (input, init) => {
    const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(raw);
    const headers = new Headers(init?.headers);
    const presented = headers.get("x-metavault-agent-token") ?? undefined;
    const body: unknown = typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
    const receipt = headers.get("x-metavault-grant-receipt") ?? undefined;
    const out = await handleVaultRequest(service, init?.method ?? "GET", url.pathname, body, {
      ...(presented !== undefined ? { providedAgentToken: presented } : {}),
      ...(receipt !== undefined ? { providedGrantReceipt: receipt } : {}),
    });
    return new Response(JSON.stringify(out.body), { status: out.status, headers: { "content-type": "application/json" } });
  };
  const server = createMetavaultMcpServer({
    daemonUrl: "http://127.0.0.1:7077",
    agentId,
    ide: "OpenCode",
    fetchFn,
    approvalWaitMs: waitMs,
    approvalPollMs: 10,
    ...(agentToken !== undefined ? { agentToken } : {}),
  });
  const client = new Client({ name: `test-${agentId}`, version: "0.0.1" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(b);
  await client.connect(a);
  clients.push(client);
  return client;
}

async function request(client: Client): Promise<string> {
  const res = (await client.callTool({ name: "request_capability", arguments: { alias: "stripe", scope: "charges.read", reason: "list charges" } })) as ToolResult;
  expect(res.structuredContent?.["status"]).toBe("awaiting-approval");
  return String(res.structuredContent?.["grantId"]);
}

async function status(client: Client, grantId: string): Promise<ToolResult> {
  return (await client.callTool({ name: "grant_status", arguments: { grantId } })) as ToolResult;
}

beforeAll(async () => {
  service = await Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* VaultService;
      yield* svc.seedCredential("stripe", "charges.read", SECRET);
      return svc;
    }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 9) })),
      Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 9)), BrainAsk, FakeConnector)),
    ),
  );
});
afterAll(async () => { for (const c of clients) await c.close(); });

describe("grant_status: the agent learns the user's decision", () => {
  it("pending, then denied after the human denies, as a final structured result", async () => {
    const opencode = await connect("opencode-synthetic");
    const grantId = await request(opencode);
    const pending = await status(opencode, grantId);
    expect(pending.structuredContent).toMatchObject({ grantId, status: "pending", terminal: false });

    await Effect.runPromise(service.deny(grantId));
    const denied = await status(opencode, grantId);
    expect(denied.isError).not.toBe(true);
    expect(denied.structuredContent).toMatchObject({ grantId, status: "denied", terminal: true });
    expect(String(denied.structuredContent?.["message"])).toContain("denied");
    expect(JSON.stringify(denied)).not.toContain(SECRET);
    // Polling never executes anything: a denied grant cannot be approved afterwards.
    await expect(Effect.runPromise(service.approve(grantId))).rejects.toBeDefined();
    expect((await status(opencode, grantId)).structuredContent?.["status"]).toBe("denied");
  });

  it("delivers the approved result to the requesting session once, never the secret", async () => {
    const c = await connect("opencode-approve");
    const grantId = await request(c);
    await Effect.runPromise(service.approve(grantId));
    const res = await status(c, grantId);
    expect(res.structuredContent).toMatchObject({ status: "executed", terminal: true });
    expect(res.structuredContent?.["result"]).toBeDefined();
    expect(JSON.stringify(res)).not.toContain(SECRET);
    // Asking again in the same session returns the same cached outcome.
    expect((await status(c, grantId)).structuredContent?.["result"]).toEqual(res.structuredContent?.["result"]);
  });

  it("another session cannot collect the result, and a revoke before pickup discards it", async () => {
    const owner = await connect("opencode-owner");
    const other = await connect("opencode-other");
    const grantId = await request(owner);
    await Effect.runPromise(service.approve(grantId));
    expect((await status(other, grantId)).structuredContent?.["status"]).toBe("unknown");
    await Effect.runPromise(service.revoke("opencode-owner"));
    const res = await status(owner, grantId);
    expect(res.structuredContent?.["result"]).toBeUndefined();
    expect(String(res.structuredContent?.["message"])).toContain("not available");
  });

  it("reports revoked when the grant is revoked while pending", async () => {
    const c = await connect("opencode-revoked");
    const grantId = await request(c);
    await Effect.runPromise(service.revoke("opencode-revoked"));
    expect((await status(c, grantId)).structuredContent).toMatchObject({ status: "revoked", terminal: true });
  });

  it("the receipt never reaches the model, and a grant id alone reads nothing", async () => {
    const c = await connect("opencode-receipt");
    const res = (await c.callTool({ name: "request_capability", arguments: { alias: "stripe", scope: "charges.read", reason: "r" } })) as ToolResult;
    expect(JSON.stringify(res)).not.toContain("receipt");
    const grantId = String(res.structuredContent?.["grantId"]);
    // Another process (no receipt) cannot read it through the tool...
    const other = await connect("opencode-receipt");
    const viaTool = await status(other, grantId);
    expect(viaTool.isError).toBe(true);
    expect(viaTool.structuredContent?.["status"]).toBe("unknown");
    // ...nor straight from the daemon with the id, or a wrong receipt.
    const direct = await handleVaultRequest(service, "GET", `/grants/${grantId}`, undefined, {});
    expect(direct.status).toBe(404);
    const wrong = await handleVaultRequest(service, "GET", `/grants/${grantId}`, undefined, { providedGrantReceipt: "x".repeat(48) });
    expect(wrong.status).toBe(404);
    expect(JSON.stringify(direct.body) + JSON.stringify(wrong.body)).not.toContain("pending");
  });

  it("request_capability itself returns the decision when the user answers during the bounded wait", async () => {
    const c = await connect("opencode-wait", undefined, 3000);
    const pendingRequest = c.callTool({ name: "request_capability", arguments: { alias: "stripe", scope: "charges.read", reason: "r" } }) as Promise<ToolResult>;
    await new Promise((resolve) => { setTimeout(resolve, 150); });
    const pendingList = await Effect.runPromise(service.listPendingApprovals());
    const mine = pendingList.find((p) => p.agentId === "opencode-wait");
    expect(mine).toBeDefined();
    await Effect.runPromise(service.deny(mine?.grantId ?? ""));
    const res = await pendingRequest;
    expect(res.structuredContent).toMatchObject({ status: "denied", final: true, terminal: true });
    expect(JSON.stringify(res)).not.toContain(SECRET);
  });

  it("a wait that runs out is pending/timedOut, not a denial; the user can still decide later", async () => {
    const c = await connect("opencode-timeout", undefined, 60);
    const res = (await c.callTool({ name: "request_capability", arguments: { alias: "stripe", scope: "charges.read", reason: "r" } })) as ToolResult;
    expect(res.structuredContent).toMatchObject({ status: "awaiting-approval", timedOut: true });
    expect(String(res.structuredContent?.["instruction"])).toContain("grant_status");
    const grantId = String(res.structuredContent?.["grantId"]);
    const still = await status(c, grantId);
    expect(still.structuredContent).toMatchObject({ status: "pending", final: false, timedOut: true });
    await Effect.runPromise(service.deny(grantId));
    expect((await status(c, grantId)).structuredContent).toMatchObject({ status: "denied", final: true });
  });

  it("a daemon outage while waiting is 'unavailable', not a decision", async () => {
    const server = createMetavaultMcpServer({
      daemonUrl: "http://127.0.0.1:7077",
      agentId: "opencode-down",
      approvalWaitMs: 0,
      fetchFn: async (input, init) => {
        const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
        if (raw.includes("/grants/")) throw new Error("connect ECONNREFUSED");
        const out = await handleVaultRequest(service, init?.method ?? "GET", new URL(raw).pathname, typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined, {});
        return new Response(JSON.stringify(out.body), { status: out.status, headers: { "content-type": "application/json" } });
      },
    });
    const client = new Client({ name: "down", version: "0.0.1" });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await server.connect(b);
    await client.connect(a);
    clients.push(client);
    const res = (await client.callTool({ name: "request_capability", arguments: { alias: "stripe", scope: "charges.read", reason: "r" } })) as ToolResult;
    expect(res.structuredContent?.["status"]).toBe("unavailable");
    expect(res.structuredContent?.["final"]).toBe(false);
  });

  it("revoking a verified agent cancels its pending request and an approval afterwards runs nothing", async () => {
    const created = await Effect.runPromise(service.registerAgent("verified-synthetic", "Verified synthetic"));
    const owner = await connect("verified-synthetic", created.token);
    const grantId = await request(owner);
    await Effect.runPromise(service.revokeAgentToken("verified-synthetic"));
    expect((await status(owner, grantId)).structuredContent).toMatchObject({ status: "revoked", final: true });
    await expect(Effect.runPromise(service.approve(grantId))).rejects.toBeDefined();
    // The revoked token is refused for every later call.
    const later = (await owner.callTool({ name: "request_capability", arguments: { alias: "stripe", scope: "charges.read", reason: "r" } })) as ToolResult;
    expect(later.isError).toBe(true);
  });
});
