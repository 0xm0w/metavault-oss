import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Effect, Layer } from "effect";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

const DAEMON_TOKEN = "synthetic-daemon-token-for-tests";
interface ToolResult { readonly isError?: boolean; readonly structuredContent?: Record<string, unknown>; }
let service: VaultServiceService;
const clients: Client[] = [];
const dir = mkdtempSync(join(tmpdir(), "mv-reg-"));

const daemon = (method: string, path: string, body?: unknown, extra: Record<string, string> = {}): ReturnType<typeof handleVaultRequest> =>
  handleVaultRequest(service, method, path, body, { daemonToken: DAEMON_TOKEN, providedToken: DAEMON_TOKEN, ...(extra["agent"] !== undefined ? { providedAgentToken: extra["agent"] } : {}) } as never);

async function connect(agentId: string, credentialPath: string): Promise<Client> {
  const fetchFn: DaemonFetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    const headers = new Headers(init?.headers);
    const presented = headers.get("x-metavault-agent-token") ?? undefined;
    const body: unknown = typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
    const out = await handleVaultRequest(service, init?.method ?? "GET", url.pathname, body, {
      ...(presented !== undefined ? { providedAgentToken: presented } : {}),
    });
    return new Response(JSON.stringify(out.body), { status: out.status, headers: { "content-type": "application/json" } });
  };
  const server = createMetavaultMcpServer({ daemonUrl: "http://127.0.0.1:7077", agentId, ide: "OpenCode", fetchFn, approvalWaitMs: 0, credentialPath });
  const client = new Client({ name: `test-${agentId}`, version: "0.0.1" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(b);
  await client.connect(a);
  clients.push(client);
  return client;
}
const call = async (c: Client, name: string): Promise<ToolResult> => (await c.callTool({ name, arguments: {} })) as ToolResult;

beforeAll(async () => {
  service = await Effect.runPromise(
    Effect.gen(function* () { const svc = yield* VaultService; yield* svc.seedCredential("stripe", "charges.read", SECRET); return svc; }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 9) })),
      Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 9)), BrainAsk, FakeConnector)),
    ),
  );
});
afterAll(async () => { for (const c of clients) await c.close(); });

describe("verified agent registration through the MCP process", () => {
  it("register, user approves with the code, credential is stored privately and never shown to the model", async () => {
    const path = join(dir, "agent-a.token");
    const c = await connect("synthetic-ide-a", path);
    const started = await call(c, "register_agent");
    const code = String(started.structuredContent?.["code"]);
    expect(code).toMatch(/^[0-9]{6}$/);
    expect(await call(c, "registration_status")).toMatchObject({ structuredContent: { status: "pending" } });
    const pending = (await daemon("GET", "/agent-registrations")).body as { registrations: { id: string; code: string }[] };
    const reg = pending.registrations.find((r) => r.code === code);
    expect(reg).toBeDefined();
    const bad = await daemon("POST", `/agent-registrations/${reg?.id ?? ""}/approve`, { code: code === "000000" ? "000001" : "000000" });
    expect(bad.status).toBe(403);
    expect((await daemon("POST", `/agent-registrations/${reg?.id ?? ""}/approve`, { code })).status).toBe(200);
    const done = await call(c, "registration_status");
    expect(done.structuredContent?.["status"]).toBe("verified");
    const stored = readFileSync(path, "utf8").trim();
    expect(stored.startsWith("ov_agent_")).toBe(true);
    expect(JSON.stringify([started, done])).not.toContain(stored);
    if (process.platform !== "win32") expect(statSync(path).mode & 0o077).toBe(0);
    // A new MCP process for the same agent picks the credential up from the file.
    const again = await connect("synthetic-ide-a", path);
    expect((await call(again, "register_agent")).structuredContent?.["status"]).toBe("verified");
    const agents = (await daemon("GET", "/agents")).body as readonly { id: string; revoked?: boolean }[];
    expect(agents.some((a) => a.id === "synthetic-ide-a" && a.revoked !== true)).toBe(true);
  });

  it("the open claim route cannot be used without the claim secret and approval", async () => {
    const c = await connect("synthetic-ide-b", join(dir, "agent-b.token"));
    const code = String((await call(c, "register_agent")).structuredContent?.["code"]);
    const pending = (await daemon("GET", "/agent-registrations")).body as { registrations: { id: string; code: string }[] };
    const reg = pending.registrations.find((r) => r.code === code);
    const stolen = await handleVaultRequest(service, "POST", `/agent-registrations/${reg?.id ?? ""}/claim`, { claim: "x".repeat(32) }, {});
    expect(stolen.status).not.toBe(200);
    expect(JSON.stringify(stolen.body)).not.toContain("ov_agent_");
    expect((await handleVaultRequest(service, "GET", "/agent-registrations", undefined, {})).status).toBe(401);
    expect((await handleVaultRequest(service, "POST", `/agent-registrations/${reg?.id ?? ""}/approve`, { code }, {})).status).toBe(401);
    await daemon("POST", `/agent-registrations/${reg?.id ?? ""}/deny`, {});
    expect(await call(c, "registration_status")).toMatchObject({ structuredContent: { status: "denied" } });
  });

  it("revoking a verified agent stops its later requests", async () => {
    const path = join(dir, "agent-c.token");
    const c = await connect("synthetic-ide-c", path);
    const code = String((await call(c, "register_agent")).structuredContent?.["code"]);
    const pending = (await daemon("GET", "/agent-registrations")).body as { registrations: { id: string; code: string }[] };
    await daemon("POST", `/agent-registrations/${pending.registrations.find((r) => r.code === code)?.id ?? ""}/approve`, { code });
    await call(c, "registration_status");
    await Effect.runPromise(service.revokeAgentToken("synthetic-ide-c"));
    const res = (await c.callTool({ name: "request_capability", arguments: { alias: "stripe", scope: "charges.read", reason: "after revoke" } })) as ToolResult;
    expect(res.isError === true || res.structuredContent?.["status"] === "denied").toBe(true);
    expect(res.structuredContent?.["status"]).not.toBe("awaiting-approval");
  });

  it("a locked vault cannot decide registrations, even with the daemon token", async () => {
    const c = await connect("synthetic-ide-d", join(dir, "agent-d.token"));
    const code = String((await call(c, "register_agent")).structuredContent?.["code"]);
    const pending = (await daemon("GET", "/agent-registrations")).body as { registrations: { id: string; code: string }[] };
    const id = pending.registrations.find((r) => r.code === code)?.id ?? "";
    const lockedService = { ...service, keyStatus: () => Effect.succeed({ mode: "passphrase", fingerprint: null, locked: true, autoLockMs: null, kdf: null, lockedUntilRetryMs: null }) } as unknown as VaultServiceService;
    const opts = { daemonToken: DAEMON_TOKEN, providedToken: DAEMON_TOKEN } as never;
    expect((await handleVaultRequest(lockedService, "POST", `/agent-registrations/${id}/approve`, { code }, opts)).status).toBe(423);
    expect((await handleVaultRequest(lockedService, "POST", `/agent-registrations/${id}/deny`, {}, opts)).status).toBe(423);
    expect(await call(c, "registration_status")).toMatchObject({ structuredContent: { status: "pending" } });
  });

  it("wrong claims never revoke an existing agent's credential", async () => {
    const path = join(dir, "agent-e.token");
    const e = await connect("synthetic-ide-e", path);
    const code = String((await call(e, "register_agent")).structuredContent?.["code"]);
    const pending = (await daemon("GET", "/agent-registrations")).body as { registrations: { id: string; code: string }[] };
    const id = pending.registrations.find((r) => r.code === code)?.id ?? "";
    await daemon("POST", `/agent-registrations/${id}/approve`, { code });
    await call(e, "registration_status");
    // A second program tries to register the same, now verified, agent id.
    const other = await connect("synthetic-ide-e", join(dir, "agent-e2.token"));
    expect((await call(other, "register_agent")).isError).toBe(true);
    for (let i = 0; i < 8; i += 1) {
      await handleVaultRequest(service, "POST", `/agent-registrations/${id}/claim`, { claim: "z".repeat(40) }, {});
    }
    const agents = (await daemon("GET", "/agents")).body as readonly { id: string; revoked?: boolean }[];
    expect(agents.find((a) => a.id === "synthetic-ide-e")?.revoked).not.toBe(true);
  });
});
