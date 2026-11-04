import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Effect, Layer } from "effect";
import { afterAll, describe, expect, it } from "vitest";
import { Brain, buildMarshalPrompt } from "../../packages/brain/src/brain.js";
import { Connector } from "../../packages/core/src/connector.js";
import { VaultStore, VaultStoreTest } from "../../packages/core/src/storage.js";
import { buildEnrollmentDeeplink, handleVaultRequest } from "../../packages/daemon/src/server.js";
import {
  makeVaultServiceLive,
  VaultService,
  type VaultServiceService,
} from "../../packages/daemon/src/service.js";
import {
  projectAliasesResponse,
  projectAuditResponse,
  projectCredentialsResponse,
  projectPendingResponse,
  projectPoliciesResponse,
  projectWardenKeyStatus,
  projectWardenSettings,
  projectWardenTestResult,
} from "../../packages/app/src/renderer/model.js";
import { parseVaultDeeplink } from "../../packages/app/src/deeplink.js";
import { validateDaemonCall } from "../../packages/app/src/daemon-client.js";
import { createMetavaultMcpServer, type DaemonFetch } from "../../packages/mcp/src/server.js";

// Extended canary sweep (Task 7): one unique fake secret is stored as a
// credential AND as the warden Meta API key. Every surface named in the
// plan — audit JSON, MCP results, deeplink URLs, settings responses
// (including warden key status), and renderer IPC payloads — is grepped
// for the full canary string. The connector's in-daemon view is asserted
// separately to prove the secret really flowed (non-vacuous scan).
const CANARY = "METAVAULT-CANARY-9f27c41a-this-string-must-never-leak";
const MASTER_KEY = Buffer.alloc(32, 7);
const TOKEN = "canary-sweep-daemon-token";
const withToken = { daemonToken: TOKEN, providedToken: TOKEN };

function assertNoCanary(label: string, value: unknown): void {
  const serialized: unknown = JSON.stringify(value);
  const text = typeof serialized === "string" ? serialized : "";
  if (text.includes(CANARY)) {
    throw new Error(`canary leaked into ${label}`);
  }
}

interface ToolResult {
  readonly isError?: boolean;
  readonly content?: readonly { readonly type: string; readonly text?: string }[];
  readonly structuredContent?: Record<string, unknown>;
}

let client: Client | undefined;
afterAll(async () => {
  await client?.close();
});

describe("canary sweep: audit, MCP, deeplink, settings, renderer IPC", () => {
  it("scan helper actually detects a planted canary (non-vacuous grep)", () => {
    expect(() => {
      assertNoCanary("planted", { note: `prefix ${CANARY} suffix` });
    }).toThrow(/canary leaked into planted/);
    expect(() => {
      assertNoCanary("clean", { note: "nothing here" });
    }).not.toThrow();
  });

  it("deeplink builder carries only alias/scope/website/enrollment — never a secret field", () => {
    const link = buildEnrollmentDeeplink({
      enrollmentId: "enr-1",
      alias: "github",
      scope: "repos.read",
      website: "github.com",
    });
    assertNoCanary("built deeplink", link);
    const url = new URL(link);
    expect([...url.searchParams.keys()].sort()).toEqual(["alias", "enrollment", "scope", "website"]);
    const parsed = parseVaultDeeplink(link);
    expect(parsed).toEqual({ alias: "github", scope: "repos.read", website: "github.com", enrollmentId: "enr-1" });
    assertNoCanary("parsed deeplink params", parsed);
  });

  it("canary is absent from audit JSON, MCP results, deeplinks, settings, and renderer IPC payloads", async () => {
    const prompts: string[] = [];
    const connectorSecrets: string[] = [];
    const capturingBrain = Layer.succeed(Brain, {
      assess: (req, historySummary, policyDigest) => {
        prompts.push(buildMarshalPrompt(req, historySummary, policyDigest));
        return Effect.succeed({
          risk: "low" as const,
          recommendedScope: "repos.read",
          requireApproval: true,
          explanation: "canary sweep marshal",
        });
      },
    });
    const mockConnector = Layer.succeed(Connector, {
      execute: (_alias, _scope, secret) => {
        connectorSecrets.push(secret);
        return Effect.succeed({ echoedLength: secret.length });
      },
    });
    const built = await Effect.runPromise(
      Effect.gen(function* () {
        const service = yield* VaultService;
        const store = yield* VaultStore;
        yield* service.seedCredential("stripe", "charges.read", CANARY);
        return { service, store };
      }).pipe(
        Effect.provide(makeVaultServiceLive({ masterKey: MASTER_KEY })),
        Effect.provide(Layer.mergeAll(VaultStoreTest(MASTER_KEY), capturingBrain, mockConnector)),
      ),
    );
    const svc: VaultServiceService = built.service;

    // The canary is also the warden key: status may show only {configured,last4}.
    const putKey = await handleVaultRequest(svc, "PUT", "/settings/warden/key", { key: CANARY }, withToken);
    expect(putKey.status).toBe(200);
    expect(putKey.body).toEqual({ configured: true, last4: CANARY.slice(-4) });
    const keyStatus = await handleVaultRequest(svc, "GET", "/settings/warden/key", undefined, withToken);
    expect(Object.keys(keyStatus.body as object).sort()).toEqual(["configured", "last4"]);
    const settingsGet = await handleVaultRequest(svc, "GET", "/settings/warden", undefined, withToken);
    const settingsPatch = await handleVaultRequest(
      svc,
      "PATCH",
      "/settings/warden",
      { provider: "ollama", model: "muse-glimmer:30b", effort: "standard" },
      withToken,
    );
    const wardenTest = await handleVaultRequest(svc, "POST", "/settings/warden/test", undefined, withToken);

    // MCP surface wired to the same daemon handler.
    const daemonFetch: DaemonFetch = async (input, init) => {
      const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const url = new URL(raw);
      const body: unknown = typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
      const out = await handleVaultRequest(svc, init?.method ?? "GET", url.pathname, body, {
        ...(new Headers(init?.headers).get("x-metavault-grant-receipt") !== null ? { providedGrantReceipt: new Headers(init?.headers).get("x-metavault-grant-receipt") ?? "" } : {}),
      });
      return new Response(JSON.stringify(out.body), {
        status: out.status,
        headers: { "content-type": "application/json" },
      });
    };
    const server = createMetavaultMcpServer({
      daemonUrl: "http://127.0.0.1:7077",
      agentId: "cursor",
      ide: "Cursor",
      fetchFn: daemonFetch,
      approvalWaitMs: 0,
      launchDeeplink: () => Promise.resolve(false),
    });
    client = new Client({ name: "canary-sweep-client", version: "0.0.1" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    // Enroll a new alias through MCP: the deeplink is an agent-visible surface.
    const enroll = (await client.callTool({
      name: "request_enrollment",
      arguments: { alias: "github", scope: "repos.read", website: "github.com", reason: "canary sweep" },
    })) as ToolResult;
    expect(enroll.isError).not.toBe(true);
    const deeplink = enroll.structuredContent?.["deeplink"];
    expect(typeof deeplink).toBe("string");
    const enrollmentId = enroll.structuredContent?.["enrollmentId"];
    expect(typeof enrollmentId).toBe("string");
    const parsedDeeplink = parseVaultDeeplink(deeplink);

    // Human seeds the enrolled credential (token-guarded), completing enrollment.
    const seeded = await handleVaultRequest(
      svc,
      "POST",
      "/credentials",
      { alias: "github", scope: "repos.read", secret: CANARY, website: "github.com", enrollmentId },
      withToken,
    );
    expect(seeded.status).toBe(201);
    const enrollmentStatus = (await client.callTool({
      name: "enrollment_status",
      arguments: { enrollmentId },
    })) as ToolResult;
    expect(enrollmentStatus.structuredContent?.["status"]).toBe("completed");

    // Request -> human approve -> execute through MCP + daemon handler.
    const mcpRequest = (await client.callTool({
      name: "request_capability",
      arguments: { alias: "github", scope: "repos.read", reason: "canary sweep" },
    })) as ToolResult;
    expect(mcpRequest.structuredContent?.["status"]).toBe("awaiting-approval");
    const grantId = mcpRequest.structuredContent?.["grantId"];
    expect(typeof grantId).toBe("string");
    const pendingBody = (await handleVaultRequest(svc, "GET", "/pending", undefined, withToken)).body;
    const approved = await Effect.runPromise(svc.approve(grantId as string));
    expect(approved.status).toBe("executed");
    const mcpAliases = (await client.callTool({ name: "list_aliases", arguments: {} })) as ToolResult;
    const mcpRevoke = (await client.callTool({ name: "revoke", arguments: { target: "cursor" } })) as ToolResult;

    // Raw daemon payloads the renderer would fetch over IPC.
    const auditBody = (await handleVaultRequest(svc, "GET", "/audit")).body;
    const aliasesBody = (await handleVaultRequest(svc, "GET", "/aliases")).body;
    const policiesBody = (await handleVaultRequest(svc, "GET", "/policies")).body;
    const audit = await Effect.runPromise(svc.listAudit());
    const auditJson = JSON.stringify(auditBody);
    expect(audit.map((e) => e.stage)).toContain("executed");
    expect(prompts.length).toBeGreaterThan(0);

    // Renderer IPC payloads: validated call shapes + whitelist projections.
    const ipcCalls = [
      validateDaemonCall({ method: "GET", path: "/audit" }),
      validateDaemonCall({ method: "GET", path: "/aliases" }),
      validateDaemonCall({ method: "GET", path: "/pending" }),
      validateDaemonCall({ method: "GET", path: "/policies" }),
      validateDaemonCall({ method: "GET", path: "/settings/warden" }),
      validateDaemonCall({ method: "GET", path: "/settings/warden/key" }),
    ];
    const record = await Effect.runPromise(built.store.getCredential("github"));

    // Proof the secret really flowed inside the daemon only.
    expect(connectorSecrets).toEqual([CANARY]);
    expect(record?.ciphertext).toBeDefined();

    const surfaces: Record<string, unknown> = {
      "audit JSON (GET /audit body)": auditBody,
      "audit JSON string": auditJson,
      "audit rows": audit,
      "MCP request_enrollment result": enroll,
      "MCP enrollment_status result": enrollmentStatus,
      "MCP request_capability result": mcpRequest,
      "MCP list_aliases result": mcpAliases,
      "MCP revoke result": mcpRevoke,
      "deeplink URL": deeplink,
      "parsed deeplink params (IPC to renderer)": parsedDeeplink,
      "settings GET /settings/warden": settingsGet.body,
      "settings PATCH /settings/warden": settingsPatch.body,
      "settings PUT warden key response": putKey.body,
      "settings warden key status": keyStatus.body,
      "settings warden test result": wardenTest.body,
      "renderer-projected audit": projectAuditResponse(auditBody),
      "renderer-projected aliases": projectAliasesResponse(aliasesBody),
      "renderer-projected credentials": projectCredentialsResponse(aliasesBody),
      "renderer-projected pending": projectPendingResponse(pendingBody),
      "renderer-projected policies": projectPoliciesResponse(policiesBody),
      "renderer-projected warden settings": projectWardenSettings(settingsGet.body),
      "renderer-projected warden key status": projectWardenKeyStatus(keyStatus.body),
      "renderer-projected warden test": projectWardenTestResult(wardenTest.body),
      "renderer IPC call payloads": ipcCalls,
      "approve result": approved,
      "stored ciphertext": record?.ciphertext,
      "captured marshal prompts": prompts,
    };
    for (const [label, surface] of Object.entries(surfaces)) {
      assertNoCanary(label, surface);
    }
  });
});
