import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Effect, Layer } from "effect";
import { afterAll, describe, expect, it } from "vitest";
import { Brain, buildMarshalPrompt } from "../packages/brain/src/brain.js";
import { Connector } from "../packages/core/src/connector.js";
import { VaultStore, VaultStoreTest } from "../packages/core/src/storage.js";
import { handleVaultRequest } from "../packages/daemon/src/server.js";
import {
  makeVaultServiceLive,
  VaultService,
  type VaultServiceService,
} from "../packages/daemon/src/service.js";
import {
  projectAliasesResponse,
  projectAuditResponse,
  projectPendingResponse,
  projectPoliciesResponse,
} from "../packages/app/src/renderer/model.js";
import {
  createOpenVaultMcpServer,
  type DaemonFetch,
} from "../packages/mcp/src/server.js";

// Canary test (design spec Sections 10-11, invariant 1): a unique fake
// secret is stored, the full request -> approve -> execute loop runs
// against a mock connector, and every surface an agent, a log, a model, or
// the desktop app could ever see is grepped for the canary. Any hit fails
// the build. The connector's in-daemon view of the secret is asserted
// separately (and never scanned as a payload) to prove the secret really
// flowed through the loop — otherwise a leak-free scan would be vacuous.
const CANARY = "OPENVAULT-CANARY-9f27c41a-this-string-must-never-leak";
const MASTER_KEY = Buffer.alloc(32, 7);

function assertNoCanary(label: string, value: unknown): void {
  const serialized: unknown = JSON.stringify(value);
  const text = typeof serialized === "string" ? serialized : "";
  if (text.includes(CANARY)) {
    throw new Error(`canary leaked into ${label}`);
  }
}

interface Harness {
  readonly service: VaultServiceService;
  readonly prompts: string[];
  readonly connectorSecrets: string[];
  readonly getCiphertext: () => Promise<string | undefined>;
}

async function buildHarness(requireApproval: boolean): Promise<Harness> {
  const prompts: string[] = [];
  const connectorSecrets: string[] = [];
  const capturingBrain = Layer.succeed(Brain, {
    assess: (req, historySummary, policyDigest) => {
      // Rebuild the exact prompt the live Ollama layer would send, so the
      // scan below covers real model prompts, not a paraphrase.
      prompts.push(buildMarshalPrompt(req, historySummary, policyDigest));
      return Effect.succeed({
        risk: "low" as const,
        recommendedScope: "charges.read",
        requireApproval,
        explanation: "canary test marshal",
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
      Effect.provide(
        Layer.mergeAll(VaultStoreTest(MASTER_KEY), capturingBrain, mockConnector),
      ),
    ),
  );
  return {
    service: built.service,
    prompts,
    connectorSecrets,
    getCiphertext: async () => {
      const record = await Effect.runPromise(built.store.getCredential("stripe"));
      return record?.ciphertext;
    },
  };
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

describe("canary: the stored secret appears on no observable surface", () => {
  it("scan helper actually detects a planted canary (non-vacuous grep)", () => {
    expect(() => {
      assertNoCanary("planted", { note: `prefix ${CANARY} suffix` });
    }).toThrow(/canary leaked into planted/);
    expect(() => {
      assertNoCanary("clean", { note: "nothing here" });
    }).not.toThrow();
  });

  it("request -> approve -> execute leaks the canary nowhere", async () => {
    const harness = await buildHarness(true);
    const svc = harness.service;

    // The stored blob is ciphertext, not the canary in a trench coat.
    const ciphertext = await harness.getCiphertext();
    expect(ciphertext).toBeDefined();
    assertNoCanary("stored ciphertext", ciphertext);

    // MCP surface, wired exactly like packages/mcp/test/mcp.test.ts:
    // in-process client -> MCP server -> daemon HTTP handler -> service.
    const daemonFetch: DaemonFetch = async (input, init) => {
      const raw =
        typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const url = new URL(raw);
      const body: unknown =
        typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
      const out = await handleVaultRequest(svc, init?.method ?? "GET", url.pathname, body);
      return new Response(JSON.stringify(out.body), {
        status: out.status,
        headers: { "content-type": "application/json" },
      });
    };
    const server = createOpenVaultMcpServer({
      daemonUrl: "http://127.0.0.1:7077",
      agentId: "cursor",
      ide: "Cursor",
      fetchFn: daemonFetch,
    });
    client = new Client({ name: "canary-test-client", version: "0.0.1" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const mcpAliases = (await client.callTool({
      name: "list_aliases",
      arguments: {},
    })) as ToolResult;
    const mcpRequest = (await client.callTool({
      name: "request_capability",
      arguments: { alias: "stripe", scope: "charges.read", reason: "canary loop" },
    })) as ToolResult;
    expect(mcpRequest.structuredContent?.["status"]).toBe("awaiting-approval");
    const grantId = mcpRequest.structuredContent?.["grantId"];
    expect(typeof grantId).toBe("string");

    // App payloads, raw from the daemon handler and as the renderer
    // projects them (the renderer's whitelist projection is the last line
    // before anything reaches the desktop window).
    const pendingBody = (await handleVaultRequest(svc, "GET", "/pending")).body;
    const policiesBody = (await handleVaultRequest(svc, "GET", "/policies")).body;
    const aliasesBody = (await handleVaultRequest(svc, "GET", "/aliases")).body;
    const pendingApprovals = await Effect.runPromise(svc.listPendingApprovals());
    expect(pendingApprovals).toHaveLength(1);

    // Human approves; the grant executes inside the daemon exactly once.
    const approved = await Effect.runPromise(svc.approve(grantId as string));
    expect(approved.status).toBe("executed");
    expect(approved.result).toEqual({ echoedLength: CANARY.length });

    // A second, direct daemon request -> approve -> execute cycle.
    const direct = await Effect.runPromise(
      svc.requestCapability({
        agentId: "cursor",
        ide: "Cursor",
        tool: "http",
        alias: "stripe",
        requestedScope: "charges.read",
        reason: "canary loop, second pass",
      }),
    );
    expect(direct.status).toBe("awaiting-approval");
    const directApproved = await Effect.runPromise(
      svc.approve(direct.grantId as string),
    );

    const audit = await Effect.runPromise(svc.listAudit());
    const auditBody = (await handleVaultRequest(svc, "GET", "/audit")).body;
    expect(audit.map((e) => e.stage)).toContain("executed");
    // The captured model prompts really are marshal prompts (metadata in,
    // secret out) — otherwise scanning them would prove nothing.
    expect(harness.prompts.length).toBeGreaterThan(0);
    expect(harness.prompts[0]).toContain("stripe");
    expect(harness.prompts[0]).toContain("charges.read");

    // Proof the secret really flowed: the mock connector received exactly
    // the canary, exactly once per execution, inside the daemon only.
    expect(harness.connectorSecrets).toEqual([CANARY, CANARY]);

    const surfaces: Record<string, unknown> = {
      "MCP list_aliases response": mcpAliases,
      "MCP request_capability response": mcpRequest,
      "daemon /pending payload": pendingBody,
      "daemon /policies payload": policiesBody,
      "daemon /aliases payload": aliasesBody,
      "daemon /audit payload": auditBody,
      "service listPendingApprovals (app payload)": pendingApprovals,
      "renderer-projected pending": projectPendingResponse(pendingBody),
      "renderer-projected policies": projectPoliciesResponse(policiesBody),
      "renderer-projected aliases": projectAliasesResponse(aliasesBody),
      "renderer-projected audit": projectAuditResponse(auditBody),
      "approve result": approved,
      "direct request result": direct,
      "direct approve result": directApproved,
      "audit rows": audit,
      "captured model prompts": harness.prompts,
      "stored ciphertext": ciphertext,
    };
    for (const [label, surface] of Object.entries(surfaces)) {
      assertNoCanary(label, surface);
    }
  });

  it("the auto-approved path (no human click) also leaks nowhere", async () => {
    const harness = await buildHarness(false);
    const result = await Effect.runPromise(
      harness.service.requestCapability({
        agentId: "cursor",
        ide: "Cursor",
        tool: "http",
        alias: "stripe",
        requestedScope: "charges.read",
        reason: "canary auto-approve pass",
      }),
    );
    expect(result.status).toBe("executed");
    expect(harness.connectorSecrets).toEqual([CANARY]);
    const audit = await Effect.runPromise(harness.service.listAudit());
    assertNoCanary("auto-approve result", result);
    assertNoCanary("auto-approve audit rows", audit);
    assertNoCanary("auto-approve model prompts", harness.prompts);
  });
});
