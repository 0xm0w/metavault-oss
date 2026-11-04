import { pathToFileURL } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { Effect, Exit, JSONSchema, Schema } from "effect";
import { CapabilityRequestSchema, EnrollmentIdSchema, EnrollmentRequestSchema, RevokeSchema } from "../../daemon/src/schemas.js";
import { metavaultEnv } from "../../core/src/env.js";

export const MCP_VERSION: string = "0.1.2-alpha";

export type DaemonFetch = typeof fetch;

export interface MetavaultMcpOptions {
  readonly daemonUrl?: string;
  readonly agentId?: string;
  readonly agentToken?: string;
  readonly shimToken?: string;
  readonly ide?: string;
  readonly defaultTool?: string;
  readonly fetchFn?: DaemonFetch;
  // How long request_capability / grant_status wait for the user's decision
  // before returning a still-pending answer. Bounded so a tool call never
  // outlives a client's own tool timeout. 0 disables waiting.
  readonly approvalWaitMs?: number;
  readonly approvalPollMs?: number;
}

// Tool-edge input for request_capability. The translated daemon request is
// additionally decoded with the shared CapabilityRequestSchema before any
// fetch, and revoke decodes with the shared RevokeSchema directly.
const RequestCapabilityToolSchema = Schema.Struct({
  alias: Schema.String,
  scope: Schema.String,
  reason: Schema.String,
  tool: Schema.optional(Schema.String),
  payload: Schema.optional(Schema.Unknown),
});

const GrantStatusToolSchema = Schema.Struct({ grantId: Schema.String });

const NoArgsSchema = Schema.Struct({});

const RequestEnrollmentToolSchema = Schema.Struct({
  alias: Schema.String,
  scope: Schema.String,
  reason: Schema.optional(Schema.String),
  website: Schema.optional(Schema.String),
});

type RequestCapabilityToolInput = Schema.Schema.Type<typeof RequestCapabilityToolSchema>;

function toolInputSchema<A, I>(schema: Schema.Schema<A, I>): Tool["inputSchema"] {
  const generated = JSONSchema.make(schema);
  const properties = (generated as { properties?: Record<string, unknown> }).properties;
  const required = (generated as { required?: readonly string[] }).required;
  return {
    type: "object",
    ...(properties !== undefined ? { properties } : {}),
    ...(required !== undefined ? { required: [...required] } : {}),
  } as Tool["inputSchema"];
}

const TOOLS: readonly Tool[] = [
  {
    name: "request_capability",
    description:
      "Request a scoped capability (e.g. alias stripe, scope charges.read) with a reason. Returns the daemon result: executed, awaiting-approval (with grantId; then call grant_status), or denied (final). Never returns secret values.",
    inputSchema: toolInputSchema(RequestCapabilityToolSchema),
  },
  {
    name: "list_aliases",
    description: "List known credential aliases (aliases only, never secret values).",
    inputSchema: toolInputSchema(NoArgsSchema),
  },
  {
    name: "request_enrollment",
    description:
      "Ask the human to add a credential you do not have. Creates a pending enrollment and returns a deeplink (metavault://add?...) that opens the MetaVault OSS app with alias/scope/website prefilled — only the human types the secret. Show the deeplink to the user, then poll enrollment_status. Never returns secret values.",
    inputSchema: toolInputSchema(RequestEnrollmentToolSchema),
  },
  {
    name: "enrollment_status",
    description: "Check an enrollment created by request_enrollment: pending, completed, or expired.",
    inputSchema: toolInputSchema(EnrollmentIdSchema),
  },
  {
    name: "grant_status",
    description:
      "Check the outcome of a request_capability call that returned awaiting-approval. Returns pending, executed, denied, expired or revoked for that grantId. denied, expired and revoked are final: nothing ran, so stop and ask the user. Never returns secret values.",
    inputSchema: toolInputSchema(GrantStatusToolSchema),
  },
  {
    name: "revoke",
    description: "Revoke pending and future grants for an agent id or alias target.",
    inputSchema: toolInputSchema(RevokeSchema),
  },
];

function errorResult(message: string): CallToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

function verbatimResult(body: unknown, ok: boolean): CallToolResult {
  const serialized: unknown = JSON.stringify(body);
  const text = typeof serialized === "string" ? serialized : "null";
  const base: CallToolResult = { content: [{ type: "text", text }] };
  if (!ok) {
    return { ...base, isError: true };
  }
  if (typeof body === "object" && body !== null && !Array.isArray(body)) {
    return { ...base, structuredContent: body as Record<string, unknown> };
  }
  return base;
}

async function decode<A, I>(schema: Schema.Schema<A, I>, value: unknown): Promise<A | null> {
  const exit = await Effect.runPromiseExit(Schema.decodeUnknown(schema)(value));
  return Exit.isSuccess(exit) ? exit.value : null;
}

// Low-level Server (not McpServer): tool inputs are validated with Effect
// Schema, not the SDK's Zod dialect — the SDK's own "advanced use case".
// eslint-disable-next-line @typescript-eslint/no-deprecated
export function createMetavaultMcpServer(options: MetavaultMcpOptions = {}): Server {
  const rawDaemonUrl = (
    options.daemonUrl ??
    metavaultEnv("DAEMON_URL") ??
    "http://127.0.0.1:7077"
  );
  let daemonUrlEnd = rawDaemonUrl.length;
  while (daemonUrlEnd > 0 && rawDaemonUrl[daemonUrlEnd - 1] === "/") daemonUrlEnd--;
  const daemonUrl = rawDaemonUrl.slice(0, daemonUrlEnd);
  const agentId = options.agentId ?? metavaultEnv("AGENT_ID") ?? "mcp-agent";
  const agentToken = options.agentToken ?? metavaultEnv("AGENT_TOKEN");
  // When daemonUrl points at a remote-access shim (DD7 loopback channel),
  // the shim requires this local token; unset it is simply not sent.
  const shimToken = options.shimToken ?? metavaultEnv("SHIM_TOKEN");
  const ide = options.ide ?? metavaultEnv("IDE") ?? "mcp";
  const defaultTool = options.defaultTool ?? "http";
  const fetchFn: DaemonFetch = options.fetchFn ?? fetch;

  const callDaemon = async (
    method: "GET" | "POST",
    path: string,
    body?: unknown,
    extraHeaders?: Record<string, string>,
  ): Promise<CallToolResult> => {
    let response: Response;
    try {
      response = await fetchFn(`${daemonUrl}${path}`, {
        method,
        headers: {
          "content-type": "application/json",
          "x-metavault-client-pid": String(process.pid),
          ...(extraHeaders ?? {}),
          ...(agentToken !== undefined && agentToken !== ""
            ? { "x-metavault-agent-token": agentToken }
            : {}),
          ...(shimToken !== undefined && shimToken !== ""
            ? { "x-metavault-shim-token": shimToken }
            : {}),
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
    } catch {
      return errorResult("metavault daemon unreachable");
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(await response.text()) as unknown;
    } catch {
      return errorResult("metavault daemon returned a non-JSON response");
    }
    return verbatimResult(parsed, response.ok);
  };

  const textOfResult = (result: CallToolResult): string => result.content.map((c) => (c.type === "text" ? c.text : "")).join("\n");

  const handleRequestCapability = async (args: unknown): Promise<CallToolResult> => {
    const input: RequestCapabilityToolInput | null = await decode(
      RequestCapabilityToolSchema,
      args ?? {},
    );
    if (input === null) {
      return errorResult("invalid arguments for request_capability");
    }
    const candidate = {
      agentId,
      ide,
      tool: input.tool ?? defaultTool,
      alias: input.alias,
      requestedScope: input.scope,
      reason: input.reason,
      clientPid: process.pid,
      ...(agentToken !== undefined && agentToken !== "" ? { agentToken } : {}),
    };
    const decoded = await decode(CapabilityRequestSchema, candidate);
    if (decoded === null) {
      return errorResult("invalid arguments for request_capability");
    }
    const result = await callDaemon("POST", "/request", {
      ...decoded,
      ...(input.payload !== undefined ? { payload: input.payload } : {}),
    });
    return await annotateRequestResult(result);
  };

  // Private receipts from awaiting-approval answers. They stay in this
  // process: the model only ever sees the grant id.
  const receipts = new Map<string, string>();
  const finals = new Map<string, Record<string, unknown>>();
  const approvalWaitMs = Math.max(0, Math.min(options.approvalWaitMs ?? 20_000, 25_000));
  const approvalPollMs = Math.max(10, options.approvalPollMs ?? 750);
  const sleep = (ms: number): Promise<void> => new Promise((resolve) => { setTimeout(resolve, ms); });

  // One read of a grant's outcome, then a bounded wait while it is pending.
  // A wait that ends is "pending, timedOut", never a denial; a daemon or
  // network failure is "unavailable", never a decision either.
  const readGrant = async (grantId: string, waitMs: number): Promise<Record<string, unknown>> => {
    const settled = finals.get(grantId);
    if (settled !== undefined) return settled;
    const receipt = receipts.get(grantId);
    if (receipt === undefined) {
      return { grantId, status: "unknown", final: false, message: "This session did not make that request, so its outcome cannot be read." };
    }
    const deadline = Date.now() + waitMs;
    for (;;) {
      const res = await callDaemon("GET", `/grants/${encodeURIComponent(grantId)}`, undefined, { "x-metavault-grant-receipt": receipt });
      let parsed: unknown;
      try { parsed = JSON.parse(textOfResult(res)) as unknown; } catch { parsed = null; }
      const record = typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
      if (res.isError === true || record === null) {
        const detail = textOfResult(res);
        return { grantId, status: "unavailable", final: false, message: `Could not read the outcome (${detail.slice(0, 120)}). This is not a decision. Ask the user instead of retrying the request.` };
      }
      if (record["terminal"] === true) {
        receipts.delete(grantId);
        const outcome = { ...record, final: true };
        finals.set(grantId, outcome);
        return outcome;
      }
      if (Date.now() >= deadline) {
        return { ...record, final: false, timedOut: waitMs > 0, message: "Still waiting for the user to decide in MetaVault OSS. The wait ended; this is not a denial. Call grant_status again, and do not send the request again." };
      }
      await sleep(Math.min(approvalPollMs, Math.max(10, deadline - Date.now())));
    }
  };

  // Gives the agent the next step for each daemon answer. A denial stays a
  // structured domain result (status "denied", unchanged contract) with
  // final: true and a plain instruction, so a client cannot read it as a
  // connection problem. awaiting-approval waits a bounded time for the
  // user's decision and returns it, or the pending state with the poll tool.
  const annotateRequestResult = async (result: CallToolResult): Promise<CallToolResult> => {
    let parsed: unknown;
    try { parsed = JSON.parse(textOfResult(result)) as unknown; } catch { return result; }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) { return result; }
    const record = { ...(parsed as Record<string, unknown>) };
    if (record["status"] === "awaiting-approval" && typeof record["grantId"] === "string") {
      const grantId = record["grantId"];
      const receipt = record["receipt"];
      delete record["receipt"];
      if (typeof receipt !== "string") { return verbatimResult(record, result.isError !== true); }
      receipts.set(grantId, receipt);
      const outcome = await readGrant(grantId, approvalWaitMs);
      const merged = { ...record, ...(outcome["final"] === true || outcome["status"] === "unavailable" ? outcome : { status: "awaiting-approval", timedOut: outcome["timedOut"], instruction: "The user must decide in MetaVault OSS. Call grant_status with this grantId to learn the outcome. Do not send this request again while it is pending." }) };
      return { content: [{ type: "text", text: JSON.stringify(merged) }], structuredContent: merged };
    }
    if (record["status"] === "denied") {
      return verbatimResult({ ...record, final: true, instruction: "This request was denied. Nothing ran. Do not retry it or look for another way around it; tell the user and ask what they want." }, result.isError !== true);
    }
    return result;
  };

  const handleGrantStatus = async (args: unknown): Promise<CallToolResult> => {
    const decoded = await decode(GrantStatusToolSchema, args ?? {});
    if (decoded === null || decoded.grantId.trim() === "") { return errorResult("invalid arguments for grant_status"); }
    const outcome = await readGrant(decoded.grantId.trim(), approvalWaitMs);
    const failed = outcome["status"] === "unavailable" || outcome["status"] === "unknown";
    return { content: [{ type: "text", text: JSON.stringify(outcome) }], structuredContent: outcome, ...(failed ? { isError: true } : {}) };
  };

  const handleRequestEnrollment = async (args: unknown): Promise<CallToolResult> => {
    const input = await decode(RequestEnrollmentToolSchema, args ?? {});
    if (input === null || input.alias.trim() === "" || input.scope.trim() === "") {
      return errorResult("invalid arguments for request_enrollment");
    }
    const candidate: { alias: string; scope: string; website?: string; reason?: string; agentId: string } = { alias: input.alias.trim(), scope: input.scope.trim(), agentId };
    if (input.website !== undefined && input.website.trim() !== "") { candidate.website = input.website.trim(); }
    if (input.reason !== undefined && input.reason.trim() !== "") { candidate.reason = input.reason.trim().slice(0, 256); }
    const decoded = await decode(EnrollmentRequestSchema, candidate);
    if (decoded === null) { return errorResult("invalid arguments for request_enrollment"); }
    const result = await callDaemon("POST", "/enrollments", decoded);
    if (result.isError === true) { return result; }
    const parsed: unknown = JSON.parse(textOfResult(result)) as unknown;
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      const record = parsed as Record<string, unknown>;
      const enriched = { ...record, instruction: "Show this deeplink to the user and ask them to open it, paste the secret in MetaVault OSS, and save. Then poll enrollment_status until completed, then test the credential with request_capability and report the outcome." };
      return verbatimResult(enriched, true);
    }
    return result;
  };

  const handleEnrollmentStatus = async (args: unknown): Promise<CallToolResult> => {
    const decoded = await decode(EnrollmentIdSchema, args ?? {});
    if (decoded === null || decoded.enrollmentId.trim() === "") { return errorResult("invalid arguments for enrollment_status"); }
    return callDaemon("GET", `/enrollments/${encodeURIComponent(decoded.enrollmentId.trim())}`);
  };

  const handleRevoke = async (args: unknown): Promise<CallToolResult> => {
    const decoded = await decode(RevokeSchema, args ?? {});
    if (decoded === null) {
      return errorResult("invalid arguments for revoke");
    }
    return callDaemon("POST", "/revoke", decoded);
  };

  // eslint-disable-next-line @typescript-eslint/no-deprecated
  const server = new Server(
    { name: "metavault", version: MCP_VERSION },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: [...TOOLS] }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    switch (name) {
      case "list_aliases": {
        const decoded = await decode(NoArgsSchema, args ?? {});
        if (decoded === null) {
          return errorResult("invalid arguments for list_aliases");
        }
        return callDaemon("GET", "/aliases");
      }
      case "request_capability":
        return handleRequestCapability(args);
      case "request_enrollment":
        return handleRequestEnrollment(args);
      case "enrollment_status":
        return handleEnrollmentStatus(args);
      case "grant_status":
        return handleGrantStatus(args);
      case "revoke":
        return handleRevoke(args);
      default:
        return errorResult(`unknown tool: ${name}`);
    }
  });

  return server;
}

export async function startMetavaultMcpServer(
  options: MetavaultMcpOptions = {},
  // eslint-disable-next-line @typescript-eslint/no-deprecated
): Promise<Server> {
  const server = createMetavaultMcpServer(options);
  await server.connect(new StdioServerTransport());
  return server;
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  startMetavaultMcpServer().catch(() => {
    process.stderr.write("failed to start metavault MCP server\n");
    process.exitCode = 1;
  });
}
