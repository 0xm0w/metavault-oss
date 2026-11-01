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

export const MCP_VERSION: string = "0.1.0";

export type DaemonFetch = typeof fetch;

export interface OpenVaultMcpOptions {
  readonly daemonUrl?: string;
  readonly agentId?: string;
  readonly ide?: string;
  readonly defaultTool?: string;
  readonly fetchFn?: DaemonFetch;
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
      "Request a scoped capability (e.g. alias stripe, scope charges.read) with a reason. Returns the daemon result verbatim: executed, awaiting-approval (with grantId), or denied. Never returns secret values.",
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
      "Ask the human to add a credential you do not have. Creates a pending enrollment and returns a deeplink (openvault://add?...) that opens the OpenVault app with alias/scope/website prefilled — only the human types the secret. Show the deeplink to the user, then poll enrollment_status. Never returns secret values.",
    inputSchema: toolInputSchema(RequestEnrollmentToolSchema),
  },
  {
    name: "enrollment_status",
    description: "Check an enrollment created by request_enrollment: pending, completed, or expired.",
    inputSchema: toolInputSchema(EnrollmentIdSchema),
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
export function createOpenVaultMcpServer(options: OpenVaultMcpOptions = {}): Server {
  const daemonUrl = (
    options.daemonUrl ??
    process.env["OPENVAULT_DAEMON_URL"] ??
    "http://127.0.0.1:7077"
  ).replace(/\/+$/, "");
  const agentId = options.agentId ?? process.env["OPENVAULT_AGENT_ID"] ?? "mcp-agent";
  const ide = options.ide ?? process.env["OPENVAULT_IDE"] ?? "mcp";
  const defaultTool = options.defaultTool ?? "http";
  const fetchFn: DaemonFetch = options.fetchFn ?? fetch;

  const callDaemon = async (
    method: "GET" | "POST",
    path: string,
    body?: unknown,
  ): Promise<CallToolResult> => {
    let response: Response;
    try {
      response = await fetchFn(`${daemonUrl}${path}`, {
        method,
        headers: { "content-type": "application/json" },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
    } catch {
      return errorResult("openvault daemon unreachable");
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(await response.text()) as unknown;
    } catch {
      return errorResult("openvault daemon returned a non-JSON response");
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
    };
    const decoded = await decode(CapabilityRequestSchema, candidate);
    if (decoded === null) {
      return errorResult("invalid arguments for request_capability");
    }
    return callDaemon("POST", "/request", {
      ...decoded,
      ...(input.payload !== undefined ? { payload: input.payload } : {}),
    });
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
      const enriched = { ...record, instruction: "Show this deeplink to the user and ask them to open it, paste the secret in OpenVault, and save. Then poll enrollment_status until completed, then test the credential with request_capability and report the outcome." };
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
    { name: "openvault", version: MCP_VERSION },
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
      case "revoke":
        return handleRevoke(args);
      default:
        return errorResult(`unknown tool: ${name}`);
    }
  });

  return server;
}

export async function startOpenVaultMcpServer(
  options: OpenVaultMcpOptions = {},
  // eslint-disable-next-line @typescript-eslint/no-deprecated
): Promise<Server> {
  const server = createOpenVaultMcpServer(options);
  await server.connect(new StdioServerTransport());
  return server;
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  startOpenVaultMcpServer().catch(() => {
    process.stderr.write("failed to start openvault MCP server\n");
    process.exitCode = 1;
  });
}
