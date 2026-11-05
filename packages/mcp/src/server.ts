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
import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { defaultCredentialPath, loadStoredCredential, storeCredentialPrivately } from "./credential-store.js";
import { metavaultEnv } from "../../core/src/env.js";

export const MCP_VERSION: string = "0.1.4-alpha";

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
  // Where the credential from a verified registration is kept. Defaults to
  // ~/.metavault/agents/<agent id>.token.
  readonly credentialPath?: string;
  // Opens a metavault:// link with the OS so the app comes to the front.
  // Injected in tests. Defaults to the platform's protocol opener.
  readonly launchDeeplink?: (url: string) => Promise<boolean>;
}

const ENROLLMENT_LINK = /^metavault:\/\/add\?[A-Za-z0-9%=&._~:@+-]{1,2000}$/;

function defaultLaunchDeeplink(url: string): Promise<boolean> {
  if (!ENROLLMENT_LINK.test(url)) return Promise.resolve(false);
  const [cmd, args]: [string, string[]] =
    process.platform === "win32" ? ["rundll32", ["url.dll,FileProtocolHandler", url]]
    : process.platform === "darwin" ? ["open", [url]]
    : ["xdg-open", [url]];
  return new Promise((resolve) => {
    try {
      execFile(cmd, args, { timeout: 5000, windowsHide: true }, (err) => { resolve(err === null); });
    } catch {
      resolve(false);
    }
  });
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
      "Request a scoped capability (e.g. alias stripe, scope charges.read) with a reason. Returns the daemon result: executed, awaiting-approval (with grantId; then call grant_status), or denied (final). Never returns secret values. Cloudflare DNS uses alias cloudflare, tool cloudflare.dns, and payload { method, path, query?, body? }. path is /zones, /zones/{32-hex-id}, /zones/{id}/dns_records, or /zones/{id}/dns_records/{32-hex-id}. query keys are name, type, content, page, per_page. GET needs a dns.read ceiling. POST, PUT, PATCH, and DELETE need dns.write and create or change only a dns_records path. No payload runs the preset read, which for cloudflare is token verify. A connector-failed denial may include upstreamStatus and is final.",
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
    name: "register_agent",
    description:
      "Ask the user to register this agent as a Verified agent in MetaVault OSS. Returns a registrationId and a 6-digit code: tell the user the code and ask them to approve the matching request in MetaVault OSS. Then call registration_status. The credential is stored privately by this MCP process and is never shown to you. Verified means the user approved this agent's credential; it does not prove which program you are.",
    inputSchema: toolInputSchema(NoArgsSchema),
  },
  {
    name: "registration_status",
    description:
      "Finish registration after the user approves it. Returns pending, verified, denied or expired. Never returns the credential.",
    inputSchema: toolInputSchema(NoArgsSchema),
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
  const credentialPath = options.credentialPath ?? defaultCredentialPath(agentId);
  let agentToken: string | undefined = options.agentToken ?? metavaultEnv("AGENT_TOKEN") ?? loadStoredCredential(credentialPath);
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
        let outcome: Record<string, unknown> = { ...record, final: true };
        if (record["status"] === "executed") {
          // One-time pickup of the approved call's result, bound to this
          // request's receipt. The daemon never sends the credential.
          const taken = await callDaemon("POST", `/grants/${encodeURIComponent(grantId)}/result`, undefined, { "x-metavault-grant-receipt": receipt });
          let body: unknown;
          try { body = JSON.parse(textOfResult(taken)) as unknown; } catch { body = null; }
          const got = typeof body === "object" && body !== null && !Array.isArray(body) ? body as Record<string, unknown> : null;
          if (got !== null && got["status"] === "delivered") {
            outcome = { ...outcome, result: got["result"], message: "The user approved this request and vaultd ran it. The result is included." };
          } else if (got === null || taken.isError === true && got["status"] !== "gone") {
            // Transient failure: keep the receipt so a later call can retry the pickup.
            return { grantId, status: "unavailable", final: false, message: "The request ran, but the result could not be fetched yet. Call grant_status again." };
          } else {
            outcome = { ...outcome, message: "The user approved this request and vaultd ran it. The result was already delivered, expired or was revoked and is not available." };
          }
        }
        receipts.delete(grantId);
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
      // Open MetaVault in front on this PC with the secure input ready. Only a
      // same-machine daemon is launched; a remote shim gets the link instead.
      const link = typeof record["deeplink"] === "string" ? record["deeplink"] : "";
      const sameMachine = /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:|\/|$)/.test(daemonUrl);
      const launched = sameMachine && link !== "" ? await (options.launchDeeplink ?? defaultLaunchDeeplink)(link).catch(() => false) : false;
      const enriched = {
        ...record,
        launched,
        instruction: launched
          ? "MetaVault OSS was opened on the user's computer with the add-credential form ready. Tell the user to type the secret there, never in this chat, and save. Then poll enrollment_status until completed. To test it, run one read-only request_capability and report the outcome; the user approves access separately."
          : "MetaVault OSS could not be opened automatically. Show this deeplink to the user and ask them to open it, enter the secret in MetaVault OSS, and save. Then poll enrollment_status until completed, then run one read-only request_capability to test it and report the outcome.",
      };
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

  // Verified-agent registration. The claim secret lives only in this process;
  // the daemon holds its hash. The credential goes daemon -> this process ->
  // an owner-only file, never through the model.
  let claim: { registrationId: string; secret: string } | null = null;
  const handleRegisterAgent = async (): Promise<CallToolResult> => {
    if (agentToken !== undefined && agentToken !== "") {
      return verbatimResult({ status: "verified", message: "This agent already holds an approved credential." }, true);
    }
    const secret = randomBytes(32).toString("hex");
    const res = await callDaemon("POST", "/agent-registrations", {
      agentId, name: ide === "mcp" ? agentId : ide, ide, claimHash: createHash("sha256").update(secret).digest("hex"),
    });
    let body: unknown;
    try { body = JSON.parse(textOfResult(res)) as unknown; } catch { body = null; }
    const rec = typeof body === "object" && body !== null && !Array.isArray(body) ? body as Record<string, unknown> : null;
    if (res.isError === true || rec === null || typeof rec["registrationId"] !== "string") {
      return errorResult(`Registration could not be started: ${textOfResult(res).slice(0, 160)}`);
    }
    claim = { registrationId: rec["registrationId"], secret };
    return verbatimResult({
      status: "pending", registrationId: rec["registrationId"], code: rec["code"],
      message: `Tell the user to open MetaVault OSS and approve the registration request that shows code ${String(rec["code"])}. Then call registration_status. Do not retry registration while it is pending.`,
    }, true);
  };
  const handleRegistrationStatus = async (): Promise<CallToolResult> => {
    if (agentToken !== undefined && agentToken !== "") return verbatimResult({ status: "verified", message: "This agent holds an approved credential." }, true);
    if (claim === null) return verbatimResult({ status: "none", message: "No registration is in progress. Call register_agent." }, true);
    const res = await callDaemon("POST", `/agent-registrations/${encodeURIComponent(claim.registrationId)}/claim`, { claim: claim.secret });
    let body: unknown;
    try { body = JSON.parse(textOfResult(res)) as unknown; } catch { body = null; }
    const rec = typeof body === "object" && body !== null && !Array.isArray(body) ? body as Record<string, unknown> : null;
    if (rec === null) return errorResult("Could not read the registration status. This is not a decision. Try again shortly.");
    if (rec["status"] === "claimed" && typeof rec["token"] === "string") {
      const stored = storeCredentialPrivately(credentialPath, rec["token"]);
      if (!stored.ok) {
        claim = null;
        return verbatimResult({ status: "failed", message: `The credential could not be stored privately (${stored.reason}), so it was not kept. Ask the user to revoke this agent in MetaVault OSS, then register again.` }, false);
      }
      agentToken = rec["token"];
      claim = null;
      return verbatimResult({ status: "verified", message: "Registered. Requests from this agent are now sent as a Verified agent. Capabilities still need the user's approval." }, true);
    }
    const st = typeof rec["status"] === "string" ? rec["status"] : "unknown";
    if (st === "denied" || st === "expired" || st === "claimed" || st === "bad-claim") claim = null;
    const messages: Record<string, string> = {
      pending: "Still waiting for the user to approve in MetaVault OSS. Do not register again.",
      denied: "The user denied the registration. Stop and ask the user.",
      expired: "The registration expired. Ask the user before registering again.",
    };
    return verbatimResult({ status: st, message: messages[st] ?? "Registration did not complete. Ask the user." }, true);
  };

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
      case "register_agent":
        return await handleRegisterAgent();
      case "registration_status":
        return await handleRegistrationStatus();
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
