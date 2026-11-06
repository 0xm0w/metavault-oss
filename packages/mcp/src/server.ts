import { pathToFileURL } from "node:url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
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
  // How long enrollment_status / registration_status long-poll before
  // reporting "pending". The human types a secret or a 6-digit code while
  // the tool call blocks, so waiting here costs zero agent turns. 0
  // disables waiting.
  readonly statusWaitMs?: number;
  // Where the credential from a verified registration is kept. Defaults to
  // ~/.metavault/agents/<agent id>.token.
  readonly credentialPath?: string;
  // Opens a metavault:// link with the OS so the app comes to the front.
  // Injected in tests. Defaults to the platform's protocol opener.
  readonly launchDeeplink?: (url: string) => Promise<boolean>;
}

const DEFAULT_LAUNCH_LINK = /^metavault:\/\/(add|approve|register|unlock)\?[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]{1,2000}$/;

// First-turn agent context. High signal, under 1500 chars, zero secrets.
export const METAVAULT_MCP_INSTRUCTIONS = `Never ask the user to paste raw API keys, tokens, or card details into chat or .env files: MetaVault OSS keeps credentials in their local vault (vaultd) and executes calls there; secrets never move, only results come back.

Call list_aliases first, then request_capability. Each credential reports alias, scopeCeiling, baseUrl, authStyle, supportedTools. Scopes: <resource>.read for GET/HEAD/GraphQL queries, <resource>.write for POST/PUT/PATCH/DELETE and mutations; stay inside scopeCeiling (ceiling "charges.write" allows charges.read or charges.write).

Shapes: preset verify/read (stripe, github, cloudflare): omit tool and payload. Website-pinned REST: tool "rest.call", payload { method, path: "/v1/...", query?, body? }. GraphQL: tool "graphql.call", payload { query, variables?, operationName? }. Cloudflare DNS: alias "cloudflare", tool "cloudflare.dns", payload { method, path: "/zones/<32hex>/dns_records", query?, body? }. Cloudflare analytics: tool "cloudflare-graphql.analytics", payload { query, variables? }.

Recovery: awaiting-approval -> share metavault://approve?grantId=..., then grant_status. vault-locked -> share metavault://unlock?target=daemon, wait for the user, then grant_status. Missing alias -> request_enrollment({alias, scope, website}) opens metavault://add; enrollment_status long-polls. Unverified caller or 401 -> register_agent, show the 6-digit code and metavault://register?registrationId=..., then registration_status (also waits).

Never fabricate or resend an approval.`;

function defaultLaunchDeeplink(url: string): Promise<boolean> {
  if (!DEFAULT_LAUNCH_LINK.test(url)) return Promise.resolve(false);
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
  // Optional: vaultd derives the identity from the authenticated token, so
  // an explicit agentId here is metadata, not authentication.
  agentId: Schema.optional(Schema.String),
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

// Terminal-vs-pending check for the enrollment/registration long-poll.
function statusFieldOf(result: CallToolResult): string | null {
  const text = result.content.map((c) => (c.type === "text" ? c.text : "")).join("\n");
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      const status = (parsed as Record<string, unknown>)["status"];
      return typeof status === "string" ? status : null;
    }
  } catch {
    // Non-JSON answer: treat as unknown so callers return it unchanged.
  }
  return null;
}

// ReadResource metatype quick-reference; mirrors METAVAULT_MCP_INSTRUCTIONS in full detail.
const CONTEXT_GUIDE_RESOURCE = `# MetaVault OSS — agent context guide

MetaVault OSS stores the user's API credentials in the local vault (vaultd) and executes every call inside it. Never ask the user to paste an API key, token, or card number into chat or a config file.

## Scopes
- \`<resource>.read\` — GET/HEAD requests and GraphQL queries.
- \`<resource>.write\` — POST/PUT/PATCH/DELETE and GraphQL mutations.
- A request must stay inside the credential's \`scopeCeiling\`: ceiling \`charges.write\` allows \`charges.read\` or \`charges.write\`.

## Tools and payloads
- Preset verify/read (aliases \`stripe\`, \`github\`, \`cloudflare\`): omit \`tool\` and \`payload\`; the preset read runs.
- Website-pinned REST — \`tool: "rest.call"\`: payload \`{ method: "GET"|"POST"|"PUT"|"PATCH"|"DELETE", path: "/v1/...", query?: { k: "v" }, body?: {...} }\`. GET needs a read scope; mutating methods need a write scope.
- Website-pinned GraphQL — \`tool: "graphql.call"\`: payload \`{ query, variables?, operationName? }\`. Mutations need a write scope.
- Cloudflare DNS — alias \`cloudflare\`, \`tool: "cloudflare.dns"\`: payload \`{ method, path: "/zones/<32hex>/dns_records", query?, body? }\`; write only on a \`dns_records\` segment.
- Cloudflare analytics — \`tool: "cloudflare-graphql.analytics"\`: payload \`{ query, variables? }\`.

## Async lifecycle
| Answer | Next step |
|---|---|
| executed (+result) | done |
| awaiting-approval, pending | call \`grant_status({grantId})\`; share \`metavault://approve?grantId=...| if the user may have missed the toast |
| vault-locked | share \`metavault://unlock?target=daemon\`, wait, then \`grant_status\` |
| denied (final) | stop; tell the user |
| scope-above-ceiling denied | retry with a narrower \`<resource>.read\` inside \`allowedCeiling\`, or ask the user to enroll a wider scope |
| missing alias | \`request_enrollment({alias, scope, website})\`, then \`enrollment_status\` (long-polls) |
| unverified / 401 | \`register_agent\`, show the 6-digit code + \`metavault://register?registrationId=...\`, then \`registration_status\` (long-polls) |

Registration, approval, and vault-locked links open the right screen in the desktop app. Agents never see credentials.`;

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
          "x-metavault-client-pid": String(process.pid),
          ...(body !== undefined ? { "content-type": "application/json" } : {}),
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

  // Plain parsed read for GET endpoints (resources list). Null on any error.
  const daemonJson = async (path: string): Promise<Record<string, unknown> | null> => {
    try {
      const response = await fetchFn(`${daemonUrl}${path}`, {
        method: "GET",
        headers: {
          "x-metavault-client-pid": String(process.pid),
          ...(agentToken !== undefined && agentToken !== "" ? { "x-metavault-agent-token": agentToken } : {}),
          ...(shimToken !== undefined && shimToken !== "" ? { "x-metavault-shim-token": shimToken } : {}),
        },
      });
      if (!response.ok) return null;
      const parsed: unknown = JSON.parse(await response.text());
      return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
        ? (parsed as Record<string, unknown>)
        : null;
    } catch {
      return null;
    }
  };

  const handleRequestCapability = async (args: unknown): Promise<CallToolResult> => {
    const input: RequestCapabilityToolInput | null = await decode(
      RequestCapabilityToolSchema,
      args ?? {},
    );
    if (input === null) {
      return errorResult("invalid arguments for request_capability");
    }
    const candidate = {
      agentId: (input.agentId ?? agentId).trim() === "" ? "mcp-agent" : (input.agentId ?? agentId).trim(),
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
  const statusWaitMs = Math.max(0, Math.min(options.statusWaitMs ?? 20_000, 25_000));
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
      const remaining = Math.max(0, deadline - Date.now());
      const pollWait = Math.min(20_000, remaining);
      const started = Date.now();
      const grantPath =
        pollWait > 0
          ? `/grants/${encodeURIComponent(grantId)}?waitMs=${String(pollWait)}`
          : `/grants/${encodeURIComponent(grantId)}`;
      const res = await callDaemon("GET", grantPath, undefined, { "x-metavault-grant-receipt": receipt });
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
      const elapsed = Date.now() - started;
      // An old daemon ignores ?waitMs= and returns immediately. A short
      // sleep stops that from becoming a tight loop. approvalPollMs still
      // caps the fallback so tests can keep the wait short.
      if (elapsed < 50) {
        await sleep(Math.min(50, approvalPollMs, Math.max(10, deadline - Date.now())));
      }
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
      // The vault is locked and the request cannot be assessed until the
      // human unlocks it: report that instead of letting the agent wait on a
      // grant nobody can decide yet.
      if (record["vaultLocked"] === true) {
        const lockedOut = {
          status: "vault-locked",
          grantId,
          deeplink: "metavault://unlock?target=daemon",
          instruction: "The vault is locked. Tell the user to unlock MetaVault OSS (or open metavault://unlock?target=daemon), then call grant_status with this grantId. Do not resend the request.",
        };
        return verbatimResult(lockedOut, true);
      }
      const outcome = await readGrant(grantId, approvalWaitMs);
      if (outcome["final"] === true || outcome["status"] === "unavailable") {
        const merged = { ...record, ...outcome };
        return { content: [{ type: "text", text: JSON.stringify(merged) }], structuredContent: merged };
      }
      // Still pending when the wait budget ends: hand the agent a clickable
      // deeplink so the user can decide even without the toast visible.
      const timedOut = {
        ...record,
        status: "awaiting-approval",
        timedOut: outcome["timedOut"],
        deeplink: `metavault://approve?grantId=${encodeURIComponent(grantId)}`,
        instruction: "The user must decide in MetaVault OSS. Show the deeplink if they may have missed the toast, then call grant_status with this grantId to learn the outcome. Do not send this request again while it is pending.",
      };
      return { content: [{ type: "text", text: JSON.stringify(timedOut) }], structuredContent: timedOut };
    }
    if (record["status"] === "denied") {
      if (record["reason"] === "scope-above-ceiling") {
        const ceiling = typeof record["allowedCeiling"] === "string" ? record["allowedCeiling"] : "";
        return verbatimResult({
          ...record,
          final: true,
          instruction: `Requested scope exceeds this credential's ceiling${ceiling !== "" ? ` (${ceiling})` : ""}. Retry with <resource>.read within that ceiling, or ask the user before requesting enrollment for a wider scope.`,
        }, result.isError !== true);
      }
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
    const id = encodeURIComponent(decoded.enrollmentId.trim());
    const deadline = Date.now() + statusWaitMs;
    for (;;) {
      const remaining = Math.max(0, deadline - Date.now());
      // The real server blocks up to ?waitMs= before answering; older ones
      // answer immediately and the loop below keeps the wait bounded.
      const res = await callDaemon("GET", `/enrollments/${id}${remaining > 0 ? `?waitMs=${String(Math.min(25_000, Math.floor(remaining)))}` : ""}`);
      if (res.isError === true) return res;
      const status = statusFieldOf(res);
      if (remaining <= 0 || (status !== "pending" && status !== null)) return res;
      await sleep(Math.min(Math.max(10, approvalPollMs), Math.max(1, remaining)));
    }
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
    {
      capabilities: { tools: {}, resources: {}, prompts: {} },
      instructions: METAVAULT_MCP_INSTRUCTIONS,
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, () => ({ tools: [...TOOLS] }));

  // Resources: static quick-reference + a live, secret-free status snapshot.
  server.setRequestHandler(ListResourcesRequestSchema, () => ({
    resources: [
      {
        uri: "metavault://context/guide",
        name: "MetaVault context guide",
        description: "Connector, scope, payload, and deeplink quick-reference.",
        mimeType: "text/markdown",
      },
      {
        uri: "metavault://context/status",
        name: "Live vault status",
        description: "Current aliases, credential routing metadata, and lock state.",
        mimeType: "application/json",
      },
    ],
  }));
  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const uri = request.params.uri;
    if (uri === "metavault://context/guide") {
      return {
        contents: [
          {
            uri,
            mimeType: "text/markdown",
            text: CONTEXT_GUIDE_RESOURCE,
          },
        ],
      };
    }
    if (uri === "metavault://context/status") {
      const [health, aliases, keyStatus] = await Promise.all([
        daemonJson("/health"),
        daemonJson("/aliases"),
        daemonJson("/key/status"),
      ]);
      const locked = typeof keyStatus?.["locked"] === "boolean" ? (keyStatus["locked"]) : undefined;
      const status = {
        daemon: health !== null ? health : { reachable: false },
        aliases: aliases?.["aliases"] ?? [],
        credentials: aliases?.["credentials"] ?? [],
        ...(locked !== undefined ? { locked } : {}),
      };
      return {
        contents: [
          {
            uri,
            mimeType: "application/json",
            text: JSON.stringify(status),
          },
        ],
      };
    }
    return {
      contents: [],
      isError: true,
      error: { code: -32602, message: `unknown resource: ${uri}` },
    };
  });

  // Prompt templates for agents that need a first-turn script.
  server.setRequestHandler(ListPromptsRequestSchema, () => ({
    prompts: [
      {
        name: "use-secret",
        description: "Make a scoped request through MetaVault with an existing credential.",
        arguments: [{ name: "alias", description: "Credential alias to use", required: false }],
      },
      {
        name: "enroll-secret",
        description: "Ask the user to add a credential to MetaVault without pasting the secret.",
        arguments: [
          { name: "alias", description: "Alias for the credential", required: true },
          { name: "website", description: "Pinned https:// base URL", required: false },
        ],
      },
    ],
  }));
  server.setRequestHandler(GetPromptRequestSchema, (request) => {
    const name = request.params.name;
    const args = request.params.arguments ?? {};
    if (name === "use-secret") {
      const alias = typeof args["alias"] === "string" && args["alias"].trim() !== "" ? args["alias"].trim() : null;
      const target = alias !== null
        ? `MetaVault credential alias "${alias}\"`
        : "one of the user's MetaVault credentials (call list_aliases to see them)";
      return {
        description: "Scoped request through vaultd; the secret never leaves the vault.",
        messages: [
          {
            role: "user" as const,
            content: {
              type: "text" as const,
              text: `Use the ${target} to make the read/web request I need. Call request_capability with the alias, a scope like <resource>.read (or <resource>.write for mutating calls) inside its scopeCeiling, and a one-line reason; add tool "rest.call" or "graphql.call" with a payload when the credential pins a website baseUrl. If the answer is awaiting-approval with a grantId, share metavault://approve?grantId=... with me if helpful and call grant_status; if vault-locked, share metavault://unlock?target=daemon and wait. Never ask me to paste the secret itself, and never resend a pending request.`,
            },
          },
        ],
      };
    }
    if (name === "enroll-secret") {
      const alias = typeof args["alias"] === "string" ? args["alias"].trim() : "";
      const website = typeof args["website"] === "string" ? args["website"].trim() : "";
      return {
        description: "Enroll a new credential without the secret ever entering chat.",
        messages: [
          {
            role: "user" as const,
            content: {
              type: "text" as const,
              text: `I need you to add a MetaVault credential${alias !== "" ? ` named "${alias}"` : ""}${website !== "" ? ` pinned to ${website}` : ""}. Call request_enrollment with the alias, the narrowest sensible scope (for example <resource>.read),${website !== "" ? ` website "${website}",` : ""} and a short reason; it opens metavault://add on my computer with the form ready. Then call enrollment_status, which waits for me to save it. Ask me only for things like the alias name or scope — never for the API key itself, and never tell me to paste it anywhere.`,
            },
          },
        ],
      };
    }
    return {
      description: "",
      messages: [],
      isError: true,
      error: { code: -32602, message: `unknown prompt: ${name}` },
    };
  });

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
    const deeplink = `metavault://register?registrationId=${encodeURIComponent(rec["registrationId"])}`;
    const sameMachine = /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:|\/|$)/.test(daemonUrl);
    const launched = sameMachine ? await (options.launchDeeplink ?? defaultLaunchDeeplink)(deeplink).catch(() => false) : false;
    return verbatimResult({
      status: "pending", agentId, registrationId: rec["registrationId"], code: rec["code"], deeplink, launched,
      message: `Tell the user to open MetaVault OSS and approve the registration request that shows code ${String(rec["code"])}. The deeplink opens the approval screen${launched ? " (it was opened on this machine)" : ""}. Then call registration_status once, which waits for their decision. Do not retry registration while it is pending.`,
    }, true);
  };
  const handleRegistrationStatus = async (): Promise<CallToolResult> => {
    if (agentToken !== undefined && agentToken !== "") return verbatimResult({ status: "verified", message: "This agent holds an approved credential." }, true);
    if (claim === null) return verbatimResult({ status: "none", message: "No registration is in progress. Call register_agent." }, true);
    // Server-side long-poll: the daemon holds the claim call open until the
    // user approves or the budget ends, so this single tool call is the wait.
    const waitMs = Math.min(25_000, statusWaitMs);
    const res = await callDaemon("POST", `/agent-registrations/${encodeURIComponent(claim.registrationId)}/claim`, { claim: claim.secret, waitMs });
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
