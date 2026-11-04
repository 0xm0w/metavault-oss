import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import { createMetavaultMcpServer, type DaemonFetch } from "../src/server.js";

interface ToolResult { readonly isError?: boolean; readonly content?: readonly { readonly type: string; readonly text?: string }[]; readonly structuredContent?: Record<string, unknown>; }
const textOf = (r: ToolResult): string => (r.content ?? []).map((c) => c.text ?? "").join("\n");

async function makeClient(fetchFn: DaemonFetch, launchDeeplink: (url: string) => Promise<boolean> = () => Promise.resolve(false), daemonUrl = "http://127.0.0.1:7077"): Promise<Client> {
  const server = createMetavaultMcpServer({ daemonUrl, fetchFn, launchDeeplink });
  const client = new Client({ name: "enroll-test", version: "0.0.1" });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  await client.connect(ct);
  return client;
}

describe("MCP enrollment tools (fake daemon)", () => {
  it("request_enrollment returns deeplink + instruction, enrollment_status polls, no secrets", async () => {
    const calls: { method: string; url: string; body: unknown }[] = [];
    const fetchFn: DaemonFetch = (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      calls.push({ method: init?.method ?? "GET", url, body: typeof init?.body === "string" ? JSON.parse(init.body) as unknown : undefined });
      const payload = url.includes("/enrollments/enr-1") ? { status: "completed", alias: "stripe", scope: "charges.read" } : { enrollmentId: "enr-1", deeplink: "metavault://add?alias=stripe&scope=charges.read&enrollment=enr-1" };
      return Promise.resolve(new Response(JSON.stringify(payload), { status: 201, headers: { "content-type": "application/json" } }));
    };
    const client = await makeClient(fetchFn);
    try {
      const listed = await client.listTools();
      expect(listed.tools.map((t) => t.name)).toContain("request_enrollment");
      expect(listed.tools.map((t) => t.name)).toContain("enrollment_status");
      const created = (await client.callTool({ name: "request_enrollment", arguments: { alias: "stripe", scope: "charges.read", reason: "need it" } })) as ToolResult;
      expect(created.isError).not.toBe(true);
      expect(textOf(created)).toContain("metavault://add?");
      expect(textOf(created)).toContain("Show this deeplink");
      expect(JSON.stringify(created)).not.toContain("sk-");
      expect(calls[0]?.body).toMatchObject({ alias: "stripe", scope: "charges.read", reason: "need it" });
      const status = (await client.callTool({ name: "enrollment_status", arguments: { enrollmentId: "enr-1" } })) as ToolResult;
      expect(status.structuredContent?.["status"]).toBe("completed");
      const bad = (await client.callTool({ name: "request_enrollment", arguments: { alias: 42 } })) as ToolResult;
      expect(bad.isError).toBe(true);
      expect(calls).toHaveLength(2);
    } finally { await client.close(); }
  });

  it("opens MetaVault on this PC with the add form instead of only returning a link", async () => {
    const fetchFn: DaemonFetch = () => Promise.resolve(new Response(JSON.stringify({ enrollmentId: "enr-2", deeplink: "metavault://add?alias=cloudflare&scope=analytics.read&enrollment=enr-2" }), { status: 201, headers: { "content-type": "application/json" } }));
    const opened: string[] = [];
    const client = await makeClient(fetchFn, (url) => { opened.push(url); return Promise.resolve(true); });
    try {
      const res = (await client.callTool({ name: "request_enrollment", arguments: { alias: "cloudflare", scope: "analytics.read" } })) as ToolResult;
      expect(opened).toEqual(["metavault://add?alias=cloudflare&scope=analytics.read&enrollment=enr-2"]);
      expect(res.structuredContent?.["launched"]).toBe(true);
      expect(textOf(res)).toContain("type the secret there, never in this chat");
    } finally { await client.close(); }
  });

  it("does not launch anything for a remote daemon url", async () => {
    const fetchFn: DaemonFetch = () => Promise.resolve(new Response(JSON.stringify({ enrollmentId: "enr-3", deeplink: "metavault://add?alias=a&scope=b.read&enrollment=enr-3" }), { status: 201, headers: { "content-type": "application/json" } }));
    const opened: string[] = [];
    const client = await makeClient(fetchFn, (url) => { opened.push(url); return Promise.resolve(true); }, "https://vault.example.invalid");
    try {
      const res = (await client.callTool({ name: "request_enrollment", arguments: { alias: "a", scope: "b.read" } })) as ToolResult;
      expect(opened).toEqual([]);
      expect(res.structuredContent?.["launched"]).toBe(false);
    } finally { await client.close(); }
  });
});
