import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import { createOpenVaultMcpServer, type DaemonFetch } from "../src/server.js";

interface ToolResult { readonly isError?: boolean; readonly content?: readonly { readonly type: string; readonly text?: string }[]; readonly structuredContent?: Record<string, unknown>; }
const textOf = (r: ToolResult): string => (r.content ?? []).map((c) => c.text ?? "").join("\n");

async function makeClient(fetchFn: DaemonFetch): Promise<Client> {
  const server = createOpenVaultMcpServer({ daemonUrl: "http://127.0.0.1:7077", fetchFn });
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
      const payload = url.includes("/enrollments/enr-1") ? { status: "completed", alias: "stripe", scope: "charges.read" } : { enrollmentId: "enr-1", deeplink: "openvault://add?alias=stripe&scope=charges.read&enrollment=enr-1" };
      return Promise.resolve(new Response(JSON.stringify(payload), { status: 201, headers: { "content-type": "application/json" } }));
    };
    const client = await makeClient(fetchFn);
    try {
      const listed = await client.listTools();
      expect(listed.tools.map((t) => t.name)).toContain("request_enrollment");
      expect(listed.tools.map((t) => t.name)).toContain("enrollment_status");
      const created = (await client.callTool({ name: "request_enrollment", arguments: { alias: "stripe", scope: "charges.read", reason: "need it" } })) as ToolResult;
      expect(created.isError).not.toBe(true);
      expect(textOf(created)).toContain("openvault://add?");
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
});
