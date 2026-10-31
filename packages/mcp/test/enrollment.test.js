import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import { createOpenVaultMcpServer } from "../src/server.js";
const textOf = (r) => (r.content ?? []).map((c) => c.text ?? "").join("\n");
async function makeClient(fetchFn) {
    const server = createOpenVaultMcpServer({ daemonUrl: "http://127.0.0.1:7077", fetchFn });
    const client = new Client({ name: "enroll-test", version: "0.0.1" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await server.connect(st);
    await client.connect(ct);
    return client;
}
describe("MCP enrollment tools (fake daemon)", () => {
    it("request_enrollment returns deeplink + instruction, enrollment_status polls, no secrets", async () => {
        const calls = [];
        const fetchFn = (input, init) => {
            const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
            calls.push({ method: init?.method ?? "GET", url, body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined });
            const payload = url.includes("/enrollments/enr-1") ? { status: "completed", alias: "stripe", scope: "charges.read" } : { enrollmentId: "enr-1", deeplink: "openvault://add?alias=stripe&scope=charges.read&enrollment=enr-1" };
            return Promise.resolve(new Response(JSON.stringify(payload), { status: 201, headers: { "content-type": "application/json" } }));
        };
        const client = await makeClient(fetchFn);
        try {
            const listed = await client.listTools();
            expect(listed.tools.map((t) => t.name)).toContain("request_enrollment");
            expect(listed.tools.map((t) => t.name)).toContain("enrollment_status");
            const created = (await client.callTool({ name: "request_enrollment", arguments: { alias: "stripe", scope: "charges.read", reason: "need it" } }));
            expect(created.isError).not.toBe(true);
            expect(textOf(created)).toContain("openvault://add?");
            expect(textOf(created)).toContain("Show this deeplink");
            expect(JSON.stringify(created)).not.toContain("sk-");
            expect(calls[0]?.body).toMatchObject({ alias: "stripe", scope: "charges.read", reason: "need it" });
            const status = (await client.callTool({ name: "enrollment_status", arguments: { enrollmentId: "enr-1" } }));
            expect(status.structuredContent?.["status"]).toBe("completed");
            const bad = (await client.callTool({ name: "request_enrollment", arguments: { alias: 42 } }));
            expect(bad.isError).toBe(true);
            expect(calls).toHaveLength(2);
        }
        finally {
            await client.close();
        }
    });
});
