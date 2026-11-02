import { describe, expect, it, vi, beforeEach } from "vitest";
import { evaluateGeminiNano, isGeminiNanoAvailable } from "../src/lib/gemini-nano.js";
import { VaultClient } from "../src/lib/vault-client.js";

describe("Browser Extension Client & Gemini Nano Bridge", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("checks Gemini Nano availability fallback when outside browser", async () => {
    const available = await isGeminiNanoAvailable();
    expect(available).toBe(false);
  });

  it("evaluates fallback decision via Gemini Nano module", async () => {
    const decision = await evaluateGeminiNano("Test agent capability request");
    expect(decision.risk).toBe("low");
    expect(decision.explanation).toContain("Google Gemini Nano");
  });

  it("handles offline daemon gracefully in VaultClient", async () => {
    const client = new VaultClient("http://127.0.0.1:9999"); // Non-existent port
    const healthy = await client.health();
    expect(healthy).toBe(false);

    const pending = await client.getPending();
    expect(pending).toEqual([]);
  });

  it("parses pending grants correctly when daemon returns data", async () => {
    const mockPending = [
      {
        grantId: "grant-123",
        agentId: "cursor-agent",
        ide: "Cursor",
        alias: "stripe",
        requestedScope: "charges.read",
        reason: "read customer charges",
        createdAt: Date.now(),
      },
    ];

    vi.spyOn(globalThis, "fetch").mockImplementationOnce(() =>
      Promise.resolve(new Response(JSON.stringify(mockPending), { status: 200 })),
    );

    const client = new VaultClient("http://127.0.0.1:7077");
    const pending = await client.getPending();
    expect(pending.length).toBe(1);
    expect(pending[0]?.grantId).toBe("grant-123");
    expect(pending[0]?.alias).toBe("stripe");
  });

  it("approves grant via POST /grants/approve", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementationOnce(() =>
      Promise.resolve(new Response(JSON.stringify({ ok: true }), { status: 200 })),
    );

    const client = new VaultClient("http://127.0.0.1:7077");
    const ok = await client.approveGrant("grant-123");
    expect(ok).toBe(true);
  });
});
