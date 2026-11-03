import { Effect, Layer } from "effect";
import { describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { createVaultHttpServer } from "../src/server.js";
import { makeVaultServiceLive, VaultService } from "../src/service.js";

const MASTER_KEY = Buffer.alloc(32, 7);
const BrainLowRisk = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({
      risk: "low" as const,
      recommendedScope: "charges.read",
      requireApproval: true,
      explanation: "safe test read",
    }),
});
const FakeConnector = Layer.succeed(Connector, {
  execute: (_alias, scope) => Effect.succeed({ scope }),
});

async function makeTestDaemon() {
  const service = await Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* VaultService;
      yield* svc.seedCredential("stripe", "charges.read", "sk_test_123");
      return svc;
    }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: MASTER_KEY })),
      Effect.provide(Layer.mergeAll(VaultStoreTest(MASTER_KEY), BrainLowRisk, FakeConnector)),
    ),
  );
  const cursor = await Effect.runPromise(service.registerAgent("cursor", "Cursor"));
  const server = createVaultHttpServer(service, { daemonToken: "test-daemon-token" });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  const base = `http://127.0.0.1:${String(address.port)}`;
  return {
    base,
    service,
    cursorToken: cursor.token,
    close: () => new Promise<void>((resolve) => server.close(() => { resolve(); })),
  };
}

describe("Agent Token Verification & Anti-Spoofing", () => {
  it("lists default agents without exposing stored bearer tokens", async () => {
    const daemon = await makeTestDaemon();
    try {
      // Agent tokens are served only via the token-guarded GET /agents route.
      const res = await fetch(`${daemon.base}/agents`, {
        headers: { "x-metavault-token": "test-daemon-token" },
      });
      const body = await res.json() as { id: string; name: string; token: string; revoked: boolean }[];
      expect(body.length).toBeGreaterThanOrEqual(4);
      const cursor = body.find((a) => a.id === "cursor");
      expect(cursor).toBeDefined();
      expect(cursor?.name).toBe("Cursor");
      expect(cursor?.token).toBe("");
      expect(daemon.cursorToken).toMatch(/^ov_agent_cursor_[0-9a-f]{32}$/);
      expect(cursor?.revoked).toBe(false);
    } finally {
      await daemon.close();
    }
  });

  it("authenticates legitimate agent via bearer token and forces authoritative identity", async () => {
    const daemon = await makeTestDaemon();
    try {
      // Get cursor's token via the token-guarded route
      const agents = await (await fetch(`${daemon.base}/agents`, {
        headers: { "x-metavault-token": "test-daemon-token" },
      })).json() as { id: string; token: string }[];
      const cursorToken = daemon.cursorToken;
      expect(agents.every(a => a.token === "")).toBe(true);

      // Caller attempts to claim agentId: "attacker" or "spoofed" in the body, but presents Cursor's token
      const res = await fetch(`${daemon.base}/request`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-metavault-agent-token": cursorToken,
        },
        body: JSON.stringify({
          agentId: "attacker-spoofed-name",
          ide: "Cursor",
          tool: "http",
          alias: "stripe",
          requestedScope: "charges.read",
          reason: "audited call",
        }),
      });
      expect(res.status).toBe(200);

      // Verify pending approval: agentId MUST be authoritative "cursor", not the spoofed string!
      const pendingRes = await fetch(`${daemon.base}/pending`, {
        headers: { "x-metavault-token": "test-daemon-token" },
      });
      const pending = await pendingRes.json() as { approvals: { agentId: string; verified: boolean }[] };
      expect(pending.approvals.length).toBe(1);
      expect(pending.approvals[0]?.agentId).toBe("cursor");
      expect(pending.approvals[0]?.verified).toBe(true);
    } finally {
      await daemon.close();
    }
  });

  it("rejects invalid or forged agent tokens with 401 Unauthorized", async () => {
    const daemon = await makeTestDaemon();
    try {
      const res = await fetch(`${daemon.base}/request`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-metavault-agent-token": "ov_agent_forged_invalid_token",
        },
        body: JSON.stringify({
          agentId: "cursor",
          ide: "Cursor",
          tool: "http",
          alias: "stripe",
          requestedScope: "charges.read",
          reason: "forged call",
        }),
      });
      expect(res.status).toBe(401);
      const body = await res.json() as { error: { message: string } };
      expect(body.error.message).toBe("invalid agent token");
    } finally {
      await daemon.close();
    }
  });

  it("marks requests without tokens as unverified and blocks standing approval bypass", async () => {
    const daemon = await makeTestDaemon();
    try {
      // 1. First, create a verified request with Cursor's real token and approve with always-allow
      const agents = await (await fetch(`${daemon.base}/agents`, {
        headers: { "x-metavault-token": "test-daemon-token" },
      })).json() as { id: string; token: string }[];
      const cursorToken = daemon.cursorToken;
      expect(agents.every(a => a.token === "")).toBe(true);

      await fetch(`${daemon.base}/request`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-metavault-agent-token": cursorToken,
        },
        body: JSON.stringify({
          agentId: "cursor",
          ide: "Cursor",
          tool: "http",
          alias: "stripe",
          requestedScope: "charges.read",
          reason: "initial legitimate request",
        }),
      });

      const pendingRes = await fetch(`${daemon.base}/pending`, {
        headers: { "x-metavault-token": "test-daemon-token" },
      });
      const grantId = (await pendingRes.json() as { approvals: { grantId: string }[] }).approvals[0]?.grantId ?? "";

      // Human grants standing approval for cursor
      const approveRes = await fetch(`${daemon.base}/approve-always`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-metavault-token": "test-daemon-token",
        },
        body: JSON.stringify({ grantId }),
      });
      expect(approveRes.status).toBe(200);

      // 2. An attacker process tries to spoof cursor WITHOUT a token to steal the standing approval
      const spoofRes = await fetch(`${daemon.base}/request`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          agentId: "cursor", // Claiming to be cursor!
          ide: "Cursor",
          tool: "http",
          alias: "stripe",
          requestedScope: "charges.read",
          reason: "attacker trying to use standing approval silently",
        }),
      });
      // MUST NOT be auto-executed! Must be routed to awaiting-approval with verified: false
      const spoofBody = await spoofRes.json() as { status: string };
      expect(spoofBody.status).toBe("awaiting-approval");

      const checkPending = await (await fetch(`${daemon.base}/pending`, {
        headers: { "x-metavault-token": "test-daemon-token" },
      })).json() as { approvals: { agentId: string; verified: boolean }[] };

      expect(checkPending.approvals.length).toBe(1);
      expect(checkPending.approvals[0]?.agentId).toBe("cursor");
      expect(checkPending.approvals[0]?.verified).toBe(false); // Flagged as UNVERIFIED!
    } finally {
      await daemon.close();
    }
  });

  it("revoking an agent invalidates its token immediately", async () => {
    const daemon = await makeTestDaemon();
    try {
      const agents = await (await fetch(`${daemon.base}/agents`, {
        headers: { "x-metavault-token": "test-daemon-token" },
      })).json() as { id: string; token: string }[];
      const cursorToken = daemon.cursorToken;
      expect(agents.every(a => a.token === "")).toBe(true);

      // Revoke cursor
      const revokeRes = await fetch(`${daemon.base}/agents/revoke`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-metavault-token": "test-daemon-token",
        },
        body: JSON.stringify({ target: "cursor" }),
      });
      expect(revokeRes.status).toBe(200);

      // Attempting request with revoked token fails with 403
      const reqRes = await fetch(`${daemon.base}/request`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-metavault-agent-token": cursorToken,
        },
        body: JSON.stringify({
          agentId: "cursor",
          ide: "Cursor",
          tool: "http",
          alias: "stripe",
          requestedScope: "charges.read",
          reason: "post-revoke request",
        }),
      });
      expect(reqRes.status).toBe(403);
    } finally {
      await daemon.close();
    }
  });
});

describe("managed agent lifecycle", () => {
  it("guards creation/rotation, validates identity, returns token once, rejects old token and cancels grants on rotation", async () => {
    const daemon = await makeTestDaemon();
    const call = (path: string, body: unknown, auth = true) => fetch(`${daemon.base}${path}`, {method:"POST",headers:{"content-type":"application/json",...(auth?{"x-metavault-token":"test-daemon-token"}:{})},body:JSON.stringify(body)});
    try {
      expect((await call("/agents",{id:"test",name:"Test"},false)).status).toBe(401);
      expect((await call("/agents/rotate",{id:"cursor",name:"Cursor"},false)).status).toBe(401);
      expect((await call("/agents",{id:"../bad",name:"Bad"})).status).toBe(400);
      const created = await call("/agents",{id:"custom",name:"Custom"});
      const first = await created.json() as {token:string}; expect(created.status).toBe(200); expect(first.token).toMatch(/^ov_agent_custom_[a-f0-9]{32}$/);
      expect((await call("/agents",{id:"custom",name:"Custom"})).status).not.toBe(200);
      const request = (token:string) => fetch(`${daemon.base}/request`,{method:"POST",headers:{"content-type":"application/json","x-metavault-agent-token":token},body:JSON.stringify({agentId:"spoof",ide:"Test",tool:"http",alias:"stripe",requestedScope:"charges.read",reason:"test"})});
      const pending = await (await request(first.token)).json() as {grantId:string};
      const rotated = await (await call("/agents/rotate",{id:"custom",name:"Custom"})).json() as {token:string};
      expect(rotated.token).not.toBe(first.token);
      expect((await request(first.token)).status).toBe(401);
      expect((await call("/approve",{grantId:pending.grantId})).status).not.toBe(200);
      expect((await request(rotated.token)).status).toBe(200);
      await call("/agents/revoke",{target:"custom"});
      expect((await request(rotated.token)).status).toBe(403);
      const recovered = await (await call("/agents/rotate",{id:"custom",name:"Custom"})).json() as {token:string};
      const recoveredRequest = await request(recovered.token); expect(recoveredRequest.status).toBe(200);
      expect((await recoveredRequest.json() as {status:string}).status).toBe("awaiting-approval");
      const listed = await (await fetch(`${daemon.base}/agents`,{headers:{"x-metavault-token":"test-daemon-token"}})).text();
      expect(listed).not.toContain(first.token); expect(listed).not.toContain(rotated.token); expect(listed).not.toContain(recovered.token);
    } finally {await daemon.close();}
  });
});

it("rotation removes a previously approved standing grant", async () => {
  const daemon = await makeTestDaemon();
  const auth = {"content-type":"application/json","x-metavault-token":"test-daemon-token"};
  const request = (token:string) => fetch(`${daemon.base}/request`, {method:"POST", headers:{"content-type":"application/json","x-metavault-agent-token":token}, body:JSON.stringify({agentId:"cursor",ide:"Cursor",tool:"http",alias:"stripe",requestedScope:"charges.read",reason:"read"})});
  try {
    const first = await (await request(daemon.cursorToken)).json() as {grantId:string};
    expect((await fetch(`${daemon.base}/approve-always`, {method:"POST",headers:auth,body:JSON.stringify({grantId:first.grantId})})).status).toBe(200);
    const before = await (await fetch(`${daemon.base}/policies`)).json() as {standingApprovals:unknown[]};
    expect(before.standingApprovals).toHaveLength(1);
    const rotated = await (await fetch(`${daemon.base}/agents/rotate`,{method:"POST",headers:auth,body:JSON.stringify({id:"cursor",name:"Cursor"})})).json() as {token:string};
    const after = await (await fetch(`${daemon.base}/policies`)).json() as {standingApprovals:unknown[]};
    expect(after.standingApprovals).toHaveLength(0);
    expect((await (await request(rotated.token)).json() as {status:string}).status).toBe("awaiting-approval");
  } finally {await daemon.close();}
});
