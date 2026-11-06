import { Effect, Layer } from "effect";
import { afterEach, describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { VaultStoreTest } from "../../core/src/storage.js";
import { handleVaultRequest, type VaultRequestOptions } from "../src/server.js";
import { makeVaultServiceLive, VaultService, type VaultServiceService } from "../src/service.js";
import { inspectProcess, setTestProcessResolver } from "../src/process-inspector.js";

const CANARY = "[REDACTED]";
const TOKEN = "test-daemon-token-0123456789abcdef";

const BrainLowRisk = Layer.succeed(Brain, {
  assess: () =>
    Effect.succeed({
      risk: "low" as const,
      recommendedScope: "charges.read",
      requireApproval: true,
      explanation: "ok",
    }),
});
const FakeConnector = Layer.succeed(Connector, {
  execute: (_a, _s, secret) => Effect.succeed({ echoedLength: secret.length }),
});

async function makeService(): Promise<VaultServiceService> {
  return Effect.runPromise(
    Effect.gen(function* () {
      const svc = yield* VaultService;
      yield* svc.seedCredential("stripe", "charges.read", CANARY);
      return svc;
    }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: Buffer.alloc(32, 7) })),
      Effect.provide(Layer.mergeAll(VaultStoreTest(Buffer.alloc(32, 7)), BrainLowRisk, FakeConnector)),
    ),
  );
}

const req = {
  agentId: "cursor",
  ide: "Cursor",
  tool: "http",
  alias: "stripe",
  requestedScope: "charges.read",
  reason: "list charges",
};

afterEach(() => {
  setTestProcessResolver(null);
});

describe("process inspector classification", () => {
  it("flags generic runtime binaries", () => {
    setTestProcessResolver(() => "node.exe");
    expect(inspectProcess(1234)).toMatchObject({ ok: true, genericRuntime: true, binary: "node.exe" });
    setTestProcessResolver(() => "bun");
    expect(inspectProcess(1234)).toMatchObject({ ok: true, genericRuntime: true });
    setTestProcessResolver(() => "deno.exe");
    expect(inspectProcess(1234)).toMatchObject({ ok: true, genericRuntime: true });
  });

  it("accepts dedicated agent binaries without the runtime caveat", () => {
    setTestProcessResolver(() => "cursor.exe");
    const res = inspectProcess(1234);
    expect(res.ok).toBe(true);
    expect(res.genericRuntime).toBeUndefined();
    setTestProcessResolver(() => "metavault oss");
    expect(inspectProcess(1234).ok).toBe(true);
  });

  it("denies disallowed binaries and unknown processes", () => {
    setTestProcessResolver(() => "python.exe");
    expect(inspectProcess(1234).ok).toBe(false);
    setTestProcessResolver(() => null);
    expect(inspectProcess(1234)).toMatchObject({ ok: false, reason: "process-not-found" });
  });
});

describe("caller process verification gate", () => {
  async function makeDaemonService(): Promise<VaultServiceService> {
    const service = await makeService();
    await Effect.runPromise(service.updateAgentSecuritySettings({ verifyCallerProcess: true }));
    return service;
  }

  const base: VaultRequestOptions = { daemonToken: TOKEN };

  it("rejects a caller claiming the daemon's own PID", async () => {
    const service = await makeDaemonService();
    const agent = await Effect.runPromise(service.registerAgent("cursor", "Cursor"));
    setTestProcessResolver(() => "cursor.exe");
    const res = await handleVaultRequest(
      service,
      "POST",
      "/request",
      req,
      { ...base, clientPid: process.pid, providedAgentToken: agent.token },
    );
    expect(res.status).toBe(403);
    expect(JSON.stringify(res.body)).toContain("not a valid caller identity");
  });

  it("rejects unaudited generic-runtime callers without an enrolled agent token", async () => {
    const service = await makeDaemonService();
    setTestProcessResolver(() => "node.exe");
    const res = await handleVaultRequest(
      service,
      "POST",
      "/request",
      req,
      { ...base, clientPid: 4242 },
    );
    expect(res.status).toBe(403);
    expect(JSON.stringify(res.body)).toContain("Process verification requires an enrolled, verified agent token.");
  });

  it("admits a generic-runtime caller that presents an enrolled agent token", async () => {
    const service = await makeDaemonService();
    const agent = await Effect.runPromise(service.registerAgent("cursor", "Cursor"));
    setTestProcessResolver(() => "node.exe");
    const res = await handleVaultRequest(
      service,
      "POST",
      "/request",
      req,
      { ...base, clientPid: 4242, providedAgentToken: agent.token },
    );
    expect(res.status).toBe(200);
    expect((res.body as Record<string, unknown>)["status"]).toBe("awaiting-approval");
  });

  it("rejects a dedicated agent binary without an enrolled token (gate on)", async () => {
    const service = await makeDaemonService();
    setTestProcessResolver(() => "cursor.exe");
    const res = await handleVaultRequest(
      service,
      "POST",
      "/request",
      req,
      { ...base, clientPid: 4242 },
    );
    expect(res.status).toBe(403);
    expect(JSON.stringify(res.body)).toContain("Process verification requires an enrolled, verified agent token.");
  });

  it("denies disallowed caller binaries", async () => {
    const service = await makeDaemonService();
    const agent = await Effect.runPromise(service.registerAgent("cursor", "Cursor"));
    setTestProcessResolver(() => "powershell.exe");
    const res = await handleVaultRequest(
      service,
      "POST",
      "/request",
      req,
      { ...base, clientPid: 4242, providedAgentToken: agent.token },
    );
    expect(res.status).toBe(403);
    expect(JSON.stringify(res.body)).toContain("disallowed-binary");
  });

  it("denies when the binary cannot be resolved (fail closed)", async () => {
    const service = await makeDaemonService();
    const agent = await Effect.runPromise(service.registerAgent("cursor", "Cursor"));
    setTestProcessResolver(() => null);
    const res = await handleVaultRequest(
      service,
      "POST",
      "/request",
      req,
      { ...base, clientPid: 4242, providedAgentToken: agent.token },
    );
    expect(res.status).toBe(403);
    expect(JSON.stringify(res.body)).toContain("process-not-found");
  });
});
