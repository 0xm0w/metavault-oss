import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { Effect, Layer } from "effect";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { decryptSecret } from "../../core/src/crypto.js";
import { VaultStore, VaultStoreLive } from "../../core/src/storage.js";
import { handleVaultRequest } from "../../daemon/src/server.js";
import {
  makeVaultServiceLive,
  VaultService,
  type VaultServiceService,
} from "../../daemon/src/service.js";
import { readSecretHidden, runCli, type CliDeps } from "../src/cli.js";

const CANARY = "sk-test-CANARY-9f8e7d6c5b";
const MASTER_KEY = Buffer.alloc(32, 7);
const DAEMON_TOKEN = "cli-test-daemon-token";

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

const workDir = mkdtempSync(join(tmpdir(), "openvault-cli-"));
const dbPath = join(workDir, "vault.db");

let service: VaultServiceService;
let daemonCalls = 0;
const ollamaCalls: { url: string; body: unknown }[] = [];

// In-process stand-in for the vaultd HTTP wire: routes fetch calls to the
// exact handler the node:http server delegates to, so no socket is needed
// (sandboxed shells block localhost listen sockets — see Task 5-7 reports).
const cliFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  const url = new URL(raw);
  if (url.port === "11434") {
    const body: unknown =
      typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
    ollamaCalls.push({ url: raw, body });
    return new Response(JSON.stringify({ status: "success" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }
  daemonCalls += 1;
  const method = init?.method ?? "GET";
  const body: unknown =
    typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
  const headers = (init?.headers ?? {}) as Record<string, string>;
  const providedToken = headers["x-openvault-token"];
  const out = await handleVaultRequest(service, method, url.pathname, body, {
    daemonToken: DAEMON_TOKEN,
    ...(providedToken !== undefined ? { providedToken } : {}),
  });
  return new Response(JSON.stringify(out.body), {
    status: out.status,
    headers: { "content-type": "application/json" },
  });
};

interface Captured {
  readonly deps: CliDeps;
  readonly out: () => string;
  readonly err: () => string;
}

function capture(overrides: Partial<CliDeps> = {}): Captured {
  const outChunks: string[] = [];
  const errChunks: string[] = [];
  const deps: CliDeps = {
    daemonUrl: "http://127.0.0.1:7077",
    fetchFn: cliFetch,
    readSecret: () => Promise.resolve(CANARY),
    masterKey: MASTER_KEY,
    dbPath,
    out: (text) => {
      outChunks.push(text);
    },
    err: (text) => {
      errChunks.push(text);
    },
    ...overrides,
  };
  return { deps, out: () => outChunks.join(""), err: () => errChunks.join("") };
}

async function daemonJson(
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await cliFetch(`http://127.0.0.1:7077${path}`, {
    method,
    headers: { "content-type": "application/json" },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

async function requestPending(): Promise<string> {
  const res = await daemonJson("POST", "/request", {
    agentId: "cursor",
    ide: "Cursor",
    tool: "http",
    alias: "stripe",
    requestedScope: "charges.read",
    reason: "list",
  });
  expect(res.status).toBe(200);
  expect(res.body["status"]).toBe("awaiting-approval");
  const grantId = res.body["grantId"];
  if (typeof grantId !== "string") {
    throw new Error("expected a grantId");
  }
  return grantId;
}

beforeAll(async () => {
  writeFileSync(join(workDir, "openvault.token"), DAEMON_TOKEN, "utf8");
  service = await Effect.runPromise(
    Effect.gen(function* () {
      return yield* VaultService;
    }).pipe(
      Effect.provide(makeVaultServiceLive({ masterKey: MASTER_KEY })),
      Effect.provide(
        Layer.mergeAll(VaultStoreLive(dbPath, MASTER_KEY), BrainLowRisk, FakeConnector),
      ),
    ),
  );
});

afterAll(() => {
  try {
    rmSync(workDir, { recursive: true, force: true });
  } catch {
    // best effort: sqlite handles may still be open on Windows
  }
});

describe("openvault CLI (in-process daemon wire)", () => {
  it("add stores the credential locally; GET /aliases then shows the alias", async () => {
    const cap = capture();
    const callsBefore = daemonCalls;
    const code = await runCli(["add", "stripe", "--scope", "charges.read"], cap.deps);
    expect(code).toBe(0);
    expect(cap.out()).toContain("stripe");
    expect(cap.out()).not.toContain(CANARY);
    expect(cap.err()).not.toContain(CANARY);
    // add is a local Effect (encrypt + vault store), never an HTTP call:
    // the secret must not cross the daemon wire at all.
    expect(daemonCalls).toBe(callsBefore);

    const aliases = await daemonJson("GET", "/aliases");
    expect(aliases.status).toBe(200);
    expect(aliases.body["aliases"]).toContain("stripe");
    expect(JSON.stringify(aliases.body)).not.toContain(CANARY);

    // The stored value is ciphertext that decrypts to the canary under the
    // master key — proving local encryption via core, not plaintext storage.
    const stored = await Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* VaultStore;
        return yield* store.getCredential("stripe");
      }).pipe(Effect.provide(VaultStoreLive(dbPath, MASTER_KEY))),
    );
    expect(stored).toBeDefined();
    expect(stored?.ciphertext).not.toContain(CANARY);
    expect(decryptSecret(MASTER_KEY, stored?.ciphertext ?? "")).toBe(CANARY);

    // And the daemon can use the CLI-added credential immediately.
    const grantId = await requestPending();
    expect(grantId.length).toBeGreaterThan(0);
  });

  it("audit prints marshal decisions with model IDs and never the secret", async () => {
    const cap = capture();
    const code = await runCli(["audit"], cap.deps);
    expect(code).toBe(0);
    const text = cap.out();
    expect(text).toContain("marshal");
    expect(text).toContain("llama3.2:1b");
    expect(text).toContain("ok");
    expect(text).not.toContain(CANARY);
    expect(cap.err()).not.toContain(CANARY);
  });

  it("approve executes once; reuse prints only the tagged error name", async () => {
    const grantId = await requestPending();
    const cap = capture();
    const code = await runCli(["approve", grantId], cap.deps);
    expect(code).toBe(0);
    expect(cap.out()).toContain("executed");
    expect(cap.out()).not.toContain(CANARY);

    const again = capture();
    const second = await runCli(["approve", grantId], again.deps);
    expect(second).toBe(1);
    expect(again.err()).toContain("GrantExpired");
    expect(again.err()).not.toContain(CANARY);
    // Only the tagged name: no daemon message, no stack, no payload echo.
    expect(again.err().trim()).toBe("error: GrantExpired");
  });

  it("revoke round-trips through the daemon and blocks later requests", async () => {
    const cap = capture();
    const code = await runCli(["revoke", "cursor"], cap.deps);
    expect(code).toBe(0);
    expect(cap.out()).toContain("revoked");
    expect(cap.out()).not.toContain(CANARY);

    const after = await daemonJson("POST", "/request", {
      agentId: "cursor",
      ide: "Cursor",
      tool: "http",
      alias: "stripe",
      requestedScope: "charges.read",
      reason: "list",
    });
    expect(after.body["status"]).toBe("denied");
  });

  it("model pull asks Ollama for the default marshal model", async () => {
    const before = ollamaCalls.length;
    const cap = capture();
    const code = await runCli(["model", "pull"], cap.deps);
    expect(code).toBe(0);
    expect(cap.out()).toContain("llama3.2:3b");
    expect(ollamaCalls.length).toBe(before + 1);
    const call = ollamaCalls[ollamaCalls.length - 1];
    expect(call?.url).toContain("/api/pull");
    expect(JSON.stringify(call?.body)).toContain("llama3.2:3b");
  });

  it("model pull failure prints only the tagged error name", async () => {
    const cap = capture({
      fetchFn: () => Promise.reject(new Error("connect ECONNREFUSED 127.0.0.1:11434")),
    });
    const code = await runCli(["model", "pull"], cap.deps);
    expect(code).toBe(1);
    expect(cap.err().trim()).toBe("error: MarshalUnavailable");
    expect(cap.err()).not.toContain("ECONNREFUSED");
  });

  it("an unreachable daemon prints only the tagged error name", async () => {
    const cap = capture({
      fetchFn: () => Promise.reject(new Error("connect ECONNREFUSED 127.0.0.1:7077")),
    });
    const code = await runCli(["audit"], cap.deps);
    expect(code).toBe(1);
    expect(cap.err().trim()).toBe("error: DaemonError");
    expect(cap.err()).not.toContain("ECONNREFUSED");
  });

  it("rejects an empty secret without storing anything", async () => {
    const cap = capture({ readSecret: () => Promise.resolve("") });
    const code = await runCli(["add", "empty-alias", "--scope", "charges.read"], cap.deps);
    expect(code).toBe(2);
    expect(cap.err()).toContain("UsageError");
    const aliases = await daemonJson("GET", "/aliases");
    expect(aliases.body["aliases"]).not.toContain("empty-alias");
  });

  it("usage errors exit 2 with only the tagged error name", async () => {
    const noArgs = capture();
    expect(await runCli([], noArgs.deps)).toBe(2);
    expect(noArgs.err()).toContain("UsageError");

    const unknown = capture();
    expect(await runCli(["bogus"], unknown.deps)).toBe(2);
    expect(unknown.err()).toContain("UsageError");

    const missingScope = capture();
    expect(await runCli(["add", "stripe"], missingScope.deps)).toBe(2);
    expect(missingScope.err()).toContain("UsageError");

    const missingGrant = capture();
    expect(await runCli(["approve"], missingGrant.deps)).toBe(2);
    expect(missingGrant.err()).toContain("UsageError");

    for (const cap of [noArgs, unknown, missingScope, missingGrant]) {
      expect(cap.out() + cap.err()).not.toContain(CANARY);
    }
  });

  it("init creates the vault and shows a fresh master key exactly once", async () => {
    const initDir = mkdtempSync(join(tmpdir(), "openvault-cli-init-"));
    const initDb = join(initDir, "vault.db");
    try {
      const cap = capture({ dbPath: initDb, masterKey: undefined });
      const code = await runCli(["init"], cap.deps);
      expect(code).toBe(0);
      expect(cap.out()).toContain("initialized");
      expect(existsSync(initDb)).toBe(true);
      const match = /master key \(shown once\): ([A-Za-z0-9+/]+={0,2})/.exec(cap.out());
      expect(match).not.toBeNull();
      expect(Buffer.from(match?.[1] ?? "", "base64").length).toBe(32);
      expect(cap.out()).not.toContain(CANARY);

      // With an existing key, init reuses it and never prints it.
      const again = capture({ dbPath: initDb });
      const second = await runCli(["init"], again.deps);
      expect(second).toBe(0);
      expect(again.out()).toContain("initialized");
      expect(again.out()).not.toContain(MASTER_KEY.toString("base64"));
    } finally {
      try {
        rmSync(initDir, { recursive: true, force: true });
      } catch {
        // best effort, as above
      }
    }
  });

  it("approve sends the daemon token header from deps", async () => {
    let seenToken: string | undefined;
    const cap = capture({
      daemonToken: "cli-deps-token",
      fetchFn: (_input, init) => {
        const headers = init?.headers as Record<string, string> | undefined;
        seenToken = headers?.["x-openvault-token"];
        return Promise.resolve(
          new Response(JSON.stringify({ status: "executed", result: {} }), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        );
      },
    });
    const code = await runCli(["approve", "grant-1"], cap.deps);
    expect(code).toBe(0);
    expect(seenToken).toBe("cli-deps-token");
  });

  it("approve falls back to the token file next to the DB path", async () => {
    const saved = process.env["OPENVAULT_DAEMON_TOKEN"];
    delete process.env["OPENVAULT_DAEMON_TOKEN"];
    const tokenPath = join(workDir, "openvault.token");
    writeFileSync(tokenPath, "file-token-value", "utf8");
    try {
      let seenToken: string | undefined;
      const cap = capture({
        fetchFn: (_input, init) => {
          const headers = init?.headers as Record<string, string> | undefined;
          seenToken = headers?.["x-openvault-token"];
          return Promise.resolve(
            new Response(JSON.stringify({ status: "executed", result: {} }), {
              status: 200,
              headers: { "content-type": "application/json" },
            }),
          );
        },
      });
      const code = await runCli(["approve", "grant-1"], cap.deps);
      expect(code).toBe(0);
      expect(seenToken).toBe("file-token-value");
    } finally {
      try {
        rmSync(tokenPath, { force: true });
      } catch {
        // best effort
      }
      if (saved === undefined) {
        delete process.env["OPENVAULT_DAEMON_TOKEN"];
      } else {
        process.env["OPENVAULT_DAEMON_TOKEN"] = saved;
      }
    }
  });

  it("readSecretHidden rejects when input closes (EOF) without a newline", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    output.resume();
    const pending = readSecretHidden("Secret: ", input, output);
    input.end();
    await expect(pending).rejects.toThrow();
  });

  it("readSecretHidden rejects on EOF even after partial input without a newline", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    output.resume();
    const pending = readSecretHidden("Secret: ", input, output);
    input.write("partial-secret-without-enter");
    input.end();
    await expect(pending).rejects.toThrow();
  });

  it("readSecretHidden resolves the secret without echoing it", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    let echoed = "";
    output.on("data", (chunk: Buffer) => {
      echoed += chunk.toString("utf8");
    });
    const pending = readSecretHidden("Secret: ", input, output);
    input.write(`${CANARY}\n`);
    const value = await pending;
    expect(value).toBe(CANARY);
    expect(echoed).toContain("Secret:");
    expect(echoed).not.toContain(CANARY);
  });

  it("openvault import imports .env file into encrypted vault storage (#17)", async () => {
    const envFile = join(workDir, "test.env");
    writeFileSync(
      envFile,
      `
# Test environment
STRIPE_API_KEY=sk_test_import_stripe_999
OPENAI_API_KEY=sk-proj-import-openai-888
`,
      "utf8",
    );

    const c = capture();
    const code = await runCli(["import", envFile], c.deps);
    expect(code).toBe(0);
    expect(c.out()).toContain("imported 2 credentials");
    expect(c.out()).toContain("STRIPE_API_KEY -> alias: stripe");
    expect(c.out()).toContain("OPENAI_API_KEY -> alias: openai");
    // Secrets must NEVER be leaked in stdout
    expect(c.out()).not.toContain("sk_test_import_stripe_999");
    expect(c.out()).not.toContain("sk-proj-import-openai-888");

    // Verify stored in vault
    const store = Effect.runSync(
      VaultStore.pipe(
        Effect.flatMap((s) => s.getCredential("stripe")),
        Effect.provide(VaultStoreLive(dbPath, MASTER_KEY)),
      ),
    );
    expect(store).toBeDefined();
    if (store === undefined) {
      throw new Error("expected store record");
    }
    expect(store.scopeCeiling).toBe("charges.read");
    const decrypted = decryptSecret(MASTER_KEY, store.ciphertext);
    expect(decrypted).toBe("sk_test_import_stripe_999");
  });

  it("openvault run injects decrypted secrets in-memory into child process (#17)", async () => {
    let capturedEnv: NodeJS.ProcessEnv | undefined;
    let commandSpawned = "";

    const mockSpawn = (
      command: string,
      _args: readonly string[],
      options: { readonly env: NodeJS.ProcessEnv },
    ) => {
      commandSpawned = command;
      capturedEnv = options.env;
      return {
        on: (event: string, cb: (code: number | null) => void) => {
          if (event === "close") {
            cb(0);
          }
        },
      };
    };

    const c = capture({ spawnFn: mockSpawn });
    const code = await runCli(["run", "--", "npm", "run", "dev"], c.deps);
    expect(code).toBe(0);
    expect(commandSpawned).toBe("npm");
    expect(capturedEnv).toBeDefined();
    if (capturedEnv === undefined) {
      throw new Error("expected capturedEnv");
    }
    expect(capturedEnv["STRIPE_API_KEY"]).toBe("sk_test_import_stripe_999");
    expect(capturedEnv["OPENAI_API_KEY"]).toBe("sk-proj-import-openai-888");
  });
});
