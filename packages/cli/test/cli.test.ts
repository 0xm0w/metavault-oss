import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { Effect, Layer } from "effect";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Brain } from "../../brain/src/brain.js";
import { Connector } from "../../core/src/connector.js";
import { decryptSecret } from "../../core/src/crypto.js";
import { unwrapMasterKey } from "../../core/src/keywrap.js";
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

const workDir = mkdtempSync(join(tmpdir(), "metavault-cli-"));
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
  const providedToken = headers["x-metavault-token"];
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
  writeFileSync(join(workDir, "metavault.token"), DAEMON_TOKEN, "utf8");
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

describe("metavault CLI (in-process daemon wire)", () => {
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
    expect(text).toContain("muse-glimmer:30b");
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
    expect(cap.out()).toContain("muse-glimmer:30b");
    expect(ollamaCalls.length).toBe(before + 1);
    const call = ollamaCalls[ollamaCalls.length - 1];
    expect(call?.url).toContain("/api/pull");
    expect(JSON.stringify(call?.body)).toContain("muse-glimmer:30b");
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

  it("init seals a fresh master key with a passphrase and never prints it", async () => {
    const initDir = mkdtempSync(join(tmpdir(), "metavault-cli-init-"));
    const initDb = join(initDir, "vault.db");
    const noKeychain = { retrieve: () => null, store: () => false, remove: () => false };
    try {
      const cap = capture({
        dbPath: initDb,
        masterKey: undefined,
        keychain: noKeychain,
        readSecret: () => Promise.resolve("correct horse battery staple"),
        keyWrapOptions: { params: { N: 2 ** 12, r: 8, p: 1 }, allowWeakParams: true },
      });
      const code = await runCli(["init"], cap.deps);
      expect(code).toBe(0);
      expect(cap.out()).toContain("initialized");
      expect(cap.out()).toContain("sealed with your passphrase (scrypt)");
      expect(cap.out()).not.toContain("shown once");
      expect(existsSync(initDb)).toBe(true);
      const keyFile = join(initDir, "metavault.key.json");
      expect(existsSync(keyFile)).toBe(true);
      const wrapped = JSON.parse(readFileSync(keyFile, "utf8")) as { kdf: string };
      expect(wrapped.kdf).toBe("scrypt");

      // Second init reuses the protected key and asks nothing.
      const again = capture({ dbPath: initDb, masterKey: undefined, keychain: noKeychain });
      expect(await runCli(["init"], again.deps)).toBe(0);
      expect(again.out()).toContain("existing passphrase-protected key reused");
    } finally {
      try {
        rmSync(initDir, { recursive: true, force: true });
      } catch {
        // best effort, as above
      }
    }
  });

  it("init --legacy-keychain keeps the old shown-once behaviour", async () => {
    const initDir = mkdtempSync(join(tmpdir(), "metavault-cli-init-legacy-"));
    const initDb = join(initDir, "vault.db");
    let stored: Buffer | null = null;
    try {
      const cap = capture({
        dbPath: initDb,
        masterKey: undefined,
        keychain: { retrieve: () => stored, store: (k) => { stored = Buffer.from(k); return true; }, remove: () => true },
      });
      expect(await runCli(["init", "--legacy-keychain"], cap.deps)).toBe(0);
      const match = /master key \(shown once\): ([A-Za-z0-9+/]+={0,2})/.exec(cap.out());
      expect(match).not.toBeNull();
      expect(Buffer.from(match?.[1] ?? "", "base64").length).toBe(32);
      expect(existsSync(join(initDir, "metavault.key.json"))).toBe(false);
    } finally {
      rmSync(initDir, { recursive: true, force: true });
    }
  });

  it("key protect migrates a legacy keychain key and deletes the keychain copy", async () => {
    const dir = mkdtempSync(join(tmpdir(), "metavault-cli-protect-"));
    const db = join(dir, "vault.db");
    let stored: Buffer | null = Buffer.alloc(32, 5);
    const legacy = Buffer.alloc(32, 5);
    const phrase = "migration passphrase 1";
    const keychain = { retrieve: () => stored, store: () => true, remove: () => { stored = null; return true; } };
    const fast = { params: { N: 2 ** 12, r: 8, p: 1 }, allowWeakParams: true } as const;
    try {
      const cap = capture({ dbPath: db, masterKey: undefined, keychain, readSecret: () => Promise.resolve(phrase), keyWrapOptions: fast });
      expect(await runCli(["key", "protect"], cap.deps)).toBe(0);
      expect(cap.out()).toContain("legacy unwrapped keychain copy deleted");
      expect(stored).toBeNull();
      const wrapped = JSON.parse(readFileSync(join(dir, "metavault.key.json"), "utf8")) as Parameters<typeof unwrapMasterKey>[0];
      expect((await unwrapMasterKey(wrapped, phrase)).equals(legacy)).toBe(true);

      const status = capture({ dbPath: db, masterKey: undefined, keychain });
      expect(await runCli(["key", "status"], status.deps)).toBe(0);
      expect(status.out()).toContain("passphrase-protected key: yes (scrypt");
      expect(status.out()).toContain("legacy keychain key present: no");

      const twice = capture({ dbPath: db, masterKey: undefined, keychain, readSecret: () => Promise.resolve(phrase), keyWrapOptions: fast });
      expect(await runCli(["key", "protect"], twice.deps)).toBe(2);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("init rejects mismatched or short passphrases", async () => {
    const dir = mkdtempSync(join(tmpdir(), "metavault-cli-short-"));
    const noKeychain = { retrieve: () => null, store: () => false, remove: () => false };
    try {
      const short = capture({ dbPath: join(dir, "a.db"), masterKey: undefined, keychain: noKeychain, readSecret: () => Promise.resolve("short") });
      expect(await runCli(["init"], short.deps)).toBe(2);
      let n = 0;
      const mismatch = capture({
        dbPath: join(dir, "b.db"),
        masterKey: undefined,
        keychain: noKeychain,
        readSecret: () => Promise.resolve(n++ === 0 ? "first passphrase ok" : "second passphrase ok"),
      });
      expect(await runCli(["init"], mismatch.deps)).toBe(2);
      expect(existsSync(join(dir, "metavault.key.json"))).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("add-card sends the card to the daemon and prints only brand + last 4", async () => {
    const answers = ["4242 4242 4242 4242", "Ada Lovelace", "12/39", "123"];
    let i = 0;
    const cap = capture({ readSecret: () => Promise.resolve(answers[i++] ?? "") });
    expect(await runCli(["add-card", "corp-visa"], cap.deps)).toBe(0);
    expect(cap.out()).toContain("added card corp-visa: visa •••• 4242");
    expect(cap.out()).not.toContain("4242 4242");
    expect(cap.out()).not.toContain("Ada");
    const aliases = await daemonJson("GET", "/aliases");
    const text = JSON.stringify(aliases.body);
    expect(text).toContain("corp-visa");
    expect(text).not.toContain("4242424242424242");
    expect(text).not.toContain("Ada Lovelace");
    expect(text).not.toContain("2039");
  });

  it("approve sends the daemon token header from deps", async () => {
    let seenToken: string | undefined;
    const cap = capture({
      daemonToken: "cli-deps-token",
      fetchFn: (_input, init) => {
        const headers = init?.headers as Record<string, string> | undefined;
        seenToken = headers?.["x-metavault-token"];
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
    const saved = process.env["METAVAULT_DAEMON_TOKEN"];
    delete process.env["METAVAULT_DAEMON_TOKEN"];
    const tokenPath = join(workDir, "metavault.token");
    writeFileSync(tokenPath, "file-token-value", "utf8");
    try {
      let seenToken: string | undefined;
      const cap = capture({
        fetchFn: (_input, init) => {
          const headers = init?.headers as Record<string, string> | undefined;
          seenToken = headers?.["x-metavault-token"];
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
        delete process.env["METAVAULT_DAEMON_TOKEN"];
      } else {
        process.env["METAVAULT_DAEMON_TOKEN"] = saved;
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

  it("metavault import imports .env file into encrypted vault storage (#17)", async () => {
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

  it("metavault run injects decrypted secrets in-memory into child process (#17)", async () => {
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
