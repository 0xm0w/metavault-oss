import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Effect, Fiber } from "effect";
import { afterEach, describe, expect, it } from "vitest";
import { Connector } from "../../core/src/connector.js";
import {
  ConnectorLive,
  DEFAULT_CONNECTOR_PRESETS,
  executeHttp,
  makeConnectorLive,
  type ToolRoutes,
} from "../src/http.js";

const SECRET = "[REDACTED]";

interface MockServer {
  readonly url: string;
  readonly close: () => Promise<void>;
}

const servers: Server[] = [];

async function startServer(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<MockServer> {
  const srv = createServer(handler);
  servers.push(srv);
  await new Promise<void>((resolve) => {
    srv.listen(0, "127.0.0.1", () => {
      resolve();
    });
  });
  const address = srv.address();
  if (address === null || typeof address === "string") {
    throw new Error("mock server has no port");
  }
  return {
    url: `http://127.0.0.1:${String(address.port)}`,
    close: () =>
      new Promise<void>((resolve) => {
        srv.closeAllConnections();
        srv.close(() => {
          resolve();
        });
      }),
  };
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (srv) =>
        new Promise<void>((resolve) => {
          srv.closeAllConnections();
          srv.close(() => {
            resolve();
          });
        }),
    ),
  );
});

describe("executeHttp", () => {
  it("injects the Bearer [REDACTED] server-side and returns only the result", async () => {
    let seenAuth = "";
    const mock = await startServer((req, res) => {
      seenAuth = req.headers.authorization ?? "";
      res.end(JSON.stringify({ ok: true, charges: 5 }));
    });
    const out = await Effect.runPromise(
      executeHttp({ url: `${mock.url}/charges`, method: "GET", secret: SECRET }),
    );
    expect(seenAuth).toBe(`Bearer ${SECRET}`);
    expect(out).toEqual({ status: 200, data: { ok: true, charges: 5 } });
    expect(JSON.stringify(out)).not.toContain(SECRET);
    await mock.close();
  });

  it("uses headerName when provided, still as a Bearer [REDACTED]", async () => {
    let seen = "";
    const mock = await startServer((req, res) => {
      const header = req.headers["x-api-key"];
      seen = typeof header === "string" ? header : "";
      res.end(JSON.stringify({ ok: true }));
    });
    const out = await Effect.runPromise(
      executeHttp({ url: `${mock.url}/x`, method: "GET", secret: SECRET, headerName: "X-Api-Key" }),
    );
    expect(seen).toBe(`Bearer ${SECRET}`);
    expect(out.status).toBe(200);
    expect(JSON.stringify(out)).not.toContain(SECRET);
    await mock.close();
  });

  it("sends a JSON body for non-GET methods and parses the response", async () => {
    let seenBody = "";
    let seenMethod = "";
    const mock = await startServer((req, res) => {
      seenMethod = req.method ?? "";
      req.on("data", (chunk: Buffer) => {
        seenBody += chunk.toString("utf8");
      });
      req.on("end", () => {
        res.end(JSON.stringify({ created: true }));
      });
    });
    const out = await Effect.runPromise(
      executeHttp({
        url: `${mock.url}/charges`,
        method: "POST",
        secret: SECRET,
        body: { amount: 42 },
      }),
    );
    expect(seenMethod).toBe("POST");
    expect(JSON.parse(seenBody) as unknown).toEqual({ amount: 42 });
    expect(out).toEqual({ status: 200, data: { created: true } });
    expect(JSON.stringify(out)).not.toContain(SECRET);
    await mock.close();
  });

  it("fails non-2xx as ConnectorFailed carrying only the status, never the secret or body", async () => {
    const mock = await startServer((_req, res) => {
      res.writeHead(502, { "content-type": "application/json", "x-secret-echo": SECRET });
      res.end(JSON.stringify({ error: SECRET }));
    });
    const err = await Effect.runPromise(
      executeHttp({ url: `${mock.url}/charges`, method: "GET", secret: SECRET }).pipe(Effect.flip),
    );
    expect(err._tag).toBe("ConnectorFailed");
    expect(err.status).toBe(502);
    expect(JSON.stringify(err)).not.toContain(SECRET);
    await mock.close();
  });

  it("fails transport errors as ConnectorFailed without the secret", async () => {
    const mock = await startServer((_req, res) => {
      res.end("{}");
    });
    const url = `${mock.url}/charges`;
    await mock.close();
    const err = await Effect.runPromise(
      executeHttp({ url, method: "GET", secret: SECRET }).pipe(Effect.flip),
    );
    expect(err._tag).toBe("ConnectorFailed");
    expect(err.status).toBeUndefined();
    expect(JSON.stringify(err)).not.toContain(SECRET);
  });

  it("is interruptible so revoke/TTL can cancel an in-flight call", async () => {
    const mock = await startServer((_req, res) => {
      setTimeout(() => {
        res.end(JSON.stringify({ late: true }));
      }, 1_000);
    });
    const fiber = await Effect.runPromise(
      Effect.fork(executeHttp({ url: `${mock.url}/slow`, method: "GET", secret: SECRET })),
    );
    await new Promise<void>((resolve) => {
      setTimeout(resolve, 50);
    });
    const started = Date.now();
    const exit = await Effect.runPromise(Fiber.interrupt(fiber));
    expect(exit._tag).toBe("Failure");
    expect(Date.now() - started).toBeLessThan(900);
    await mock.close();
  });
});

describe("ConnectorLive", () => {
  it("has stripe/github presets by default", () => {
    expect(DEFAULT_CONNECTOR_PRESETS["stripe"]).toBe("https://api.stripe.com/v1/charges");
    expect(DEFAULT_CONNECTOR_PRESETS["github"]).toBe("https://api.github.com/user/repos");
    expect(ConnectorLive).toBeDefined();
  });

  it("executes a preset alias against its mapped URL with the secret injected", async () => {
    let seenAuth = "";
    const mock = await startServer((req, res) => {
      seenAuth = req.headers.authorization ?? "";
      res.end(JSON.stringify({ ok: true, charges: 5 }));
    });
    const out = await Effect.runPromise(
      Effect.gen(function* () {
        const connector = yield* Connector;
        return yield* connector.execute("stripe", "charges.read", SECRET);
      }).pipe(Effect.provide(makeConnectorLive({ stripe: `${mock.url}/charges` }))),
    );
    expect(seenAuth).toBe(`Bearer ${SECRET}`);
    expect(out).toEqual({ status: 200, data: { ok: true, charges: 5 } });
    expect(JSON.stringify(out)).not.toContain(SECRET);
    await mock.close();
  });

  it("fails an unmapped alias without leaking the secret", async () => {
    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const connector = yield* Connector;
        return yield* connector.execute("nope", "charges.read", SECRET);
      }).pipe(Effect.provide(makeConnectorLive({ stripe: "http://127.0.0.1:1/charges" })), Effect.flip),
    );
    // Core Connector contract (packages/core/src/connector.ts) only admits
    // ConnectorFailed; the brief's UnknownAlias is surfaced in its message/alias.
    expect(err._tag).toBe("ConnectorFailed");
    expect(err.alias).toBe("nope");
    expect(JSON.stringify(err)).not.toContain(SECRET);
  });

  it("maps preset HTTP failures to ConnectorFailed carrying only the status", async () => {
    const mock = await startServer((_req, res) => {
      res.writeHead(500, { "x-secret-echo": SECRET });
      res.end(SECRET);
    });
    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const connector = yield* Connector;
        return yield* connector.execute("stripe", "charges.read", SECRET);
      }).pipe(Effect.provide(makeConnectorLive({ stripe: `${mock.url}/charges` })), Effect.flip),
    );
    expect(err._tag).toBe("ConnectorFailed");
    expect(err.status).toBe(500);
    expect(JSON.stringify(err)).not.toContain(SECRET);
    await mock.close();
  });
});

describe("payload-routed tool calls", () => {
  const routes = (url: string): ToolRoutes => ({
    "cloudflare:cloudflare-graphql.analytics": url,
  });

  it("POSTs the payload to the route URL for alias:tool with the secret injected", async () => {
    let seenAuth = "";
    let seenMethod = "";
    let seenBody = "";
    let seenPath = "";
    const mock = await startServer((req, res) => {
      seenAuth = req.headers.authorization ?? "";
      seenMethod = req.method ?? "";
      seenPath = req.url ?? "";
      req.on("data", (chunk: Buffer) => {
        seenBody += chunk.toString("utf8");
      });
      req.on("end", () => {
        res.end(JSON.stringify({ zones: [{ zoneName: "example.com" }] }));
      });
    });
    const out = await Effect.runPromise(
      Effect.gen(function* () {
        const connector = yield* Connector;
        return yield* connector.execute(
          "cloudflare",
          "read",
          SECRET,
          { query: "{ viewer { zones } }", variables: {} },
          "cloudflare-graphql.analytics",
        );
      }).pipe(
        Effect.provide(
          makeConnectorLive(
            { cloudflare: `${mock.url}/tokens/verify` },
            routes(`${mock.url}/graphql`),
          ),
        ),
      ),
    );
    expect(seenMethod).toBe("POST");
    expect(seenPath).toBe("/graphql");
    expect(seenAuth).toBe(`Bearer ${SECRET}`);
    expect(JSON.parse(seenBody) as unknown).toEqual({
      query: "{ viewer { zones } }",
      variables: {},
    });
    expect(out).toEqual({ status: 200, data: { zones: [{ zoneName: "example.com" }] } });
    expect(JSON.stringify(out)).not.toContain(SECRET);
    await mock.close();
  });

  it("fails with NoConnectorRoute when no route is defined for alias:tool", async () => {
    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const connector = yield* Connector;
        return yield* connector.execute(
          "cloudflare",
          "read",
          SECRET,
          { query: "{ zones }" },
          "unknown.tool",
        );
      }).pipe(
        Effect.provide(makeConnectorLive({ cloudflare: "http://127.0.0.1:1/verify" })),
        Effect.flip,
      ),
    );
    expect(err._tag).toBe("ConnectorFailed");
    expect(err.message).toContain("NoConnectorRoute");
    expect(JSON.stringify(err)).not.toContain(SECRET);
  });

  it("maps route failures to ConnectorFailed carrying only the status", async () => {
    const mock = await startServer((_req, res) => {
      res.writeHead(503, { "x-secret-echo": SECRET });
      res.end(SECRET);
    });
    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const connector = yield* Connector;
        return yield* connector.execute(
          "cloudflare",
          "read",
          SECRET,
          { query: "{ zones }" },
          "cloudflare-graphql.analytics",
        );
      }).pipe(
        Effect.provide(makeConnectorLive({ cloudflare: `${mock.url}/verify` }, routes(`${mock.url}/graphql`))),
        Effect.flip,
      ),
    );
    expect(err._tag).toBe("ConnectorFailed");
    expect(err.status).toBe(503);
    expect(JSON.stringify(err)).not.toContain(SECRET);
    await mock.close();
  });
});
