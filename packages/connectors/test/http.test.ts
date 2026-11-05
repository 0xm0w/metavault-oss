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

describe("response secret redaction", () => {
  // Chosen so the exact, percent-encoded, Base64 and Base64-URL forms all
  // differ from each other.
  const ECHOED = "sk:secret key/9f8e7d6c5b4a3210?";

  it("redacts an exact secret echoed back by the upstream inside a JSON body", async () => {
    const mock = await startServer((_req, res) => {
      res.end(JSON.stringify({ echo: ECHOED, note: "verification ok" }));
    });
    const out = await Effect.runPromise(
      executeHttp({ url: `${mock.url}/verify`, method: "GET", secret: ECHOED }),
    );
    expect(out.status).toBe(200);
    const data = out.data as { echo: string };
    expect(data.echo).toBe("[REDACTED]");
    expect(JSON.stringify(out.data)).not.toContain(ECHOED);
    await mock.close();
  });

  it("redacts secret material embedded inside larger strings, percent-encoded and base64", async () => {
    const percent = encodeURIComponent(ECHOED);
    const base64 = Buffer.from(ECHOED, "utf8").toString("base64");
    const base64Url = base64.replace(/\+/g, "-").replace(/\//g, "_");
    const mock = await startServer((_req, res) => {
      res.end(
        JSON.stringify({
          a: `header: Bearer ${ECHOED} tail`,
          b: `url=${percent}`,
          c: base64,
          d: base64Url,
        }),
      );
    });
    const out = await Effect.runPromise(
      executeHttp({ url: `${mock.url}/logs`, method: "GET", secret: ECHOED }),
    );
    const data = out.data as Record<string, string>;
    expect(data["a"]).toBe("header: Bearer [REDACTED] tail");
    expect(data["b"]).toBe("url=[REDACTED]");
    expect(data["c"]).toBe("[REDACTED]");
    expect(data["d"]).toBe("[REDACTED]");
    expect(JSON.stringify(out.data)).not.toContain(ECHOED);
    expect(JSON.stringify(out.data)).not.toContain(percent);
    expect(JSON.stringify(out.data)).not.toContain(base64);
    expect(JSON.stringify(out.data)).not.toContain(base64Url);
    await mock.close();
  });

  it("redacts a non-JSON body too, keeping the redacted text readable", async () => {
    const mock = await startServer((_req, res) => {
      res.end(`token=${ECHOED}; status=ok`);
    });
    const out = await Effect.runPromise(
      executeHttp({ url: `${mock.url}/echo`, method: "GET", secret: ECHOED }),
    );
    expect(out.data).toBe("token=[REDACTED]; status=ok");
    await mock.close();
  });

  it("leaves unrelated response bodies untouched", async () => {
    const mock = await startServer((_req, res) => {
      res.end(JSON.stringify({ ok: true, charges: 5, tag: "sk-r3d" }));
    });
    const out = await Effect.runPromise(
      executeHttp({ url: `${mock.url}/normal`, method: "GET", secret: "sk_long_secret_value_abcd" }),
    );
    expect(out.data).toEqual({ ok: true, charges: 5, tag: "sk-r3d" });
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

describe("cloudflare dns allowlist", () => {
  it("posts an allowlisted Cloudflare DNS record and deletes it without leaking the secret", async () => {
    const zoneId = "0123456789abcdef0123456789abcdef";
    const recordId = "fedcba9876543210fedcba9876543210";
    let seenMethod = "";
    let seenUrl = "";
    let seenAuth = "";
    let seenBody = "";
    const mock = await startServer((req, res) => {
      seenMethod = req.method ?? "";
      seenUrl = req.url ?? "";
      seenAuth = req.headers.authorization ?? "";
      req.on("data", (chunk: Buffer) => {
        seenBody += chunk.toString("utf8");
      });
      req.on("end", () => {
        if (seenMethod === "DELETE") {
          res.end(JSON.stringify({ success: true, result: { id: recordId } }));
          return;
        }
        res.end(JSON.stringify({ success: true, result: { id: recordId, type: "TXT" } }));
      });
    });
    const created = await Effect.runPromise(
      Effect.gen(function* () {
        const connector = yield* Connector;
        return yield* connector.execute(
          "cloudflare",
          "dns.write",
          SECRET,
          {
            method: "POST",
            path: `/zones/${zoneId}/dns_records`,
            body: { type: "TXT", name: "mv-test.goodrecmovies.com", content: "metavault-test", ttl: 120 },
          },
          "cloudflare.dns",
        );
      }).pipe(Effect.provide(makeConnectorLive({ cloudflare: `${mock.url}/verify` }, undefined, { cloudflareApiBase: `${mock.url}/client/v4` }))),
    );
    expect(seenMethod).toBe("POST");
    expect(seenUrl).toBe(`/client/v4/zones/${zoneId}/dns_records`);
    expect(seenAuth).toBe(`Bearer ${SECRET}`);
    expect(JSON.parse(seenBody) as unknown).toEqual({
      type: "TXT",
      name: "mv-test.goodrecmovies.com",
      content: "metavault-test",
      ttl: 120,
    });
    expect(created).toEqual({ status: 200, data: { success: true, result: { id: recordId, type: "TXT" } } });
    expect(JSON.stringify(created)).not.toContain(SECRET);

    seenBody = "";
    const deleted = await Effect.runPromise(
      Effect.gen(function* () {
        const connector = yield* Connector;
        return yield* connector.execute(
          "cloudflare",
          "dns.write",
          SECRET,
          { method: "DELETE", path: `/zones/${zoneId}/dns_records/${recordId}` },
          "cloudflare.dns",
        );
      }).pipe(Effect.provide(makeConnectorLive({ cloudflare: `${mock.url}/verify` }, undefined, { cloudflareApiBase: `${mock.url}/client/v4` }))),
    );
    expect(seenMethod).toBe("DELETE");
    expect(seenUrl).toBe(`/client/v4/zones/${zoneId}/dns_records/${recordId}`);
    expect(seenBody).toBe("");
    expect(deleted).toEqual({ status: 200, data: { success: true, result: { id: recordId } } });
    expect(JSON.stringify(deleted)).not.toContain(SECRET);
    await mock.close();
  });

  it("looks up a zone by name with an allowlisted query", async () => {
    let seenUrl = "";
    const mock = await startServer((req, res) => {
      seenUrl = req.url ?? "";
      res.end(JSON.stringify({ success: true, result: [] }));
    });
    const out = await Effect.runPromise(
      Effect.gen(function* () {
        const connector = yield* Connector;
        return yield* connector.execute(
          "cloudflare",
          "dns.read",
          SECRET,
          { method: "GET", path: "/zones", query: { name: "goodrecmovies.com" } },
          "cloudflare.dns",
        );
      }).pipe(Effect.provide(makeConnectorLive({ cloudflare: `${mock.url}/verify` }, undefined, { cloudflareApiBase: `${mock.url}/client/v4` }))),
    );
    expect(seenUrl).toBe("/client/v4/zones?name=goodrecmovies.com");
    expect(out).toEqual({ status: 200, data: { success: true, result: [] } });
    expect(JSON.stringify(out)).not.toContain(SECRET);
    await mock.close();
  });

  it("rejects a Cloudflare DNS path that leaves the allowlist before any request", async () => {
    let hits = 0;
    const mock = await startServer((_req, res) => {
      hits += 1;
      res.end("{}");
    });
    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const connector = yield* Connector;
        return yield* connector.execute(
          "cloudflare",
          "dns.write",
          SECRET,
          { method: "POST", path: "https://evil.example/zones/0123456789abcdef0123456789abcdef/dns_records" },
          "cloudflare.dns",
        );
      }).pipe(
        Effect.provide(makeConnectorLive({ cloudflare: `${mock.url}/verify` }, undefined, { cloudflareApiBase: `${mock.url}/client/v4` })),
        Effect.flip,
      ),
    );
    expect(err._tag).toBe("ConnectorFailed");
    expect(hits).toBe(0);
    expect(JSON.stringify(err)).not.toContain(SECRET);
    await mock.close();
  });

  it("does not send a DNS write when the scope is read-only", async () => {
    let hits = 0;
    const mock = await startServer((_req, res) => {
      hits += 1;
      res.end("{}");
    });
    const err = await Effect.runPromise(
      Effect.gen(function* () {
        const connector = yield* Connector;
        return yield* connector.execute(
          "cloudflare",
          "dns.read",
          SECRET,
          {
            method: "POST",
            path: "/zones/0123456789abcdef0123456789abcdef/dns_records",
            body: { type: "TXT", name: "mv-test", content: "metavault-test" },
          },
          "cloudflare.dns",
        );
      }).pipe(
        Effect.provide(makeConnectorLive({ cloudflare: `${mock.url}/verify` }, undefined, { cloudflareApiBase: `${mock.url}/client/v4` })),
        Effect.flip,
      ),
    );
    expect(err._tag).toBe("ConnectorFailed");
    expect(hits).toBe(0);
    expect(JSON.stringify(err)).not.toContain(SECRET);
    await mock.close();
  });
});
