import { describe, expect, it } from "vitest";
import {
  inferAliasAndScope,
  parseDotEnv,
  parseDotEnvWithInference,
} from "../src/dotenv.js";

describe(".env parser and inference engine (#17)", () => {
  it("parses comments, empty lines, and unquoted values", () => {
    const raw = `
# Server config
PORT=3000
HOST=127.0.0.1 # inline comment
DEBUG=true
`;
    const entries = parseDotEnv(raw);
    expect(entries).toEqual([
      { key: "PORT", value: "3000" },
      { key: "HOST", value: "127.0.0.1" },
      { key: "DEBUG", value: "true" },
    ]);
  });

  it("handles exports, quotes, and escaped characters", () => {
    const raw = `
export STRIPE_SECRET_KEY="sk_test_12345\\nwith_newline"
DATABASE_URL='postgresql://user:pass@localhost:5432/mydb'
EMPTY_STRING=""
SINGLE_WORD='simple'
ESCAPED_QUOTE="hello \\"world\\""
MULTILINE_SINGLE='line1
line2
line3'
`;
    const entries = parseDotEnv(raw);
    expect(entries).toHaveLength(6);
    expect(entries[0]).toEqual({
      key: "STRIPE_SECRET_KEY",
      value: "sk_test_12345\nwith_newline",
    });
    expect(entries[1]).toEqual({
      key: "DATABASE_URL",
      value: "postgresql://user:pass@localhost:5432/mydb",
    });
    expect(entries[2]).toEqual({ key: "EMPTY_STRING", value: "" });
    expect(entries[3]).toEqual({ key: "SINGLE_WORD", value: "simple" });
    expect(entries[4]?.value).toBe('hello "world"');
    expect(entries[5]?.value).toBe("line1\nline2\nline3");
  });

  it("infers aliases and least-privilege scopes for known providers", () => {
    expect(inferAliasAndScope("STRIPE_SECRET_KEY")).toEqual({
      alias: "stripe",
      scope: "charges.read",
    });
    expect(inferAliasAndScope("OPENAI_API_KEY")).toEqual({
      alias: "openai",
      scope: "models.read",
    });
    expect(inferAliasAndScope("ANTHROPIC_API_KEY")).toEqual({
      alias: "anthropic",
      scope: "models.read",
    });
    expect(inferAliasAndScope("GH_TOKEN")).toEqual({
      alias: "github",
      scope: "repo.read",
    });
    expect(inferAliasAndScope("CLOUDFLARE_API_TOKEN")).toEqual({
      alias: "cloudflare",
      scope: "dns.read",
    });
    expect(inferAliasAndScope("GEMINI_API_KEY")).toEqual({
      alias: "gemini",
      scope: "models.read",
    });
  });

  it("falls back cleanly on unknown environment keys", () => {
    expect(inferAliasAndScope("CUSTOM_PAYMENT_GATEWAY_TOKEN")).toEqual({
      alias: "custom-payment-gateway",
      scope: "read",
    });
    expect(inferAliasAndScope("MY_SERVICE_SECRET")).toEqual({
      alias: "my-service",
      scope: "read",
    });
    expect(inferAliasAndScope("API_KEY")).toEqual({
      alias: "api",
      scope: "read",
    });
    expect(inferAliasAndScope("KEY")).toEqual({
      alias: "credential",
      scope: "read",
    });
  });

  it("produces full inference import items ready for vault storage", () => {
    const raw = `
# Production keys
STRIPE_API_KEY=sk_live_xyz987
OPENAI_API_KEY="sk-proj-abc123"
CUSTOM_API_SECRET=supersecret
`;
    const items = parseDotEnvWithInference(raw);
    expect(items).toEqual([
      {
        rawKey: "STRIPE_API_KEY",
        alias: "stripe",
        scope: "charges.read",
        value: "sk_live_xyz987",
      },
      {
        rawKey: "OPENAI_API_KEY",
        alias: "openai",
        scope: "models.read",
        value: "sk-proj-abc123",
      },
      {
        rawKey: "CUSTOM_API_SECRET",
        alias: "custom",
        scope: "read",
        value: "supersecret",
      },
    ]);
  });

  it("skips malformed lines without a key instead of failing", () => {
    const entries = parseDotEnv("NOT_A_PAIR\n=missing-key\nOK=1");
    expect(entries).toEqual([{ key: "OK", value: "1" }]);
  });

  it("supports multiline double-quoted values", () => {
    const entries = parseDotEnv('MULTI="one\ntwo"');
    expect(entries).toEqual([{ key: "MULTI", value: "one\ntwo" }]);
  });

});
