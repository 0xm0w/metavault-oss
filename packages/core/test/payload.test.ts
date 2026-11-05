import { describe, expect, it } from "vitest";
import { summarizeHttpRequestPayload } from "../src/payload.js";

describe("summarizeHttpRequestPayload", () => {
  it("returns null for absent payloads", () => {
    expect(summarizeHttpRequestPayload(undefined)).toBeNull();
    expect(summarizeHttpRequestPayload(null)).toBeNull();
  });

  it("declares a method only when the payload carries a string method", () => {
    const withMethod = summarizeHttpRequestPayload({ method: "delete", path: "/x" });
    expect(withMethod?.declaredMethod).toBe("DELETE");
    expect(withMethod?.mutating).toBe(true);
    const noMethod = summarizeHttpRequestPayload({ query: "select 1" });
    expect(noMethod?.declaredMethod).toBeNull();
    expect(noMethod?.mutating).toBe(false);
  });

  it("marks GET and HEAD as non-mutating, POST/PUT/PATCH/DELETE as mutating", () => {
    for (const [method, mutating] of [
      ["GET", false],
      ["HEAD", false],
      ["POST", true],
      ["PUT", true],
      ["PATCH", true],
      ["DELETE", true],
    ] as const) {
      expect(summarizeHttpRequestPayload({ method })?.mutating).toBe(mutating);
    }
  });

  it("digests deterministically over the serialized payload", () => {
    const a = summarizeHttpRequestPayload({ method: "GET", path: "/same" });
    const b = summarizeHttpRequestPayload({ method: "GET", path: "/same" });
    expect(a?.digest).toBe(b?.digest);
    expect(a?.digest).toMatch(/^[0-9a-f]{64}$/);
    const c = summarizeHttpRequestPayload({ method: "GET", path: "/other" });
    expect(a?.digest).not.toBe(c?.digest);
  });

  it("bounds the preview to a single short string", () => {
    const summary = summarizeHttpRequestPayload({ data: "y".repeat(10_000) });
    expect(summary?.preview.length).toBe(400);
    expect(summary?.preview).toContain("yy");
  });

  it("handles arrays, strings, numbers and booleans as payload content", () => {
    expect(summarizeHttpRequestPayload([1, 2, 3])?.declaredMethod).toBeNull();
    expect(summarizeHttpRequestPayload("body")?.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(summarizeHttpRequestPayload(42)?.declaredMethod).toBeNull();
    expect(summarizeHttpRequestPayload(false)?.mutating).toBe(false);
  });

  it("trims and upper-cases the declared method", () => {
    expect(summarizeHttpRequestPayload({ method: "  patch " })?.declaredMethod).toBe("PATCH");
  });
});
