import { describe, expect, it } from "vitest";
import { findVaultDeeplink, isDeeplinkAddParams, parseVaultDeeplink } from "../src/deeplink.js";

describe("parseVaultDeeplink", () => {
  it("parses a full add link", () => {
    expect(parseVaultDeeplink("openvault://add?alias=stripe&scope=charges.read&website=stripe.com&enrollment=enr-1")).toEqual({ alias: "stripe", scope: "charges.read", website: "stripe.com", enrollmentId: "enr-1" });
  });
  it("defaults website/enrollment to empty and ignores extra params incl. secret", () => {
    const parsed = parseVaultDeeplink("openvault://add?alias=a&scope=s.read&secret=hunter2&token=x&extra=1");
    expect(parsed).toEqual({ alias: "a", scope: "s.read", website: "", enrollmentId: "" });
    expect(JSON.stringify(parsed)).not.toContain("hunter2");
  });
  it("rejects wrong scheme/host, missing fields, non-strings", () => {
    expect(parseVaultDeeplink("https://add?alias=a&scope=s")).toBeNull();
    expect(parseVaultDeeplink("openvault://evil?alias=a&scope=s")).toBeNull();
    expect(parseVaultDeeplink("openvault://add?scope=s")).toBeNull();
    expect(parseVaultDeeplink("openvault://add?alias=a")).toBeNull();
    expect(parseVaultDeeplink("openvault://add?alias=%20&scope=s")).toBeNull();
    expect(parseVaultDeeplink("not a url")).toBeNull();
    expect(parseVaultDeeplink(42)).toBeNull();
    expect(parseVaultDeeplink(null)).toBeNull();
  });
  it("rejects oversized values and URLs", () => {
    expect(parseVaultDeeplink(`openvault://add?alias=${"a".repeat(129)}&scope=s`)).toBeNull();
    expect(parseVaultDeeplink(`openvault://add?alias=a&scope=${"s".repeat(300)}`)).toBeNull();
    expect(parseVaultDeeplink(`openvault://add?alias=a&scope=s&website=${"w".repeat(300)}`)).toBeNull();
    expect(parseVaultDeeplink(`openvault://add?alias=a&scope=s&enrollment=${"e".repeat(200)}`)).toBeNull();
    expect(parseVaultDeeplink(`openvault://add?alias=a&scope=s&x=${"y".repeat(3000)}`)).toBeNull();
  });
  it("finds link in argv and validates payload shape", () => {
    expect(findVaultDeeplink(["--flag", "openvault://add?alias=a&scope=s.read"])?.alias).toBe("a");
    expect(findVaultDeeplink(["--flag"])).toBeNull();
    expect(isDeeplinkAddParams({ alias: "a", scope: "s", website: "", enrollmentId: "" })).toBe(true);
    expect(isDeeplinkAddParams({ alias: "a", scope: "s", website: "", enrollmentId: "", secret: "x" })).toBe(false);
  });
});
