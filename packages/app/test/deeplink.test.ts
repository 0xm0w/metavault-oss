import { describe, expect, it } from "vitest";
import {
  findVaultDeeplink,
  findVaultDeeplinkAction,
  isDeeplinkAddParams,
  parseVaultDeeplink,
  parseVaultDeeplinkAction,
  websiteFromTrustedEnrollment,
} from "../src/deeplink.js";

describe("parseVaultDeeplink", () => {
  it("parses a full add link", () => {
    expect(parseVaultDeeplink("metavault://add?alias=stripe&scope=charges.read&website=stripe.com&enrollment=enr-1")).toEqual({
      alias: "stripe",
      scope: "charges.read",
      website: "stripe.com",
      enrollmentId: "enr-1",
    });
  });

  it("defaults website/enrollment to empty and ignores extra params incl. secret", () => {
    const parsed = parseVaultDeeplink("metavault://add?alias=a&scope=s.read&secret=hunter2&token=x&extra=1");
    expect(parsed).toEqual({ alias: "a", scope: "s.read", website: "", enrollmentId: "" });
    expect(JSON.stringify(parsed)).not.toContain("hunter2");
  });

  it("rejects wrong scheme/host, missing fields, non-strings", () => {
    expect(parseVaultDeeplink("https://add?alias=a&scope=s")).toBeNull();
    expect(parseVaultDeeplink("metavault://evil?alias=a&scope=s")).toBeNull();
    expect(parseVaultDeeplink("metavault://add?scope=s")).toBeNull();
    expect(parseVaultDeeplink("metavault://add?alias=a")).toBeNull();
    expect(parseVaultDeeplink("metavault://add?alias=%20&scope=s")).toBeNull();
    expect(parseVaultDeeplink("not a url")).toBeNull();
    expect(parseVaultDeeplink(42)).toBeNull();
    expect(parseVaultDeeplink(null)).toBeNull();
  });

  it("rejects oversized values, duplicate params, and URLs", () => {
    expect(parseVaultDeeplink(`metavault://add?alias=${"a".repeat(129)}&scope=s`)).toBeNull();
    expect(parseVaultDeeplink(`metavault://add?alias=a&scope=${"s".repeat(300)}`)).toBeNull();
    expect(parseVaultDeeplink(`metavault://add?alias=a&scope=s&website=${"w".repeat(300)}`)).toBeNull();
    expect(parseVaultDeeplink(`metavault://add?alias=a&scope=s&enrollment=${"e".repeat(200)}`)).toBeNull();
    expect(parseVaultDeeplink(`metavault://add?alias=a&scope=s&x=${"y".repeat(3000)}`)).toBeNull();
    expect(parseVaultDeeplink("metavault://add?alias=a&alias=b&scope=s")).toBeNull();
  });

  it("finds link in argv and validates payload shape", () => {
    expect(findVaultDeeplink(["--flag", "metavault://add?alias=a&scope=s.read"])?.alias).toBe("a");
    expect(findVaultDeeplink(["--flag"])).toBeNull();
    expect(isDeeplinkAddParams({ alias: "a", scope: "s", website: "", enrollmentId: "" })).toBe(true);
    expect(isDeeplinkAddParams({ alias: "a", scope: "s", website: "", enrollmentId: "", secret: "x" })).toBe(false);
  });

  it("accepts the legacy openvault scheme and rejects bidi", () => {
    expect(parseVaultDeeplink("openvault://add?alias=stripe&scope=charges.read")?.alias).toBe("stripe");
    expect(parseVaultDeeplink("metavault://add?alias=stripe&scope=charges.read&website=a\u202E.com")).toBeNull();
    expect(parseVaultDeeplink("metavault://add?alias=str\u202Eipe&scope=charges.read")).toBeNull();
  });
});

describe("parseVaultDeeplinkAction (6 routes)", () => {
  it("parses all six metavault:// and openvault:// routes", () => {
    expect(parseVaultDeeplinkAction("metavault://add?alias=openai&scope=chat.write&enrollment=enr-42")).toEqual({
      kind: "add",
      alias: "openai",
      scope: "chat.write",
      website: "",
      enrollmentId: "enr-42",
    });
    expect(parseVaultDeeplinkAction("metavault://approve?grantId=grant_abc-123")).toEqual({
      kind: "approve",
      grantId: "grant_abc-123",
    });
    expect(parseVaultDeeplinkAction("openvault://approve?grantId=grant_legacy")).toEqual({
      kind: "approve",
      grantId: "grant_legacy",
    });
    expect(parseVaultDeeplinkAction("openvault://approve")).toBeNull();
    expect(parseVaultDeeplinkAction("metavault://register?registrationId=reg_99")).toEqual({
      kind: "register",
      registrationId: "reg_99",
    });
    expect(parseVaultDeeplinkAction("metavault://unlock?target=daemon")).toEqual({
      kind: "unlock",
      target: "daemon",
    });
    expect(parseVaultDeeplinkAction("metavault://unlock?target=ui")).toEqual({
      kind: "unlock",
      target: "ui",
    });
    expect(parseVaultDeeplinkAction("metavault://audit?requestId=req_100")).toEqual({
      kind: "audit",
      requestId: "req_100",
    });
    expect(parseVaultDeeplinkAction("metavault://settings?section=connections")).toEqual({
      kind: "settings",
      section: "connections",
    });
  });

  it("rejects duplicate query keys, bidi/control characters, and invalid route parameters", () => {
    expect(parseVaultDeeplinkAction("metavault://approve?grantId=g1&grantId=g2")).toBeNull();
    expect(parseVaultDeeplinkAction("metavault://register?registrationId=r1&registrationId=r2")).toBeNull();
    expect(parseVaultDeeplinkAction("metavault://unlock?target=root")).toBeNull();
    expect(parseVaultDeeplinkAction("metavault://settings?section=admin")).toBeNull();
    expect(parseVaultDeeplinkAction("metavault://approve?grantId=bad/slash")).toBeNull();
    expect(parseVaultDeeplinkAction("metavault://approve?grantId=g1\u202E")).toBeNull();
    expect(parseVaultDeeplinkAction("metavault://approve?grantId=g1\u0007")).toBeNull();
    expect(findVaultDeeplinkAction(["--minimized", "metavault://unlock?target=daemon"])).toEqual({
      kind: "unlock",
      target: "daemon",
    });
  });
});

describe("websiteFromTrustedEnrollment", () => {
  const params = { alias: "stripe", scope: "charges.read", website: "https://api.stripe.com", enrollmentId: "enr-1" };
  const enrollment = { status: "pending", alias: "stripe", scope: "charges.read", website: "https://api.stripe.com" };
  it("keeps the website only when the pending enrollment matches and is live", () => {
    expect(websiteFromTrustedEnrollment(params, enrollment, 1_000, 2_000)).toEqual({
      website: "https://api.stripe.com",
      untrusted: false,
    });
    expect(websiteFromTrustedEnrollment({ ...params, website: "" }, null, 1_000, null)).toEqual({
      website: "",
      untrusted: false,
    });
  });
  it("strips the website when the enrollment is missing, expired, or mismatched", () => {
    expect(websiteFromTrustedEnrollment(params, null, 1_000, 2_000)).toEqual({ website: "", untrusted: true });
    expect(websiteFromTrustedEnrollment(params, { ...enrollment, status: "completed" }, 1_000, 2_000).untrusted).toBe(true);
    expect(websiteFromTrustedEnrollment(params, enrollment, 2_000, 2_000).website).toBe("");
    expect(websiteFromTrustedEnrollment(params, { ...enrollment, website: "https://evil.example" }, 1_000, 2_000).website).toBe("");
    expect(websiteFromTrustedEnrollment(params, { ...enrollment, alias: "other" }, 1_000, 2_000).untrusted).toBe(true);
  });
});
