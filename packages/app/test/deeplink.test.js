import { describe, expect, it } from "vitest";
import { findOpenVaultUrl, isDeeplinkAddParams, parseOpenVaultUrl } from "../src/deeplink.js";
describe("parseOpenVaultUrl", () => {
    it("parses a full add link", () => {
        expect(parseOpenVaultUrl("openvault://add?alias=stripe&scope=charges.read&website=stripe.com&enrollment=enr-1")).toEqual({ alias: "stripe", scope: "charges.read", website: "stripe.com", enrollmentId: "enr-1" });
    });
    it("defaults website/enrollment to empty and ignores extra params incl. secret", () => {
        const parsed = parseOpenVaultUrl("openvault://add?alias=a&scope=s.read&secret=hunter2&token=x&extra=1");
        expect(parsed).toEqual({ alias: "a", scope: "s.read", website: "", enrollmentId: "" });
        expect(JSON.stringify(parsed)).not.toContain("hunter2");
    });
    it("rejects wrong scheme/host, missing fields, non-strings", () => {
        expect(parseOpenVaultUrl("https://add?alias=a&scope=s")).toBeNull();
        expect(parseOpenVaultUrl("openvault://evil?alias=a&scope=s")).toBeNull();
        expect(parseOpenVaultUrl("openvault://add?scope=s")).toBeNull();
        expect(parseOpenVaultUrl("openvault://add?alias=a")).toBeNull();
        expect(parseOpenVaultUrl("openvault://add?alias=%20&scope=s")).toBeNull();
        expect(parseOpenVaultUrl("not a url")).toBeNull();
        expect(parseOpenVaultUrl(42)).toBeNull();
        expect(parseOpenVaultUrl(null)).toBeNull();
    });
    it("rejects oversized values and URLs", () => {
        expect(parseOpenVaultUrl(`openvault://add?alias=${"a".repeat(129)}&scope=s`)).toBeNull();
        expect(parseOpenVaultUrl(`openvault://add?alias=a&scope=${"s".repeat(300)}`)).toBeNull();
        expect(parseOpenVaultUrl(`openvault://add?alias=a&scope=s&website=${"w".repeat(300)}`)).toBeNull();
        expect(parseOpenVaultUrl(`openvault://add?alias=a&scope=s&enrollment=${"e".repeat(200)}`)).toBeNull();
        expect(parseOpenVaultUrl(`openvault://add?alias=a&scope=s&x=${"y".repeat(3000)}`)).toBeNull();
    });
    it("finds link in argv and validates payload shape", () => {
        expect(findOpenVaultUrl(["--flag", "openvault://add?alias=a&scope=s.read"])?.alias).toBe("a");
        expect(findOpenVaultUrl(["--flag"])).toBeNull();
        expect(isDeeplinkAddParams({ alias: "a", scope: "s", website: "", enrollmentId: "" })).toBe(true);
        expect(isDeeplinkAddParams({ alias: "a", scope: "s", website: "", enrollmentId: "", secret: "x" })).toBe(false);
    });
});
