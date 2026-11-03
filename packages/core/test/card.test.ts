import { describe, expect, it } from "vitest";
import {
  CARD_SECRET_TYPE,
  detectCardBrand,
  isCardSecretPayload,
  luhnValid,
  maskCardNumber,
  parseCardInput,
  parseCardPublicMeta,
  serializeCardSecret,
} from "../src/card.js";

// Public test numbers published by card networks / processors for testing.
const VISA = "4242424242424242";
const MC = "5555555555554444";
const AMEX = "378282246310005";
const NOW = new Date(Date.UTC(2026, 10, 3));
const base = { number: VISA, name: "Ada Lovelace", expMonth: 12, expYear: 2030, cvv: "123" };

describe("card validation", () => {
  it("accepts valid Luhn numbers and rejects a one-digit change", () => {
    expect(luhnValid(VISA)).toBe(true);
    expect(luhnValid(MC)).toBe(true);
    expect(luhnValid(AMEX)).toBe(true);
    expect(luhnValid("4242424242424241")).toBe(false);
  });
  it("detects brands", () => {
    expect(detectCardBrand(VISA)).toBe("visa");
    expect(detectCardBrand(MC)).toBe("mastercard");
    expect(detectCardBrand(AMEX)).toBe("amex");
  });
  it("normalises spaces and dashes and returns only last-4 metadata", () => {
    const r = parseCardInput({ ...base, number: "4242 4242-4242 4242" }, NOW);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.card.number).toBe(VISA);
    expect(r.meta).toEqual({ brand: "visa", last4: "4242", masked: maskCardNumber("4242") });
    expect(JSON.stringify(r.meta)).not.toContain("424242");
    expect(JSON.stringify(r.meta)).not.toContain("Ada");
  });
  it("rejects bad Luhn, empty name, expired cards and wrong CVV length", () => {
    const r = parseCardInput({ number: "4242424242424241", name: " ", expMonth: 10, expYear: 2026, cvv: "12" }, NOW);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.issues).toEqual(expect.arrayContaining(["number-luhn", "name-empty", "expired", "cvv-format"]));
  });
  it("treats the expiry month as valid through its last day and accepts 2-digit years", () => {
    expect(parseCardInput({ ...base, expMonth: 11, expYear: 26 }, NOW).ok).toBe(true);
    expect(parseCardInput({ ...base, expMonth: 13, expYear: 2030 }, NOW).ok).toBe(false);
  });
  it("requires a 4-digit CVV for amex and 3 digits otherwise", () => {
    expect(parseCardInput({ ...base, number: AMEX, cvv: "1234" }, NOW).ok).toBe(true);
    expect(parseCardInput({ ...base, number: AMEX, cvv: "123" }, NOW).ok).toBe(false);
    expect(parseCardInput({ ...base, cvv: "1234" }, NOW).ok).toBe(false);
  });
  it("recognises serialised card payloads and nothing else", () => {
    const r = parseCardInput(base, NOW);
    if (!r.ok) throw new Error("expected valid");
    const s = serializeCardSecret(r.card);
    expect(isCardSecretPayload(s)).toBe(true);
    expect(JSON.parse(s)).toMatchObject({ type: CARD_SECRET_TYPE });
    expect(isCardSecretPayload("sk-live-abc")).toBe(false);
    expect(isCardSecretPayload('{"type":"other"}')).toBe(false);
    expect(isCardSecretPayload("{not json")).toBe(false);
  });
  it("parses stored public meta defensively", () => {
    expect(parseCardPublicMeta('{"brand":"visa","last4":"4242"}')?.masked).toBe(maskCardNumber("4242"));
    expect(parseCardPublicMeta('{"brand":"visa","last4":"42424242"}')).toBeNull();
    expect(parseCardPublicMeta("")).toBeNull();
    expect(parseCardPublicMeta("garbage")).toBeNull();
  });
});
