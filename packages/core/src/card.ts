// Payment-card credential type.
//
// A card is stored like every other secret: the full record (number, name,
// expiry, CVV) is JSON-encoded and sealed with AES-256-GCM under the vault
// master key (crypto.ts). Only CardPublicMeta (brand + last 4) is kept in
// clear, so agents and the app can tell cards apart without ever holding
// the number. Validation here is structural (Luhn, expiry, CVV length);
// it does not prove the card is real or funded.

export const CARD_SECRET_TYPE = "payment-card";
export const CARD_KIND = "card";
export const SECRET_KIND = "secret";
export type CredentialKind = typeof CARD_KIND | typeof SECRET_KIND;
export const DEFAULT_CARD_SCOPE = "card.payment:write";

export type CardBrand = "visa" | "mastercard" | "amex" | "discover" | "unknown";

export interface CardInput {
  readonly number: string;
  readonly name: string;
  readonly expMonth: number | string;
  readonly expYear: number | string;
  readonly cvv: string;
}

export interface CardSecret {
  readonly type: typeof CARD_SECRET_TYPE;
  readonly v: 1;
  readonly number: string;
  readonly name: string;
  readonly expMonth: number;
  readonly expYear: number;
  readonly cvv: string;
}

// The only card fields that ever leave the daemon. No expiry, no name.
export interface CardPublicMeta {
  readonly brand: CardBrand;
  readonly last4: string;
  readonly masked: string;
}

export type CardValidationIssue =
  | "number-format"
  | "number-length"
  | "number-luhn"
  | "name-empty"
  | "name-too-long"
  | "expiry-format"
  | "expired"
  | "cvv-format";

export type CardParseResult =
  | { readonly ok: true; readonly card: CardSecret; readonly meta: CardPublicMeta }
  | { readonly ok: false; readonly issues: readonly CardValidationIssue[] };

export function normalizeCardNumber(raw: string): string | null {
  const stripped = raw.replace(/[\s-]/g, "");
  return /^\d+$/.test(stripped) ? stripped : null;
}

// Luhn mod-10 (ISO/IEC 7812-1 check digit).
export function luhnValid(digits: string): boolean {
  if (!/^\d+$/.test(digits) || digits.length < 2) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

export function detectCardBrand(digits: string): CardBrand {
  if (/^4/.test(digits)) return "visa";
  if (/^3[47]/.test(digits)) return "amex";
  const two = Number(digits.slice(0, 2));
  const four = Number(digits.slice(0, 4));
  if ((two >= 51 && two <= 55) || (four >= 2221 && four <= 2720)) return "mastercard";
  const three = Number(digits.slice(0, 3));
  if (/^6011/.test(digits) || /^65/.test(digits) || (three >= 644 && three <= 649)) return "discover";
  return "unknown";
}

function lengthOk(brand: CardBrand, len: number): boolean {
  switch (brand) {
    case "amex":
      return len === 15;
    case "visa":
      return len === 13 || len === 16 || len === 19;
    case "mastercard":
      return len === 16;
    case "discover":
      return len >= 16 && len <= 19;
    case "unknown":
      return len >= 12 && len <= 19;
  }
}

function toInt(v: number | string): number | null {
  if (typeof v === "number") return Number.isInteger(v) ? v : null;
  const t = v.trim();
  return /^\d{1,4}$/.test(t) ? Number(t) : null;
}

export function maskCardNumber(last4: string): string {
  return `•••• ${last4}`;
}

export function cardPublicMeta(card: Pick<CardSecret, "number">): CardPublicMeta {
  const last4 = card.number.slice(-4);
  return { brand: detectCardBrand(card.number), last4, masked: maskCardNumber(last4) };
}

// `now` is injectable so tests are not date-dependent. A card is valid
// through the last day of its expiry month.
export function parseCardInput(input: CardInput, now: Date = new Date()): CardParseResult {
  const issues: CardValidationIssue[] = [];
  const digits = normalizeCardNumber(input.number);
  let brand: CardBrand = "unknown";
  if (digits === null) {
    issues.push("number-format");
  } else {
    brand = detectCardBrand(digits);
    if (!lengthOk(brand, digits.length)) issues.push("number-length");
    else if (!luhnValid(digits)) issues.push("number-luhn");
  }
  const name = input.name.trim();
  if (name === "") issues.push("name-empty");
  else if (name.length > 100) issues.push("name-too-long");

  const month = toInt(input.expMonth);
  let year = toInt(input.expYear);
  if (year !== null && year < 100) year += 2000;
  if (month === null || year === null || month < 1 || month > 12 || year > 2100) {
    issues.push("expiry-format");
  } else {
    const nowYear = now.getUTCFullYear();
    const nowMonth = now.getUTCMonth() + 1;
    if (year < nowYear || (year === nowYear && month < nowMonth)) issues.push("expired");
  }
  const cvv = input.cvv.trim();
  const cvvLen = brand === "amex" ? 4 : 3;
  if (!new RegExp(`^\\d{${String(cvvLen)}}$`).test(cvv)) issues.push("cvv-format");

  if (issues.length > 0 || digits === null || month === null || year === null) {
    return { ok: false, issues };
  }
  const card: CardSecret = { type: CARD_SECRET_TYPE, v: 1, number: digits, name, expMonth: month, expYear: year, cvv };
  return { ok: true, card, meta: cardPublicMeta(card) };
}

export function serializeCardSecret(card: CardSecret): string {
  return JSON.stringify(card);
}

// True when a decrypted secret is a card record. Connectors use this to
// refuse ever sending a card as a bearer token.
export function isCardSecretPayload(plaintext: string): boolean {
  if (!plaintext.startsWith("{")) return false;
  try {
    const parsed: unknown = JSON.parse(plaintext);
    return typeof parsed === "object" && parsed !== null && (parsed as { type?: unknown }).type === CARD_SECRET_TYPE;
  } catch {
    return false;
  }
}

export function parseCardPublicMeta(raw: string): CardPublicMeta | null {
  if (raw === "") return null;
  try {
    const parsed = JSON.parse(raw) as Partial<CardPublicMeta>;
    if (typeof parsed.last4 === "string" && /^\d{4}$/.test(parsed.last4) && typeof parsed.brand === "string") {
      return { brand: parsed.brand, last4: parsed.last4, masked: maskCardNumber(parsed.last4) };
    }
    return null;
  } catch {
    return null;
  }
}
