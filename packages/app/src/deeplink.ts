// Pure metavault:// deeplink parsing for the Electron main process. Kept
// free of Electron imports so hostile-input handling is unit-testable.
// Only alias/scope/website/enrollmentId survive, each length-capped; the
// secret is never a deeplink field — the human types it in the app.

export const DEEPLINK_CHANNEL = "metavault:deeplink-add";

export interface DeeplinkAddParams {
  readonly alias: string;
  readonly scope: string;
  readonly website: string;
  readonly enrollmentId: string;
}

export const MAX_ALIAS_LENGTH = 128;
export const MAX_SCOPE_LENGTH = 256;
export const MAX_WEBSITE_LENGTH = 253;
export const MAX_ENROLLMENT_LENGTH = 128;
const MAX_URL_LENGTH = 2048;
const BIDI_CONTROLS = /[\u202A-\u202E\u2066-\u2069]/;

function hasBidi(value: string): boolean {
  return BIDI_CONTROLS.test(value);
}

function capped(value: string | null, max: number): string | null {
  if (value === null) {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed === "" || trimmed.length > max) {
    return null;
  }
  // Reject control characters (covers smuggled newlines / NULs).
  for (let i = 0; i < trimmed.length; i += 1) {
    const code = trimmed.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      return null;
    }
  }
  return trimmed;
}

export function parseVaultDeeplink(raw: unknown): DeeplinkAddParams | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_URL_LENGTH) {
    return null;
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if ((url.protocol !== "metavault:" && url.protocol !== "openvault:") || url.hostname !== "add") {
    return null;
  }
  // Duplicate known params are ambiguous: reject instead of picking one.
  for (const key of ["alias", "scope", "website", "enrollment"]) {
    if (url.searchParams.getAll(key).length > 1) {
      return null;
    }
  }
  const alias = capped(url.searchParams.get("alias"), MAX_ALIAS_LENGTH);
  if (alias !== null && (alias.includes("/") || alias.includes("\\") || alias === "." || alias === "..")) {
    return null;
  }
  const scope = capped(url.searchParams.get("scope"), MAX_SCOPE_LENGTH);
  if (alias === null || scope === null) {
    return null;
  }
  const websiteRaw = url.searchParams.get("website");
  const website = websiteRaw === null || websiteRaw.trim() === "" ? "" : capped(websiteRaw, MAX_WEBSITE_LENGTH);
  if (website === null) {
    return null;
  }
  const enrollmentRaw = url.searchParams.get("enrollment");
  const enrollmentId =
    enrollmentRaw === null || enrollmentRaw.trim() === "" ? "" : capped(enrollmentRaw, MAX_ENROLLMENT_LENGTH);
  if (enrollmentId === null) {
    return null;
  }
  if (hasBidi(alias) || hasBidi(scope) || hasBidi(website) || hasBidi(enrollmentId)) {
    return null;
  }
  return { alias, scope, website, enrollmentId };
}

export interface EnrollmentWebsiteRecord {
  readonly status: string;
  readonly alias: string;
  readonly scope: string;
  readonly website: string;
}

// A website from a deeplink is kept only when a live pending enrollment
// matches the alias, scope, and website and has not expired.
export function websiteFromTrustedEnrollment(
  params: DeeplinkAddParams,
  enrollment: EnrollmentWebsiteRecord | null,
  nowMs: number,
  expiresAtMs: number | null,
): { readonly website: string; readonly untrusted: boolean } {
  const reject = { website: "", untrusted: true as const };
  if (params.website === "") return { website: "", untrusted: false };
  if (enrollment === null || enrollment.status !== "pending") return reject;
  if (expiresAtMs !== null && nowMs >= expiresAtMs) return reject;
  if (enrollment.alias !== params.alias || enrollment.scope !== params.scope) return reject;
  if (enrollment.website !== params.website) return reject;
  return { website: params.website, untrusted: false };
}

export function findVaultDeeplink(argv: readonly unknown[]): DeeplinkAddParams | null {
  for (const arg of argv) {
    const parsed = parseVaultDeeplink(arg);
    if (parsed !== null) {
      return parsed;
    }
  }
  return null;
}

export function isDeeplinkAddParams(value: unknown): value is DeeplinkAddParams {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.join(",") !== "alias,enrollmentId,scope,website") {
    return false;
  }
  return (
    typeof record["alias"] === "string" &&
    record["alias"] !== "" &&
    record["alias"].length <= MAX_ALIAS_LENGTH &&
    typeof record["scope"] === "string" &&
    record["scope"] !== "" &&
    record["scope"].length <= MAX_SCOPE_LENGTH &&
    typeof record["website"] === "string" &&
    record["website"].length <= MAX_WEBSITE_LENGTH &&
    typeof record["enrollmentId"] === "string" &&
    record["enrollmentId"].length <= MAX_ENROLLMENT_LENGTH
  );
}

// Discriminated union for every metavault:// (and legacy openvault://)
// route the app accepts. Tokens and ids are length-capped; no secret
// material is ever a deeplink field.
export type VaultDeeplinkAction =
  | {
      readonly kind: "add";
      readonly alias: string;
      readonly scope: string;
      readonly website: string;
      readonly enrollmentId: string;
    }
  | { readonly kind: "approve"; readonly grantId: string }
  | { readonly kind: "register"; readonly registrationId: string }
  | { readonly kind: "unlock"; readonly target: "ui" | "daemon" | "auto" }
  | { readonly kind: "audit"; readonly requestId: string }
  | {
      readonly kind: "settings";
      readonly section: "warden" | "agents" | "security" | "notifications" | "connections";
    };

// Control characters, Bidi overrides and isolates: invisible in a rendered
// link, so any occurrence is an attack signal, not formatting.
const BIDI_AND_CONTROL = /[\u0000-\u001f\u007f\u200e\u200f\u202a-\u202e\u2066-\u2069]/;

function cappedAction(value: string | null, max: number): string | null {
  if (value === null) return null;
  const trimmed = value.trim();
  if (trimmed === "" || trimmed.length > max) return null;
  if (trimmed.includes("/") || trimmed.includes("\\") || trimmed === "." || trimmed === "..") return null;
  if (BIDI_AND_CONTROL.test(trimmed)) return null;
  return trimmed;
}

const MAX_UNKNOWNS = 128;

const SETTINGS_SECTIONS = ["warden", "agents", "security", "notifications", "connections"] as const;
const UNLOCK_TARGETS = ["ui", "daemon", "auto"] as const;

// Parses the six action routes. Unknown hosts, duplicate search params,
// oversized values, and control/Bidi characters all fail closed.
export function parseVaultDeeplinkAction(raw: unknown): VaultDeeplinkAction | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_URL_LENGTH) {
    return null;
  }
  if (BIDI_AND_CONTROL.test(raw)) {
    return null;
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "metavault:" && url.protocol !== "openvault:") {
    return null;
  }
  const seenKeys = new Set<string>();
  for (const key of url.searchParams.keys()) {
    if (seenKeys.has(key)) {
      return null;
    }
    seenKeys.add(key);
  }
  const param = (key: string): string | null => {
    const all = url.searchParams.getAll(key);
    if (all.length > 1) {
      return null;
    }
    return all[0] ?? null;
  };
  const route = url.hostname;
  if (route === "add") {
    const alias = capped(param("alias"), MAX_ALIAS_LENGTH);
    if (alias !== null && (alias.includes("/") || alias.includes("\\") || alias === "." || alias === "..")) {
      return null;
    }
    const scope = capped(param("scope"), MAX_SCOPE_LENGTH);
    if (alias === null || scope === null) return null;
    const websiteRaw = param("website");
    const website = websiteRaw === null || websiteRaw.trim() === "" ? "" : capped(websiteRaw, MAX_WEBSITE_LENGTH);
    if (website === null) return null;
    const enrollmentRaw = param("enrollment");
    const enrollmentId = enrollmentRaw === null || enrollmentRaw.trim() === "" ? "" : capped(enrollmentRaw, MAX_ENROLLMENT_LENGTH);
    if (enrollmentId === null) return null;
    for (const value of [alias, scope, website, enrollmentId]) {
      if (BIDI_AND_CONTROL.test(value)) return null;
    }
    return { kind: "add", alias, scope, website, enrollmentId };
  }
  if (route === "approve") {
    const grantId = cappedAction(param("grantId"), MAX_UNKNOWNS);
    return grantId === null ? null : { kind: "approve", grantId };
  }
  if (route === "register") {
    const registrationId = cappedAction(param("registrationId"), MAX_UNKNOWNS);
    return registrationId === null ? null : { kind: "register", registrationId };
  }
  if (route === "unlock") {
    const targetRaw = param("target");
    const target = targetRaw === null || targetRaw.trim() === "" ? "auto" : targetRaw.trim();
    return UNLOCK_TARGETS.some((t) => t === target)
      ? { kind: "unlock", target: target as "ui" | "daemon" | "auto" }
      : null;
  }
  if (route === "audit") {
    const requestId = cappedAction(param("requestId"), MAX_UNKNOWNS);
    return requestId === null ? null : { kind: "audit", requestId };
  }
  if (route === "settings") {
    const section = (param("section") ?? "").trim();
    return SETTINGS_SECTIONS.some((s) => s === section)
      ? { kind: "settings", section: section as (typeof SETTINGS_SECTIONS)[number] }
      : null;
  }
  return null;
}

export function findVaultDeeplinkAction(argv: readonly unknown[]): VaultDeeplinkAction | null {
  for (const arg of argv) {
    const parsed = parseVaultDeeplinkAction(arg);
    if (parsed !== null) {
      return parsed;
    }
  }
  return null;
}
