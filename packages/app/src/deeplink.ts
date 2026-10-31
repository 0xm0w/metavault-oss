// Pure openvault:// deeplink parsing for the Electron main process. Kept
// free of Electron imports so hostile-input handling is unit-testable.
// Only alias/scope/website/enrollmentId survive, each length-capped; the
// secret is never a deeplink field — the human types it in the app.

export const DEEPLINK_CHANNEL = "openvault:deeplink-add";

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

export function parseOpenVaultUrl(raw: unknown): DeeplinkAddParams | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_URL_LENGTH) {
    return null;
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "openvault:" || url.hostname !== "add") {
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
  return { alias, scope, website, enrollmentId };
}

export function findOpenVaultUrl(argv: readonly unknown[]): DeeplinkAddParams | null {
  for (const arg of argv) {
    const parsed = parseOpenVaultUrl(arg);
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
