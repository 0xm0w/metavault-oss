import { createHash } from "node:crypto";

// Canonical summary of an agent-supplied HTTP payload. The warden, the
// deterministic rules and the policy floor all look at this instead of the
// raw payload, so an agent cannot hide a state-changing call behind a benign
// stated reason: intent (reason) and effect (payload method, digest, body
// preview) are assessed together.
//
// The effective HTTP method used by the connector depends on the route:
// a payload that DECLARES a method ({ method, path }) is executed as that
// method; payload-less calls are GETs; other payload routes always POST the
// body to a fixed URL. Declared mutating methods are what the deterministic
// checks act on.

export interface HttpRequestPayloadSummary {
  // Declared inside the payload ("GET"/"POST"/...), or null when the payload
  // does not declare one (route transport decides; never agent-chosen).
  readonly declaredMethod: string | null;
  // True when the declared method is a state-changing HTTP verb.
  readonly mutating: boolean;
  // sha256 over the serialized payload: a stable integrity binding that can
  // appear in prompts and audits without exposing payload content.
  readonly digest: string;
  // Bounded single-line preview of the serialized payload. Untrusted data:
  // escape before embedding anywhere instructions matter.
  readonly preview: string;
}

const MUTATING_METHODS: ReadonlySet<string> = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const PREVIEW_LIMIT = 400;

export function summarizeHttpRequestPayload(
  payload: unknown,
): HttpRequestPayloadSummary | null {
  if (payload === undefined || payload === null) {
    return null;
  }
  let serialized: string;
  try {
    serialized = JSON.stringify(payload);
  } catch {
    return null;
  }
  if (serialized === "") {
    return null;
  }
  // Structured payloads serialize deterministically (insertion-ordered keys),
  // which is canonical enough for a digest that binds the exact bytes the
  // human and the wardens saw.
  const digest = createHash("sha256").update(serialized, "utf8").digest("hex");
  let declaredMethod: string | null = null;
  if (typeof payload === "object" && !Array.isArray(payload)) {
    const record = payload as Record<string, unknown>;
    if (typeof record["method"] === "string" && record["method"].trim() !== "") {
      declaredMethod = record["method"].trim().toUpperCase();
    }
  }
  return {
    declaredMethod,
    mutating: declaredMethod !== null && MUTATING_METHODS.has(declaredMethod),
    digest,
    preview: serialized.slice(0, PREVIEW_LIMIT),
  };
}
