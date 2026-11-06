import { summarizeHttpRequestPayload } from "../../core/src/payload.js";
import { isWriteScope } from "../../core/src/policy.js";
import type { MarshalDecision } from "../../core/src/types.js";

function resourcePrefix(scope: string): string {
  const index = Math.max(scope.lastIndexOf("."), scope.lastIndexOf(":"));
  return index > 0 ? scope.slice(0, index) : scope;
}

function isExtensionOf(longer: string, shorter: string): boolean {
  return (
    longer.length > shorter.length &&
    longer.startsWith(shorter) &&
    (longer[shorter.length] === "." || longer[shorter.length] === ":")
  );
}

export function narrowerScope(a: string, b: string): string {
  if (a === b) return a;
  if (a === "") return b;
  if (b === "") return a;
  if (isExtensionOf(a, b)) return a;
  if (isExtensionOf(b, a)) return b;
  if (resourcePrefix(a) === resourcePrefix(b)) {
    const aWrite = isWriteScope(a);
    const bWrite = isWriteScope(b);
    if (aWrite !== bWrite) return aWrite ? b : a;
  }
  return a;
}

export function enforceScopeSafety(
  decision: MarshalDecision,
  requestedScope: string,
  reason?: string,
  extraUntrusted?: { readonly tool?: string; readonly payload?: unknown },
): MarshalDecision {
  const isSafe =
    decision.recommendedScope === requestedScope ||
    isExtensionOf(decision.recommendedScope, requestedScope);

  if (!isSafe || decision.recommendedScope.includes("*")) {
    return {
      risk: "high",
      recommendedScope: requestedScope,
      requireApproval: true,
      explanation: `Warden proposed scope '${decision.recommendedScope}' does not narrow '${requestedScope}'; clamped to requested scope and escalated to high risk.`,
    };
  }

  if (isWriteScope(requestedScope) && !decision.requireApproval) {
    return {
      ...decision,
      requireApproval: true,
      explanation: `Write capability '${requestedScope}' strictly requires approval. ${decision.explanation}`,
    };
  }

  const payloadPreview = summarizeHttpRequestPayload(extraUntrusted?.payload)?.preview ?? "";
  const combinedText = [reason ?? "", extraUntrusted?.tool ?? "", requestedScope, payloadPreview]
    .filter((s) => s.trim() !== "")
    .join("\n");

  if (combinedText !== "") {
    const isAdversarial =
      /(?:classify|mark|set|return|rate)\s+(?:this|operation|request)?\s*(?:as)?\s*(?:risk)?\s*low/i.test(combinedText) ||
      /(?:requireapproval|require_approval)\s*(?:false|no|none)/i.test(combinedText) ||
      /(?:ignore\s+(?:all\s+)?(?:previous\s+)?instructions|system\s+override|developer\s+mode)/i.test(combinedText) ||
      /(?:approve|grant|execute)\s+[\w.:-]*write/i.test(combinedText) ||
      /https?:\/\/[^\s"'>]+/i.test(combinedText) ||
      /\|\s*(?:bash|sh|zsh|pwsh|powershell|cmd)\b/i.test(combinedText) ||
      /(?:\/etc\/(?:shadow|passwd)|\.ssh\/id_|\.aws\/credentials)/i.test(combinedText);

    if (isAdversarial && decision.risk !== "high") {
      return {
        risk: "high",
        recommendedScope: requestedScope,
        requireApproval: true,
        explanation: `Adversarial pattern or policy override attempt detected in request inputs; escalated to high risk. ${decision.explanation}`,
      };
    }
  }

  return decision;
}
