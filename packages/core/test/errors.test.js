import { describe, expect, it } from "vitest";
import { ConnectorFailed, GrantExpired, GrantRevoked, MarshalInvalidOutput, MarshalUnavailable, PolicyDenied, StorageError, UnknownAlias, } from "../src/errors.js";
describe("shared types", () => {
    it("shapes CapabilityRequest, MarshalDecision and AuditEvent", () => {
        const scope = "stripe:charges.read";
        const risk = "low";
        const req = {
            agentId: "agent-1",
            ide: "cursor",
            tool: "stripe",
            alias: "stripe",
            requestedScope: scope,
            reason: "read charges",
        };
        const decision = {
            risk,
            recommendedScope: scope,
            requireApproval: false,
            explanation: "read-only",
        };
        const event = {
            ts: "2026-10-31T00:00:00.000Z",
            agentId: req.agentId,
            alias: req.alias,
            scope,
            stage: "requested",
            detail: "requested",
        };
        expect(req.requestedScope).toBe("stripe:charges.read");
        expect(decision.risk).toBe("low");
        expect(event.stage).toBe("requested");
        expect(event.modelId).toBeUndefined();
    });
});
describe("tagged error taxonomy", () => {
    it("each error carries its tag and only safe fields", () => {
        const cases = [
            [new StorageError({ message: "disk full" }), "StorageError"],
            [new PolicyDenied({ message: "denied", reason: "ceiling" }), "PolicyDenied"],
            [new UnknownAlias({ alias: "nope" }), "UnknownAlias"],
            [new MarshalUnavailable(), "MarshalUnavailable"],
            [new MarshalUnavailable({ message: "ollama down" }), "MarshalUnavailable"],
            [new MarshalInvalidOutput({ message: "bad json" }), "MarshalInvalidOutput"],
            [new GrantExpired({ grantId: "g1" }), "GrantExpired"],
            [new GrantRevoked({ grantId: "g1" }), "GrantRevoked"],
            [new ConnectorFailed({ message: "502", alias: "stripe" }), "ConnectorFailed"],
        ];
        for (const [err, tag] of cases) {
            expect(err._tag).toBe(tag);
            expect(err).toBeInstanceOf(Error);
            const keys = Object.keys(err).sort();
            expect(keys).not.toContain("secret");
            expect(keys).not.toContain("plaintextSecret");
            expect(keys).not.toContain("value");
        }
        expect(new UnknownAlias({ alias: "nope" }).alias).toBe("nope");
        expect(new GrantExpired({ grantId: "g1" }).grantId).toBe("g1");
    });
});
