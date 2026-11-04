import { describe, expect, it } from "vitest";
import { grantOutcome } from "../src/server.js";

describe("grantOutcome", () => {
  it("reads a pending grant past its expiry as expired, and before it as pending", () => {
    expect(grantOutcome("pending", 1000, 999)).toMatchObject({ status: "pending", terminal: false });
    expect(grantOutcome("pending", 1000, 1000)).toMatchObject({ status: "expired", terminal: true });
  });
  it("maps each terminal status and treats unknown values as still pending, never as a decision", () => {
    expect(grantOutcome("denied", 1000, 0)).toMatchObject({ status: "denied", terminal: true });
    expect(grantOutcome("revoked", 1000, 0)).toMatchObject({ status: "revoked", terminal: true });
    expect(grantOutcome("executed", 1000, 0)).toMatchObject({ status: "executed", terminal: true });
    expect(grantOutcome("something-else", 1000, 0)).toMatchObject({ status: "pending", terminal: false });
  });
});
