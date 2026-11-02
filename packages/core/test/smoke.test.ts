import { describe, expect, it } from "vitest";
import { Connector } from "../src/connector.js";

describe("smoke", () => {
  it("adds numbers", () => {
    expect(1 + 1).toBe(2);
  });

  it("instantiates Connector tag", () => {
    expect(Connector).toBeDefined();
    expect(Connector.key).toBe("Connector");
  });
});
