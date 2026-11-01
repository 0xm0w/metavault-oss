import { describe, expect, it } from "vitest";
import { classifyWindowsHelloOutput, isWindowsHelloPurpose } from "../src/windows-hello.js";

describe("Windows Hello output", () => {
  it("keeps the last status line from the prompt script", () => {
    expect(classifyWindowsHelloOutput("available\r\n")).toBe("available");
    expect(classifyWindowsHelloOutput("noise\nverified\n")).toBe("verified");
    expect(classifyWindowsHelloOutput("canceled")).toBe("canceled");
    expect(classifyWindowsHelloOutput("not-configured")).toBe("not-configured");
    expect(classifyWindowsHelloOutput("unavailable")).toBe("unavailable");
    expect(classifyWindowsHelloOutput("failed")).toBe("failed");
    expect(classifyWindowsHelloOutput("")).toBe("failed");
    expect(classifyWindowsHelloOutput("something else")).toBe("failed");
  });

  it("accepts only the two prompt purposes", () => {
    expect(isWindowsHelloPurpose("setup")).toBe(true);
    expect(isWindowsHelloPurpose("unlock")).toBe(true);
    expect(isWindowsHelloPurpose("pin")).toBe(false);
    expect(isWindowsHelloPurpose(undefined)).toBe(false);
  });
});
