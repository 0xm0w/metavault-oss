import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const styles = readFileSync(new URL("../src/renderer/styles.css", import.meta.url), "utf8");

function rulesForSelector(selector: string): string[] {
  return styles
    .split("}")
    .map((block) => `${block.trim()}}`)
    .filter((block) => {
      const openBrace = block.indexOf("{");
      return openBrace > 0 && block.slice(0, openBrace).split(",").map((part) => part.trim()).includes(selector);
    });
}

describe("locked window chrome", () => {
  it("keeps the top caption row present and draggable while locked", () => {
    const hiddenHeader = rulesForSelector("body.is-locked .app-header").find((rule) => /display\s*:\s*none/.test(rule));

    expect(hiddenHeader).toBeUndefined();
    expect(styles).toMatch(/\.app-header\s*\{[^}]*-webkit-app-region:\s*drag/s);
  });

  it("hides locked-only controls but not the drag header", () => {
    const headerRules = rulesForSelector("body.is-locked .app-header");
    const hiddenControls = rulesForSelector("body.is-locked .header-right");

    expect(headerRules.some((rule) => rule.includes(".header-right"))).toBe(false);
    expect(hiddenControls.some((rule) => /display\s*:\s*none/.test(rule))).toBe(true);
  });
});
