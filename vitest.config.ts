import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/**/test/**/*.test.ts", "packages/**/*.test.ts", "test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      // Coverage thresholds (statements/lines) measured before gating; see
      // docs/VERIFICATION.md "Coverage baseline (Task 7)". Renderer DOM code
      // (main.ts) and the Electron main process are excluded from thresholds
      // and covered by smoke screenshots instead.
      include: [
        "packages/core/src/**/*.ts",
        "packages/daemon/src/**/*.ts",
        "packages/brain/src/**/*.ts",
        "packages/mcp/src/**/*.ts",
        "packages/app/src/renderer/model.ts",
      ],
      reporter: ["text", "json-summary"],
      reportsDirectory: "coverage",
      thresholds: {
        "packages/core/src/**": { statements: 90, lines: 90 },
        "packages/daemon/src/**": { statements: 85, lines: 85 },
        "packages/brain/src/**": { statements: 85, lines: 85 },
        "packages/mcp/src/**": { statements: 85, lines: 85 },
        "packages/app/src/renderer/model.ts": { statements: 90, lines: 90 },
      },
    },
  },
});
