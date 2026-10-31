import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/**/test/**/*.test.ts", "packages/**/*.test.ts", "test/**/*.test.ts"],
  },
});
