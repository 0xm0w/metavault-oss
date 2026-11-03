import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["node_modules/**", "dist/**", "**/dist/**", "coverage/**", "packages/app/bundle/**", "packages/app/release/**"],
  },
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-explicit-any": "error",
    },
  },
  {
    files: ["packages/{core,brain,connectors,daemon,mcp,cli}/**/*.ts"],
    rules: {
      "no-console": "error",
    },
  },
  {
    // The Electron renderer is plain TypeScript by design (spec Section 7):
    // it only renders daemon responses, so Effect stays daemon-side.
    files: ["packages/app/src/renderer/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          paths: [
            { name: "effect", message: "Renderer is plain TypeScript: no Effect imports." },
            { name: "@effect/platform", message: "Renderer is plain TypeScript: no Effect imports." },
            { name: "@effect/platform-node", message: "Renderer is plain TypeScript: no Effect imports." },
          ],
          patterns: ["@effect/*", "effect/*"],
        },
      ],
    },
  },
  {
    files: ["**/*.test.ts", "packages/**/test/**/*.ts", "test/**/*.ts"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
  {
    files: ["**/*.js", "**/*.mjs", "**/*.cjs"],
    ...tseslint.configs.disableTypeChecked,
  },
);
