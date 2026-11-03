import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { metavaultEnv } from "../src/env.js";
import { metavaultEnv as appMetavaultEnv } from "../../app/src/env.js";

// Built from parts so a future find-and-replace can't silently rewrite it.
const LEGACY_PREFIX = ["OPEN", "VAULT_"].join("");
const SUFFIX = "ENV_TEST_PROBE";
const canonical = `METAVAULT_${SUFFIX}`;
const legacy = `${LEGACY_PREFIX}${SUFFIX}`;

afterEach(() => {
  Reflect.deleteProperty(process.env, canonical);
  Reflect.deleteProperty(process.env, legacy);
});

describe.each([
  ["core", metavaultEnv],
  ["app", appMetavaultEnv],
] as const)("metavaultEnv (%s)", (_name, read) => {
  it("reads the METAVAULT_ name", () => {
    process.env[canonical] = "canonical";
    expect(read(SUFFIX)).toBe("canonical");
  });

  it("ignores the pre-rebrand prefix (breaking change, see CHANGELOG)", () => {
    process.env[legacy] = "legacy";
    expect(read(SUFFIX)).toBeUndefined();
    process.env[canonical] = "canonical";
    expect(read(SUFFIX)).toBe("canonical");
  });

  it("returns undefined when nothing is set", () => {
    expect(read(SUFFIX)).toBeUndefined();
  });
});

describe("env var sources", () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  it("no source file reads the pre-rebrand prefix", () => {
    for (const rel of ["packages/core/src/env.ts", "packages/app/src/env.ts"]) {
      expect(readFileSync(join(root, rel), "utf8")).not.toContain(LEGACY_PREFIX);
    }
  });
});
