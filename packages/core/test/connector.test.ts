import { Effect, Layer } from "effect";
import { describe, expect } from "vitest";
import { it } from "@effect/vitest";
import { Connector } from "../src/connector.js";

describe("Connector service contract", () => {
  it.effect("routes execution through the provided connector layer", () =>
    Effect.gen(function* () {
      const calls: Array<{ alias: string; scope: string; secret: string }> = [];
      const stub = Layer.succeed(Connector, {
        execute: (alias, scope, secret) => {
          calls.push({ alias, scope, secret });
          return Effect.succeed({ ok: true });
        },
      });
      const result = yield* Effect.flatMap(Connector, (connector) =>
        connector.execute("stripe", "charges.read", "sk_test"),
      ).pipe(Effect.provide(stub));
      expect(result).toEqual({ ok: true });
      expect(calls).toEqual([{ alias: "stripe", scope: "charges.read", secret: "sk_test" }]);
    }),
  );
});
