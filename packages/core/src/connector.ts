import { Context, type Effect } from "effect";
import type { ConnectorFailed } from "./errors.js";

export interface ConnectorService {
  readonly execute: (
    alias: string,
    scope: string,
    secret: string,
    payload?: unknown,
  ) => Effect.Effect<unknown, ConnectorFailed>;
}

export class Connector extends Context.Tag("Connector")<Connector, ConnectorService>() {}
