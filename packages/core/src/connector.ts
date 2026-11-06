import { Context, type Effect } from "effect";
import type { ConnectorFailed } from "./errors.js";

// How the daemon injects the secret on a website-pinned REST call.
// The agent never chooses this; it is stored with the credential.
export type CredentialAuthStyle = "bearer" | "api-key" | "basic";

export interface ConnectorRouteContext {
  readonly baseUrl?: string;
  readonly auth?: CredentialAuthStyle;
}

export interface ConnectorService {
  readonly execute: (
    alias: string,
    scope: string,
    secret: string,
    payload?: unknown,
    tool?: string,
    route?: ConnectorRouteContext,
  ) => Effect.Effect<unknown, ConnectorFailed>;
}

export class Connector extends Context.Tag("Connector")<Connector, ConnectorService>() {}
