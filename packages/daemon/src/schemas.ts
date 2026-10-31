import { Schema } from "effect";

// Shared daemon API schemas. The HTTP handler and the MCP adapter both
// decode untrusted input with these exact schemas — one dialect, reused.
export const CapabilityRequestSchema = Schema.Struct({
  agentId: Schema.String,
  ide: Schema.String,
  tool: Schema.String,
  alias: Schema.String,
  requestedScope: Schema.String,
  reason: Schema.String,
});

export const GrantIdSchema = Schema.Struct({ grantId: Schema.String });
export const RevokeSchema = Schema.Struct({ target: Schema.String });
export const CredentialSchema = Schema.Struct({
  alias: Schema.String,
  scope: Schema.String,
  secret: Schema.String,
  website: Schema.optional(Schema.String),
  enrollmentId: Schema.optional(Schema.String),
});

export const EnrollmentRequestSchema = Schema.Struct({
  alias: Schema.String,
  scope: Schema.String,
  website: Schema.optional(Schema.String),
  reason: Schema.optional(Schema.String),
  agentId: Schema.optional(Schema.String),
});

export const EnrollmentIdSchema = Schema.Struct({ enrollmentId: Schema.String });

export const WardenSettingsPatchSchema = Schema.Struct({
  provider: Schema.optional(Schema.Literal("none", "ollama", "meta-api")),
  model: Schema.optional(Schema.String),
  effort: Schema.optional(Schema.Literal("fast", "standard", "deep")),
  metaApiBaseUrl: Schema.optional(Schema.String),
});

export const WardenKeyPutSchema = Schema.Struct({
  key: Schema.optional(Schema.String),
  apiKey: Schema.optional(Schema.String),
  secret: Schema.optional(Schema.String),
});

export const UpdateCredentialSchema = Schema.Struct({
  scope: Schema.optional(Schema.String),
  website: Schema.optional(Schema.String),
  secret: Schema.optional(Schema.String),
});

// Response contract for GET /policies: enforced ceilings (alias -> scope
// ceiling) plus current standing approvals. Metadata only by construction —
// no secret values, no ciphertext, no credential material of any kind.
export const PoliciesResponseSchema = Schema.Struct({
  ceilings: Schema.Record({ key: Schema.String, value: Schema.String }),
  standingApprovals: Schema.Array(
    Schema.Struct({
      agentId: Schema.String,
      alias: Schema.String,
      scope: Schema.String,
    }),
  ),
});
