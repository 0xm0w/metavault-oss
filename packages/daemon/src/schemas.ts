import { Schema } from "effect";

// Bounds & safety filters for untrusted agent inputs
export const SafeIdentifier = Schema.String.pipe(
  Schema.maxLength(128),
  Schema.filter((s) => !/[\0\u200E\u200F\u202A-\u202E]/.test(s), {
    message: () => "prohibited control or bidi override characters",
  }),
);

export const SafeText = Schema.String.pipe(
  Schema.maxLength(1024),
  Schema.filter((s) => !/[\0]/.test(s), {
    message: () => "prohibited null bytes",
  }),
);

// Shared daemon API schemas. The HTTP handler and the MCP adapter both
// decode untrusted input with these exact schemas — one dialect, reused.
export const CapabilityRequestSchema = Schema.Struct({
  agentId: SafeIdentifier,
  ide: SafeIdentifier,
  tool: SafeIdentifier,
  alias: SafeIdentifier,
  requestedScope: SafeIdentifier,
  reason: SafeText,
});

export const GrantIdSchema = Schema.Struct({ grantId: SafeIdentifier });
export const RevokeSchema = Schema.Struct({ target: SafeIdentifier });
export const CredentialSchema = Schema.Struct({
  alias: SafeIdentifier,
  scope: SafeIdentifier,
  secret: Schema.String,
  website: Schema.optional(Schema.String),
  enrollmentId: Schema.optional(SafeIdentifier),
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
