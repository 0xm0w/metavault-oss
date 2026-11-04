import { Data } from "effect";

export class StorageError extends Data.TaggedError("StorageError")<{
  readonly message?: string;
  readonly operation?: string;
}> {
  constructor(props: { readonly message?: string; readonly operation?: string } = {}) {
    super(props);
  }
}

export class PolicyDenied extends Data.TaggedError("PolicyDenied")<{
  readonly message?: string;
  readonly reason?: string;
  readonly alias?: string;
  readonly scope?: string;
}> {
  constructor(
    props: {
      readonly message?: string;
      readonly reason?: string;
      readonly alias?: string;
      readonly scope?: string;
    } = {},
  ) {
    super(props);
  }
}

export class UnknownAlias extends Data.TaggedError("UnknownAlias")<{
  readonly alias?: string;
}> {
  constructor(props: { readonly alias?: string } = {}) {
    super(props);
  }
}

export class MarshalUnavailable extends Data.TaggedError("MarshalUnavailable")<{
  readonly message?: string;
}> {
  constructor(props: { readonly message?: string } = {}) {
    super(props);
  }
}

export class MarshalInvalidOutput extends Data.TaggedError("MarshalInvalidOutput")<{
  readonly message?: string;
}> {
  constructor(props: { readonly message?: string } = {}) {
    super(props);
  }
}

export class GrantExpired extends Data.TaggedError("GrantExpired")<{
  readonly grantId?: string;
  readonly message?: string;
}> {
  constructor(props: { readonly grantId?: string; readonly message?: string } = {}) {
    super(props);
  }
}

export class GrantRevoked extends Data.TaggedError("GrantRevoked")<{
  readonly grantId?: string;
  readonly message?: string;
}> {
  constructor(props: { readonly grantId?: string; readonly message?: string } = {}) {
    super(props);
  }
}

export class ConnectorFailed extends Data.TaggedError("ConnectorFailed")<{
  readonly message?: string;
  readonly alias?: string;
  readonly status?: number;
}> {
  constructor(
    props: { readonly message?: string; readonly alias?: string; readonly status?: number } = {},
  ) {
    super(props);
  }
}

export class PresenceRequired extends Data.TaggedError("PresenceRequired")<{
  readonly message?: string;
  readonly grantId?: string;
}> {
  constructor(props: { readonly message?: string; readonly grantId?: string } = {}) {
    super(props);
  }
}

export class PairingNotConfirmable extends Data.TaggedError("PairingNotConfirmable")<{
  readonly message?: string;
  readonly pairingId?: string;
}> {
  constructor(props: { readonly message?: string; readonly pairingId?: string } = {}) {
    super(props);
  }
}
