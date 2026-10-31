import { Data } from "effect";
export class StorageError extends Data.TaggedError("StorageError") {
    constructor(props = {}) {
        super(props);
    }
}
export class PolicyDenied extends Data.TaggedError("PolicyDenied") {
    constructor(props = {}) {
        super(props);
    }
}
export class UnknownAlias extends Data.TaggedError("UnknownAlias") {
    constructor(props = {}) {
        super(props);
    }
}
export class MarshalUnavailable extends Data.TaggedError("MarshalUnavailable") {
    constructor(props = {}) {
        super(props);
    }
}
export class MarshalInvalidOutput extends Data.TaggedError("MarshalInvalidOutput") {
    constructor(props = {}) {
        super(props);
    }
}
export class GrantExpired extends Data.TaggedError("GrantExpired") {
    constructor(props = {}) {
        super(props);
    }
}
export class GrantRevoked extends Data.TaggedError("GrantRevoked") {
    constructor(props = {}) {
        super(props);
    }
}
export class ConnectorFailed extends Data.TaggedError("ConnectorFailed") {
    constructor(props = {}) {
        super(props);
    }
}
