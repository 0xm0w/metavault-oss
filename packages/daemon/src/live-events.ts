// In-process fan-out for GET /events. Payloads are counts and ids only.
// Never put secrets, receipts, tokens, or credential material on this bus.

export type VaultLiveEvent =
  | {
      readonly type: "pending.changed";
      readonly pendingCount: number;
      readonly addedGrantId?: string;
      readonly risk?: string;
      readonly origin?: string;
    }
  | {
      readonly type: "registration.changed";
      readonly pendingRegistrationsCount: number;
      readonly addedRegistrationId?: string;
    }
  | {
      readonly type: "enrollment.changed";
      readonly enrollmentId: string;
      readonly status: string;
    }
  | { readonly type: "vault.lock_changed"; readonly daemonLocked: boolean }
  | { readonly type: "audit.appended"; readonly requestId?: string; readonly stage: string };

type Listener = (event: VaultLiveEvent) => void;

const listeners = new Set<Listener>();

export function subscribeVaultEvents(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function publishVaultEvent(event: VaultLiveEvent): void {
  for (const listener of listeners) {
    listener(event);
  }
}

export function vaultEventData(event: VaultLiveEvent): Record<string, unknown> {
  const data: Record<string, unknown> = {};
  if (event.type === "pending.changed") {
    data["pendingCount"] = event.pendingCount;
    if (event.addedGrantId !== undefined) data["addedGrantId"] = event.addedGrantId;
    if (event.risk !== undefined) data["risk"] = event.risk;
    if (event.origin !== undefined) data["origin"] = event.origin;
  } else if (event.type === "registration.changed") {
    data["pendingRegistrationsCount"] = event.pendingRegistrationsCount;
    if (event.addedRegistrationId !== undefined) data["addedRegistrationId"] = event.addedRegistrationId;
  } else if (event.type === "enrollment.changed") {
    data["enrollmentId"] = event.enrollmentId;
    data["status"] = event.status;
  } else if (event.type === "vault.lock_changed") {
    data["daemonLocked"] = event.daemonLocked;
  } else {
    data["stage"] = event.stage;
    if (event.requestId !== undefined) data["requestId"] = event.requestId;
  }
  return data;
}
