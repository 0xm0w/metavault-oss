// OS toast notifications for pending approvals and agent registrations.
// Approval alerts are non-intrusive by default: toast + tray badge + taskbar
// flash + chime; the window only pops up when the user enables it in
// Settings. Clicking a toast routes to the exact card. Secrets never appear
// in text; details are redacted while locked.

import { Notification } from "electron";

export type ToastKey = string;

export interface ToastClickRoute {
  readonly kind: "approval" | "registration";
  readonly id: string;
}

export interface ToastDeps {
  readonly notificationsSupported: () => boolean;
  readonly create: (options: { readonly title: string; readonly body: string; readonly silent: boolean }) => Pick<Notification, "on" | "show" | "close"> & { closed?: boolean };
  readonly onRoute: (route: ToastClickRoute) => void;
  readonly onSettingsRoute: () => void;
}

export const defaultToastDeps: () => ToastDeps = () => ({
  notificationsSupported: () => Notification.isSupported(),
  create: (options) => {
    const note = new Notification({ ...options, silent: true });
    return {
      on: note.on.bind(note),
      show: note.show.bind(note),
      close: note.close.bind(note),
    };
  },
  onRoute: () => undefined,
  onSettingsRoute: () => undefined,
});

export interface PendingGrantSnapshot {
  readonly grantId: string;
  readonly agentId: string;
  readonly alias: string;
  readonly requestedScope: string;
  readonly risk: string;
  readonly remote: boolean;
}

export interface PendingRegistrationSnapshot {
  readonly registrationId: string;
  readonly name: string;
}

export interface ToastPreferences {
  readonly toastNotificationsEnabled: boolean;
  readonly redactToastWhenLocked: boolean;
}

export class ApprovalToastManager {
  private readonly dep: ToastDeps;
  private readonly activeToasts = new Map<string, ReturnType<ToastDeps["create"]>>();

  constructor(deps: ToastDeps) {
    this.dep = deps;
  }

  private surface(
    key: string,
    title: string,
    body: string,
    onClick: () => void,
  ): void {
    if (!this.dep.notificationsSupported() || this.activeToasts.has(key)) return;
    try {
      const note = this.dep.create({ title, body, silent: true });
      note.on("click", () => {
        this.activeToasts.delete(key);
        onClick();
      });
      this.activeToasts.set(key, note);
      note.show();
    } catch {
      // Notification churn must never break the approval flow.
    }
  }

  private lockedCopy(): { readonly title: string; readonly body: string } {
    return {
      title: "MetaVault OSS — Approval Waiting",
      body: "An agent capability request is waiting. Click to unlock and review.",
    };
  }

  private highRisk(snapshot: PendingGrantSnapshot): boolean {
    return (
      snapshot.risk === "high" ||
      snapshot.requestedScope.includes(".write") ||
      snapshot.remote
    );
  }

  fires(snap: PendingGrantSnapshot, prefs: ToastPreferences, locked: boolean): void {
    if (!prefs.toastNotificationsEnabled) return;
    const redact = locked && prefs.redactToastWhenLocked;
    const title = redact
      ? this.lockedCopy().title
      : this.highRisk(snap)
        ? `High-Risk Approval Needed — ${snap.alias}`
        : `Agent Request — ${snap.alias}`;
    const body = redact
      ? this.lockedCopy().body
      : `${snap.agentId} requests ${snap.requestedScope}. Click to review in MetaVault.`;
    this.surface(`grant:${snap.grantId}`, title, body, () => { this.dep.onRoute({ kind: "approval", id: snap.grantId }); },
    );
  }

  firesRegistration(snap: PendingRegistrationSnapshot, prefs: ToastPreferences, locked: boolean): void {
    if (!prefs.toastNotificationsEnabled) return;
    const redact = locked && prefs.redactToastWhenLocked;
    const title = redact
      ? "MetaVault OSS — Agent Verification"
      : `Verify Agent — ${snap.name}`;
    const body = redact
      ? "An agent wants to register. Click to unlock and review."
      : "Click to enter the 6-digit verification code in MetaVault.";
    this.surface(`reg:${snap.registrationId}`, title, body, () => { this.dep.onRoute({ kind: "registration", id: snap.registrationId }); },
    );
  }

  // An unexpected SSH tunnel drop is toast-worthy only (not an approval);
  // clicking routes to Settings > Connections.
  firesTunnelDrop(reason: string, prefs: ToastPreferences): void {
    if (!prefs.toastNotificationsEnabled) return;
    this.surfaceTunnel("MetaVault Remote Connection Stopped", reason.slice(0, 160));
  }

  private surfaceTunnel(title: string, body: string): void {
    if (!this.dep.notificationsSupported() || this.activeToasts.has("tunnel")) return;
    try {
      const note = this.dep.create({ title, body, silent: true });
      note.on("click", () => {
        this.activeToasts.delete("tunnel");
        this.dep.onSettingsRoute();
      });
      this.activeToasts.set("tunnel", note);
      note.show();
    } catch {
      // Ignore: same guard as grant toasts.
    }
  }

  // One-time informational notices (e.g. first close-to-tray). Click does
  // nothing beyond closing; honoring toastNotificationsEnabled.
  firesInfo(key: string, title: string, body: string): void {
    this.surface(key, title, body, () => undefined);
  }

  // Stale banners vanish from Action Center as soon as the source moves on
  // (decided, expired, claimed, reconnected).
  dismiss(key: ToastKey, genericKeys: readonly string[] = []): void {
    for (const candidate of [key, ...genericKeys]) {
      const note = this.activeToasts.get(candidate);
      if (note !== undefined) {
        this.activeToasts.delete(candidate);
        try {
          note.close();
        } catch {
          // Already gone.
        }
      }
    }
  }
}
