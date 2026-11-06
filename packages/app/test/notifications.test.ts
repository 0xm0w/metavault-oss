import { describe, expect, it, vi } from "vitest";

vi.mock("electron", () => ({
  Notification: {
    isSupported: () => true,
  },
}));

import { ApprovalToastManager, type ToastClickRoute, type ToastDeps } from "../src/notifications.js";

interface FakeToast {
  readonly title: string;
  readonly body: string;
  readonly silent: boolean;
  shown: boolean;
  closed: boolean;
  triggerClick: () => void;
}

function makeHarness() {
  const created: FakeToast[] = [];
  const routes: ToastClickRoute[] = [];
  let settingsRouted = 0;

  const manager = new ApprovalToastManager({
    notificationsSupported: () => true,
    create: (opts) => {
      let clickHandler: (() => void) | null = null;
      const item: FakeToast = {
        title: opts.title,
        body: opts.body,
        silent: opts.silent,
        shown: false,
        closed: false,
        triggerClick: () => {
          clickHandler?.();
        },
      };
      created.push(item);
      return {
        on: ((event: string, cb: () => void) => {
          if (event === "click") clickHandler = cb;
        }) as unknown as ReturnType<ToastDeps["create"]>["on"],
        show: () => {
          item.shown = true;
        },
        close: () => {
          item.closed = true;
        },
      };
    },
    onRoute: (r) => {
      routes.push(r);
    },
    onSettingsRoute: () => {
      settingsRouted += 1;
    },
  });

  return { manager, created, routes, getSettingsRouted: () => settingsRouted };
}

describe("ApprovalToastManager", () => {
  const prefsOn = { toastNotificationsEnabled: true, redactToastWhenLocked: true };

  it("surfaces silent OS toasts with rich metadata when unlocked and routes click to target grant", () => {
    const { manager, created, routes } = makeHarness();
    manager.fires(
      {
        grantId: "g-1",
        agentId: "claude-code",
        alias: "stripe",
        requestedScope: "charges.write",
        risk: "high",
        remote: false,
      },
      prefsOn,
      false,
    );
    expect(created).toHaveLength(1);
    expect(created[0]?.silent).toBe(true);
    expect(created[0]?.shown).toBe(true);
    expect(created[0]?.title).toBe("High-Risk Approval Needed — stripe");
    expect(created[0]?.body).toContain("claude-code requests charges.write");

    created[0]?.triggerClick();
    expect(routes).toEqual([{ kind: "approval", id: "g-1" }]);
  });

  it("redacts alias, agentId, and scope in toast copy while UI or daemon is locked", () => {
    const { manager, created } = makeHarness();
    manager.fires(
      {
        grantId: "g-secret",
        agentId: "cursor",
        alias: "openai-prod",
        requestedScope: "chat.write",
        risk: "high",
        remote: true,
      },
      prefsOn,
      true,
    );
    expect(created).toHaveLength(1);
    expect(created[0]?.title).toBe("MetaVault OSS — Approval Waiting");
    expect(created[0]?.body).not.toContain("openai-prod");
    expect(created[0]?.body).not.toContain("cursor");
    expect(created[0]?.body).not.toContain("chat.write");

    manager.firesRegistration({ registrationId: "reg-1", name: "Secret Agent" }, prefsOn, true);
    expect(created).toHaveLength(2);
    expect(created[1]?.title).toBe("MetaVault OSS — Agent Verification");
    expect(created[1]?.body).not.toContain("Secret Agent");
  });

  it("auto-closes stale toasts when a grant or registration resolves and routes tunnel drops", () => {
    const { manager, created, getSettingsRouted } = makeHarness();
    manager.fires(
      {
        grantId: "g-99",
        agentId: "cursor",
        alias: "cloudflare",
        requestedScope: "dns.read",
        risk: "low",
        remote: false,
      },
      prefsOn,
      false,
    );
    expect(created[0]?.closed).toBe(false);
    manager.dismiss("grant:g-99");
    expect(created[0]?.closed).toBe(true);

    manager.firesTunnelDrop("Host key mismatch", prefsOn);
    expect(created[1]?.title).toBe("MetaVault Remote Connection Stopped");
    created[1]?.triggerClick();
    expect(getSettingsRouted()).toBe(1);
  });
});
