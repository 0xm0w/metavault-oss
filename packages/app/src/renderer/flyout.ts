import type { FlyoutGrantLike, FlyoutStateLike } from "./types.js";

export const FLYOUT_FOCUS_GUARD_MS = 500;

export function isFlyoutApprovalArmed(nowMs: number, armedAtMs: number): boolean {
  return nowMs >= armedAtMs;
}

function node<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const elem = document.createElement(tag);
  if (className !== "") elem.className = className;
  if (text !== undefined) elem.textContent = text;
  return elem;
}

function mountFlyout(root: HTMLElement): void {
  let state: FlyoutStateLike = {
    uiLocked: false,
    daemonLocked: false,
    localAuthConfigured: false,
    canLockDaemon: false,
    soundMode: "all",
    pendingCount: 0,
    registrationCount: 0,
    credentialCount: 0,
    grants: [],
    registrations: [],
  };
  let errorBanner = "";
  let armedAtMs = Date.now() + FLYOUT_FOCUS_GUARD_MS;
  let armTimer: number | null = null;
  const knownGrantIds = new Set<string>();
  const regDrafts = new Map<string, string>();
  const busyIds = new Set<string>();

  const rearmFocusGuard = (): void => {
    armedAtMs = Date.now() + FLYOUT_FOCUS_GUARD_MS;
    if (armTimer !== null) {
      window.clearTimeout(armTimer);
    }
    armTimer = window.setTimeout(() => {
      armTimer = null;
      paint();
    }, FLYOUT_FOCUS_GUARD_MS + 15);
  };

  const renderGrantCard = (grant: FlyoutGrantLike, armed: boolean): HTMLElement => {
    const card = node("section", "flyout-card");
    const top = node("div", "flyout-card-top");
    top.append(node("span", "flyout-agent", grant.agentId));

    const badges = node("div", "flyout-badges");
    badges.append(
      node(
        "span",
        grant.verified ? "flyout-tag is-ok" : "flyout-tag is-warn",
        grant.verified ? "Verified" : "\u26A0 Unverified",
      ),
    );
    if (grant.origin === "remote") {
      badges.append(node("span", "flyout-tag is-danger", "Remote"));
    }
    const riskClass =
      grant.risk === "high"
        ? "flyout-tag is-danger"
        : grant.risk === "medium"
          ? "flyout-tag is-warn"
          : "flyout-tag is-ok";
    badges.append(node("span", riskClass, grant.risk));
    top.append(badges);
    card.append(top);

    const scopeText =
      grant.requestedScope !== grant.allowedScope
        ? `${grant.alias} \u00B7 ${grant.requestedScope} \u2192 ${grant.allowedScope}`
        : `${grant.alias} \u00B7 ${grant.allowedScope}`;
    card.append(node("div", "flyout-target", scopeText));

    if (grant.payloadHeadline !== undefined && grant.payloadHeadline !== "") {
      card.append(node("div", "flyout-mono", grant.payloadHeadline));
    }
    if (grant.explanation !== undefined && grant.explanation !== "") {
      card.append(node("p", "flyout-explain", grant.explanation));
    }

    const actions = node("div", "flyout-actions");
    const busy = busyIds.has(grant.grantId);

    if (grant.origin === "remote") {
      const reviewBtn = node("button", "btn btn-approve", "Review in App \u2197");
      reviewBtn.type = "button";
      reviewBtn.disabled = busy || !armed;
      reviewBtn.addEventListener("click", () => {
        if (!isFlyoutApprovalArmed(Date.now(), armedAtMs)) return;
        window.metavault.flyoutAction({
          type: "open-app",
          nav: { kind: "approval", id: grant.grantId },
        });
      });
      actions.append(reviewBtn);
    } else {
      const approveBtn = node("button", "btn btn-approve", "Approve Once");
      approveBtn.type = "button";
      approveBtn.disabled = busy || !armed;
      approveBtn.addEventListener("click", () => {
        if (!isFlyoutApprovalArmed(Date.now(), armedAtMs)) return;
        busyIds.add(grant.grantId);
        errorBanner = "";
        paint();
        void window.metavault
          .approve(grant.grantId)
          .catch((err: unknown) => {
            const msg = err instanceof Error ? err.message : "";
            if (msg.toLowerCase().includes("presence") || msg.toLowerCase().includes("pin")) {
              window.metavault.flyoutAction({
                type: "open-app",
                nav: { kind: "approval", id: grant.grantId },
              });
              return;
            }
            errorBanner = "Could not approve here. Open MetaVault to review.";
          })
          .finally(() => {
            busyIds.delete(grant.grantId);
            paint();
          });
      });
      actions.append(approveBtn);
    }

    const denyBtn = node("button", "btn btn-deny", "Deny");
    denyBtn.type = "button";
    denyBtn.disabled = busy;
    denyBtn.addEventListener("click", () => {
      busyIds.add(grant.grantId);
      errorBanner = "";
      paint();
      void window.metavault
        .deny(grant.grantId)
        .catch(() => {
          errorBanner = "Could not deny request.";
        })
        .finally(() => {
          busyIds.delete(grant.grantId);
          paint();
        });
    });
    actions.append(denyBtn);
    card.append(actions);
    return card;
  };

  const paint = (): void => {
    const activeEl = document.activeElement;
    const focusedRegId =
      activeEl instanceof HTMLInputElement && activeEl.dataset["regId"] !== undefined
        ? activeEl.dataset["regId"]
        : null;

    root.replaceChildren();
    const locked = state.uiLocked || state.daemonLocked;
    const armed = isFlyoutApprovalArmed(Date.now(), armedAtMs);

    // Header
    const header = node("header", "flyout-header");
    const brand = node("div", "flyout-brand");
    brand.append(node("span", "flyout-brand-dot"));
    brand.append(node("span", "flyout-brand-title", "MetaVault"));

    const pillClass = state.daemonLocked
      ? "flyout-status-pill is-daemon-locked"
      : state.uiLocked
        ? "flyout-status-pill is-ui-locked"
        : "flyout-status-pill is-unlocked";
    const pillLabel = state.daemonLocked
      ? "Vault Locked"
      : state.uiLocked
        ? "UI Locked"
        : "Unlocked";
    brand.append(node("span", pillClass, pillLabel));
    header.append(brand);

    const headerActions = node("div", "flyout-header-actions");
    const muted = state.soundMode === "off";
    const muteBtn = node("button", muted ? "flyout-icon-btn is-muted" : "flyout-icon-btn", muted ? "Muted" : "Sound");
    muteBtn.type = "button";
    muteBtn.title = muted ? "Unmute notification sounds" : "Mute notification sounds";
    muteBtn.setAttribute("aria-pressed", muted ? "true" : "false");
    muteBtn.addEventListener("click", () => {
      window.metavault.flyoutAction({ type: "toggle-mute" });
    });

    const openBtn = node("button", "flyout-open-btn", "Open App \u2197");
    openBtn.type = "button";
    openBtn.addEventListener("click", () => {
      window.metavault.flyoutAction({ type: "open-app" });
    });
    headerActions.append(muteBtn, openBtn);
    header.append(headerActions);
    root.append(header);

    // Body
    const body = node("main", "flyout-body");
    if (errorBanner !== "") {
      body.append(node("p", "flyout-banner-error", errorBanner));
    }

    if (locked) {
      const box = node("section", "flyout-locked");
      const waitingTotal = state.pendingCount + state.registrationCount;
      box.append(
        node(
          "p",
          "flyout-locked-title",
          state.daemonLocked ? "Vault daemon is locked" : "MetaVault UI is locked",
        ),
      );
      box.append(
        node(
          "p",
          "flyout-locked-sub",
          waitingTotal > 0
            ? `${String(waitingTotal)} agent request${waitingTotal === 1 ? "" : "s"} waiting. Details stay hidden until you unlock.`
            : state.daemonLocked
              ? "Master key is zeroed in memory. Unlock with your vault password."
              : "Background standing read approvals remain active.",
        ),
      );
      const unlockBtn = node("button", "btn btn-approve", "Unlock in MetaVault");
      unlockBtn.type = "button";
      unlockBtn.addEventListener("click", () => {
        window.metavault.flyoutAction({
          type: "open-app",
          nav: { kind: "unlock", target: state.daemonLocked ? "daemon" : "ui" },
        });
      });
      box.append(unlockBtn);
      body.append(box);
    } else if (state.grants.length === 0 && state.registrations.length === 0) {
      const empty = node("section", "flyout-empty");
      empty.append(node("p", "flyout-empty-title", "All clear \u2014 no pending agent requests"));
      empty.append(
        node(
          "p",
          "flyout-empty-sub",
          `${String(state.credentialCount)} stored credential${state.credentialCount === 1 ? "" : "s"} protected by policy`,
        ),
      );
      const addBtn = node("button", "btn", "Add Credential\u2026");
      addBtn.type = "button";
      addBtn.addEventListener("click", () => {
        window.metavault.flyoutAction({
          type: "open-app",
          nav: { kind: "add-credential" },
        });
      });
      empty.append(addBtn);
      body.append(empty);
    } else {
      for (const grant of state.grants) {
        body.append(renderGrantCard(grant, armed));
      }
      for (const reg of state.registrations) {
        const card = node("section", "flyout-card");
        const top = node("div", "flyout-card-top");
        top.append(node("span", "flyout-agent", reg.name));
        top.append(node("span", "flyout-tag is-warn", "Verify Agent"));
        card.append(top);
        card.append(
          node(
            "p",
            "flyout-explain",
            `Agent "${reg.agentId}" asked to register. Enter the 6-digit code shown in its chat.`,
          ),
        );
        const actions = node("div", "flyout-actions");
        const input = document.createElement("input");
        input.type = "text";
        input.inputMode = "numeric";
        input.maxLength = 6;
        input.placeholder = "6-digit code";
        input.className = "flyout-code-input";
        input.dataset["regId"] = reg.id;
        input.value = regDrafts.get(reg.id) ?? "";
        input.addEventListener("input", () => {
          regDrafts.set(reg.id, input.value);
        });

        const busy = busyIds.has(reg.id);
        const confirmBtn = node("button", "btn btn-approve", "Confirm");
        confirmBtn.type = "button";
        confirmBtn.disabled = busy || !armed;
        confirmBtn.addEventListener("click", () => {
          if (!isFlyoutApprovalArmed(Date.now(), armedAtMs)) return;
          const code = input.value.trim();
          if (!/^[0-9]{6}$/.test(code)) {
            errorBanner = "Enter the 6-digit verification code from the agent chat.";
            paint();
            return;
          }
          busyIds.add(reg.id);
          errorBanner = "";
          paint();
          void window.metavault
            .decideAgentRegistration(reg.id, "approve", code)
            .then(() => {
              regDrafts.delete(reg.id);
            })
            .catch(() => {
              errorBanner = "Code did not match or registration expired.";
            })
            .finally(() => {
              busyIds.delete(reg.id);
              paint();
            });
        });

        const denyBtn = node("button", "btn btn-deny", "Deny");
        denyBtn.type = "button";
        denyBtn.disabled = busy;
        denyBtn.addEventListener("click", () => {
          busyIds.add(reg.id);
          errorBanner = "";
          paint();
          void window.metavault
            .decideAgentRegistration(reg.id, "deny")
            .then(() => {
              regDrafts.delete(reg.id);
            })
            .catch(() => {
              errorBanner = "Could not deny registration.";
            })
            .finally(() => {
              busyIds.delete(reg.id);
              paint();
            });
        });
        actions.append(input, confirmBtn, denyBtn);
        card.append(actions);
        body.append(card);
      }
    }
    root.append(body);

    // Footer: two explicit lock options
    const footer = node("footer", "flyout-footer");
    const lockUiBtn = node("button", "btn", "Lock UI");
    lockUiBtn.type = "button";
    lockUiBtn.disabled = !state.localAuthConfigured || state.uiLocked;
    lockUiBtn.title = state.localAuthConfigured
      ? "Lock UI screen behind Windows Hello / App PIN (standing read approvals stay active)"
      : "Set App PIN or Windows Hello in Settings to enable UI Lock";
    lockUiBtn.addEventListener("click", () => {
      window.metavault.flyoutAction({ type: "lock-ui" });
    });

    const lockVaultBtn = node("button", "btn btn-deny", "Lock Vault");
    lockVaultBtn.type = "button";
    lockVaultBtn.disabled = !state.canLockDaemon;
    lockVaultBtn.title = state.canLockDaemon
      ? "Zero master key in vaultd until passphrase unlock"
      : state.daemonLocked
        ? "Vault daemon is already locked"
        : "Protect vault with a passphrase to enable daemon lock";
    lockVaultBtn.addEventListener("click", () => {
      window.metavault.flyoutAction({ type: "lock-daemon" });
    });

    footer.append(lockUiBtn, lockVaultBtn);
    root.append(footer);

    if (focusedRegId !== null) {
      const restored = root.querySelector<HTMLInputElement>(`input[data-reg-id="${CSS.escape(focusedRegId)}"]`);
      restored?.focus();
    }
  };

  window.addEventListener("focus", () => {
    rearmFocusGuard();
    paint();
  });

  window.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      event.preventDefault();
      window.metavault.flyoutAction({ type: "close" });
    }
  });

  window.metavault.onFlyoutState((next) => {
    let sawNewGrant = false;
    for (const g of next.grants) {
      if (!knownGrantIds.has(g.grantId)) {
        knownGrantIds.add(g.grantId);
        sawNewGrant = true;
      }
    }
    state = next;
    if (sawNewGrant) {
      rearmFocusGuard();
    }
    paint();
  });

  window.metavault.onLockState(({ uiLocked, daemonLocked }) => {
    state = { ...state, uiLocked, daemonLocked };
    paint();
  });

  rearmFocusGuard();
  paint();
  window.metavault.flyoutReady();
}

if (typeof document !== "undefined") {
  const rootEl = document.getElementById("flyout-root");
  if (rootEl !== null && typeof window !== "undefined" && "metavault" in window) {
    mountFlyout(rootEl);
  }
}
