import { VaultClient } from "./lib/vault-client.js";

const client = new VaultClient("http://127.0.0.1:7077");

async function render(): Promise<void> {
  const container = document.getElementById("pending-list");
  const countBadge = document.getElementById("pending-count");
  if (!container || !countBadge) return;

  const healthy = await client.health();
  const statusEl = document.getElementById("status-indicator");
  if (statusEl) {
    statusEl.textContent = healthy ? "● Armed (Connected to vaultd)" : "○ Offline (vaultd not detected)";
    statusEl.className = healthy ? "status-indicator is-connected" : "status-indicator";
  }

  if (!healthy) {
    container.innerHTML = '<div class="empty-state">vaultd daemon not detected. Start MetaVault to begin approving requests.</div>';
    countBadge.textContent = "0";
    return;
  }

  const pending = await client.getPending();
  countBadge.textContent = String(pending.length);

  if (pending.length === 0) {
    container.innerHTML = '<div class="empty-state">No pending approval requests. Your agents are within policy ceilings.</div>';
    return;
  }

  container.innerHTML = "";
  for (const item of pending) {
    const card = document.createElement("div");
    card.className = "approval-card";

    const title = document.createElement("div");
    title.className = "approval-title";
    title.textContent = `${item.alias} · ${item.requestedScope}`;

    const agent = document.createElement("div");
    agent.className = "approval-agent";
    agent.textContent = `Agent: ${item.agentId} (${item.ide})`;

    const reason = document.createElement("div");
    reason.className = "approval-reason";
    reason.textContent = `"${item.reason}"`;

    const actions = document.createElement("div");
    actions.className = "approval-actions";

    const approveBtn = document.createElement("button");
    approveBtn.className = "btn-approve";
    approveBtn.textContent = "Approve";
    approveBtn.addEventListener("click", () => {
      void (async () => {
        approveBtn.disabled = true;
        approveBtn.textContent = "Approving...";
        await client.approveGrant(item.grantId);
        await render();
      })();
    });

    actions.append(approveBtn);
    card.append(title, agent, reason, actions);
    container.append(card);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  void render();
  setInterval(() => void render(), 3000);
});
