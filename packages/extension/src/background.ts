import { evaluateGeminiNano } from "./lib/gemini-nano.js";
import { VaultClient } from "./lib/vault-client.js";

const client = new VaultClient("http://127.0.0.1:7077");

async function pollPendingApprovals(): Promise<void> {
  const isHealthy = await client.health();
  if (!isHealthy) {
    if (typeof chrome !== "undefined") {
      void chrome.action.setBadgeText({ text: "" });
    }
    return;
  }

  const pending = await client.getPending();
  if (typeof chrome !== "undefined") {
    const text = pending.length > 0 ? String(pending.length) : "";
    void chrome.action.setBadgeText({ text });
    if (pending.length > 0) {
      void chrome.action.setBadgeBackgroundColor({ color: "#DC2626" });
    }
  }
}

// Set up periodic check if chrome.alarms is available
if (typeof chrome !== "undefined") {
  chrome.alarms.create("poll-vaultd", { periodInMinutes: 0.1 });
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "poll-vaultd") {
      void pollPendingApprovals();
    }
  });
}

// Message handler for Side Panel and Web page queries
if (typeof chrome !== "undefined") {
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message["type"] === "GET_PENDING") {
      client
        .getPending()
        .then((res) => {
          sendResponse(res);
        })
        .catch(() => {
          sendResponse([]);
        });
      return true;
    }
    if (message["type"] === "APPROVE_GRANT") {
      client
        .approveGrant(message["grantId"] as string)
        .then((res) => {
          sendResponse(res);
        })
        .catch(() => {
          sendResponse(false);
        });
      return true;
    }
    if (message["type"] === "EVALUATE_GEMINI") {
      evaluateGeminiNano(message["prompt"] as string)
        .then((res) => {
          sendResponse(res);
        })
        .catch(() => {
          sendResponse(null);
        });
      return true;
    }
    return false;
  });
}
