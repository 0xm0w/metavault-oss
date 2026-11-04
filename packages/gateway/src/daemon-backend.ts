// Loopback client from the gateway to the daemon's /internal/* routes.
// Authenticated with the shared gateway secret; no other route family is
// reachable through this client by construction.
import type { GatewayBackend, DeviceStatus } from "./server.js";

export function makeDaemonBackend(daemonBaseUrl: string, gatewaySecret: string): GatewayBackend {
  const base = daemonBaseUrl.replace(/\/+$/, "");
  const call = async (path: string, body: Record<string, unknown>): Promise<unknown> => {
    const res = await fetch(`${base}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-metavault-gateway-secret": gatewaySecret },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      throw new Error(`daemon internal route failed: ${String(res.status)}`);
    }
    return (await res.json()) as unknown;
  };
  return {
    pairingActive: async () => {
      const out = (await call("/internal/pair-open", {})) as { open: boolean };
      return out.open;
    },
    deviceStatus: async (fingerprint) => {
      const out = (await call("/internal/device-status", { fingerprint })) as DeviceStatus;
      return out;
    },
    pairBegin: async (input) => {
      return (await call("/internal/pair-begin", { ...input })) as {
        pairingId: string;
        serverNonce: string;
      };
    },
    pairSas: async (pairingId, sas) => {
      await call("/internal/pair-sas", { pairingId, sas });
    },
    pairStatus: async (pairingId) => {
      return (await call("/internal/pair-status", { pairingId })) as {
        status: string;
        certificatePem?: string;
        caCertPem?: string;
      };
    },
  };
}
