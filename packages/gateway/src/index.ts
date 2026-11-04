// Gateway process entrypoint. Spawned by the desktop app (Electron in
// Node mode) only when remote access is explicitly enabled. Configuration
// comes from the environment; every input fails closed.
//
//   METAVAULT_VAULT_DIR        vault directory (CA + gateway cert + secret)
//   METAVAULT_DAEMON_URL       loopback daemon base URL
//   METAVAULT_GATEWAY_HOST     bind address: loopback (default) or an
//                              overlay (CGNAT/ULA) address only
//   METAVAULT_GATEWAY_PORT     pairing listener port (default 7078):
//                              server-only TLS (the pairing client cannot
//                              validate the vault's identity until the
//                              human SAS comparison), pairing routes only
//   METAVAULT_GATEWAY_DEVICE_PORT
//                              device listener port (default pairing + 1):
//                              strict mTLS, client cert required at the
//                              TLS handshake
//   METAVAULT_TRANSPORT        audit label: "loopback" (default) | "overlay"
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import {
  GATEWAY_CERT_FILE,
  GATEWAY_KEY_FILE,
  VAULT_CA_CERT_FILE,
} from "../../core/src/vault-ca.js";
import { makeDaemonBackend } from "./daemon-backend.js";
import { createGatewayServers } from "./server.js";

function fail(message: string): never {
  process.stderr.write(`metavault-gateway: ${message}\n`);
  process.exit(1);
}

function isLoopback(host: string): boolean {
  return host === "127.0.0.1" || host === "::1" || host === "localhost";
}

// The gateway never binds a wildcard or plain LAN address. An overlay
// address is a CGNAT (100.64.0.0/10) or the overlay ULA /48 address the
// user configures explicitly after joining their own overlay network.
// Loopback-only until an explicit transport/interface decision approves
// anything broader: overlay ranges alone do not establish tailnet
// membership, so accepting them would be unreviewed exposure.
export function isAcceptableGatewayHost(host: string): boolean {
  return isLoopback(host);
}

export function main(): void {
  const vaultDir = process.env["METAVAULT_VAULT_DIR"];
  if (vaultDir === undefined || vaultDir === "") fail("METAVAULT_VAULT_DIR is required");
  const daemonBaseUrl = process.env["METAVAULT_DAEMON_URL"] ?? "http://127.0.0.1:7077";
  if (!daemonBaseUrl.startsWith("http://127.0.0.1") && !daemonBaseUrl.startsWith("http://localhost") && !daemonBaseUrl.startsWith("http://[::1]")) {
    fail("daemon URL must be loopback");
  }
  const host = process.env["METAVAULT_GATEWAY_HOST"] ?? "127.0.0.1";
  if (!isAcceptableGatewayHost(host)) {
    fail("gateway host must be a loopback address");
  }
  const port = Number(process.env["METAVAULT_GATEWAY_PORT"] ?? "7078");
  if (!Number.isInteger(port) || port < 1024 || port > 65535) fail("invalid gateway port");
  const devicePort = Number(process.env["METAVAULT_GATEWAY_DEVICE_PORT"] ?? String(port + 1));
  if (!Number.isInteger(devicePort) || devicePort < 1024 || devicePort > 65535 || devicePort === port) {
    fail("invalid gateway device port");
  }
  const transport = process.env["METAVAULT_TRANSPORT"] === "overlay" ? "overlay" : "loopback";

  const read = (name: string): string => {
    try {
      return readFileSync(join(vaultDir, name), "utf8");
    } catch {
      fail(`missing ${name}: enable remote access in the app first`);
    }
  };
  const caCertPem = read(VAULT_CA_CERT_FILE);
  const serverCertPem = read(GATEWAY_CERT_FILE);
  const serverKeyPem = read(GATEWAY_KEY_FILE);
  const gatewaySecret = read("metavault.gateway-token").trim();

  const servers = createGatewayServers({
    caCertPem,
    serverCertPem,
    serverKeyPem,
    backend: makeDaemonBackend(daemonBaseUrl, gatewaySecret),
    daemonBaseUrl,
    gatewaySecret,
    transport,
  });
  // Either listener failing (port conflict, bind error) stops the whole
  // gateway: never run half-configured.
  const onListenError = (which: string) => (err: Error) => {
    process.stderr.write(`metavault-gateway: ${which} listener failed: ${err.message}\n`);
    servers.pairing.close();
    servers.device.close();
    process.exit(1);
  };
  servers.pairing.once("error", onListenError("pairing"));
  servers.device.once("error", onListenError("device"));
  servers.pairing.listen(port, host, () => {
    process.stderr.write(`metavault-gateway: pairing on ${host}:${String(port)} (${transport})\n`);
  });
  servers.device.listen(devicePort, host, () => {
    process.stderr.write(`metavault-gateway: devices (mTLS) on ${host}:${String(devicePort)} (${transport})\n`);
  });
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  main();
}
