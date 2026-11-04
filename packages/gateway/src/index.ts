// Gateway process entrypoint. Spawned by the desktop app (Electron in
// Node mode) only when remote access is explicitly enabled. Configuration
// comes from the environment; every input fails closed.
//
//   METAVAULT_VAULT_DIR        vault directory (CA + gateway cert + secret)
//   METAVAULT_DAEMON_URL       loopback daemon base URL
//   METAVAULT_GATEWAY_HOST     bind address: loopback (default) or an
//                              overlay (CGNAT/ULA) address only
//   METAVAULT_GATEWAY_PORT     bind port (default 7078)
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
import { createGatewayServer } from "./server.js";

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
export function isAcceptableGatewayHost(host: string): boolean {
  if (isLoopback(host)) return true;
  const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4 !== null) {
    return Number(v4[1]) === 100 && Number(v4[2]) >= 64 && Number(v4[2]) <= 127;
  }
  return host.toLowerCase().startsWith("fd7a:115c:a1e0:");
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
    fail("gateway host must be loopback or an overlay (CGNAT/ULA) address");
  }
  const port = Number(process.env["METAVAULT_GATEWAY_PORT"] ?? "7078");
  if (!Number.isInteger(port) || port < 1024 || port > 65535) fail("invalid gateway port");
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

  const server = createGatewayServer({
    caCertPem,
    serverCertPem,
    serverKeyPem,
    backend: makeDaemonBackend(daemonBaseUrl, gatewaySecret),
    daemonBaseUrl,
    gatewaySecret,
    transport,
  });
  server.listen(port, host, () => {
    process.stderr.write(`metavault-gateway: listening on ${host}:${String(port)} (${transport})\n`);
  });
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  main();
}
