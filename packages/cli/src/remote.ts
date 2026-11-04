// CLI commands for remote Connections (WP5/DD7): `metavault pair` performs
// the device side of the SAS pairing handshake, `metavault shim` serves
// the loopback MCP channel that forwards over the pinned mTLS session.
import { hostname } from "node:os";
import { homedir } from "node:os";
import { join } from "node:path";
import { Effect } from "effect";
import {
  loadDeviceProfile,
  PairingError,
  runPairingHandshake,
  saveDeviceProfile,
  startShim,
} from "../../gateway/src/device-client.js";
import { DaemonError, UsageError } from "./cli.js";

interface RemoteIo {
  readonly out: (text: string) => void;
  readonly err: (text: string) => void;
}

function flagValue(args: readonly string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index < 0) return undefined;
  const value = args[index + 1];
  return value === undefined || value === "" || value.startsWith("--") ? undefined : value;
}

function defaultProfileDir(): string {
  return join(homedir(), ".metavault", "device");
}

export function pairProgram(io: RemoteIo, args: readonly string[]): Effect.Effect<string, UsageError | DaemonError> {
  return Effect.gen(function* () {
    const code = flagValue(args, "--code");
    if (code === undefined) {
      return yield* Effect.fail(new UsageError({ message: "pair requires --code <pairing-code from the vault screen>" }));
    }
    const host = flagValue(args, "--host") ?? "127.0.0.1";
    const portRaw = flagValue(args, "--port");
    const port = portRaw === undefined ? 7078 : Number(portRaw);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return yield* Effect.fail(new UsageError({ message: "invalid --port" }));
    }
    const name = flagValue(args, "--name") ?? hostname();
    const profileDir = flagValue(args, "--profile-dir") ?? defaultProfileDir();
    const result = yield* Effect.tryPromise({
      try: () =>
        runPairingHandshake({
          host,
          port,
          code,
          deviceName: name,
          platform: process.platform,
          onSas: (sas) => {
            // The SAS is shown to the human here and on the vault screen;
            // it is never logged or persisted.
            io.err(`compare this code with the vault screen, then confirm there:\n\n  ${sas}\n\n`);
          },
        }),
      catch: (err) =>
        new DaemonError({
          message: err instanceof PairingError ? err.message : "pairing failed",
        }),
    });
    yield* Effect.sync(() => {
      saveDeviceProfile(profileDir, {
        deviceId: result.deviceId,
        host,
        port,
        pairedAt: new Date().toISOString(),
        serverCertFingerprint: result.serverCertFingerprint,
      }, result);
    });
    return `paired as ${result.deviceId}; credentials saved to ${profileDir}\nnext: run \`metavault shim\` and point the IDE MCP config at http://127.0.0.1:7079\n`;
  });
}

export function shimProgram(io: RemoteIo, args: readonly string[]): Effect.Effect<string, UsageError | DaemonError> {
  return Effect.gen(function* () {
    const portRaw = flagValue(args, "--port");
    const port = portRaw === undefined ? 7079 : Number(portRaw);
    if (!Number.isInteger(port) || port < 1024 || port > 65535) {
      return yield* Effect.fail(new UsageError({ message: "invalid --port" }));
    }
    const profileDir = flagValue(args, "--profile-dir") ?? defaultProfileDir();
    const handle = yield* Effect.tryPromise({
      try: () => startShim({ profileDir, port }),
      catch: () => new DaemonError({ message: `cannot start the shim; pair this device first (${profileDir})` }),
    });
    const device = yield* Effect.try({
      try: () => loadDeviceProfile(profileDir),
      catch: () => new DaemonError({ message: "device profile unreadable" }),
    });
    io.out(`metavault shim: ${device.profile.deviceId} connected, MCP channel on http://127.0.0.1:${String(handle.port)}\n`);
    return yield* Effect.never;
  });
}
