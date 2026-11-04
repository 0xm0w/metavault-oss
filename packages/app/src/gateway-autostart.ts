// Packaged-app gateway autostart, extracted from main.ts so the retry and
// diagnostics behavior is unit-testable. Every attempt and outcome is
// logged: packaged Electron has no console the user can see, and the
// clean-install smoke test collects this log on failure.
//
// The gateway refuses to run unconfigured, so "remote disabled" is a
// definitive no-op answer; only daemon/ensure failures retry, and the loop
// is strictly bounded.
export interface GatewayAutostartDeps {
  readonly callDaemonFn: (input: { readonly method: string; readonly path: string }) => Promise<unknown>;
  // Starts (or adopts) the bundled gateway; returns the launcher status.
  readonly ensureGatewayFn: () => Promise<string>;
  readonly waitFn: (ms: number) => Promise<void>;
  readonly logFn: (line: string) => void;
  readonly maxAttempts?: number;
}

export type GatewayAutostartOutcome = "started" | "disabled" | "unreachable";

export async function autostartGatewayWhenRemoteEnabled(deps: GatewayAutostartDeps): Promise<GatewayAutostartOutcome> {
  const maxAttempts = deps.maxAttempts ?? 30;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const remote = (await deps.callDaemonFn({ method: "GET", path: "/settings/remote" })) as { enabled?: boolean };
      if (remote.enabled === true) {
        const status = await deps.ensureGatewayFn();
        deps.logFn(`gateway autostart: remote enabled, gateway ensure -> ${status} (attempt ${String(attempt)})`);
        return "started";
      }
      deps.logFn(`gateway autostart: remote disabled, gateway not started (attempt ${String(attempt)})`);
      return "disabled";
    } catch (err) {
      deps.logFn(`gateway autostart: attempt ${String(attempt)}/${String(maxAttempts)} failed: ${(err as Error).message}`);
      await deps.waitFn(1000);
    }
  }
  deps.logFn(`gateway autostart: daemon never answered after ${String(maxAttempts)} attempts; gateway NOT started`);
  return "unreachable";
}
