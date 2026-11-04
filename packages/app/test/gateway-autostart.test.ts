import { describe, expect, it } from "vitest";
import { autostartGatewayWhenRemoteEnabled, type GatewayAutostartDeps } from "../src/gateway-autostart.js";

const makeDeps = (overrides: Partial<GatewayAutostartDeps> = {}) => {
  const lines: string[] = [];
  const calls: { method: string; path: string }[] = [];
  let ensured = 0;
  const deps: GatewayAutostartDeps = {
    callDaemonFn: (input) => {
      calls.push(input);
      return Promise.resolve({ enabled: true });
    },
    ensureGatewayFn: () => {
      ensured += 1;
      return Promise.resolve("started");
    },
    waitFn: () => Promise.resolve(),
    logFn: (line) => { lines.push(line); },
    ...overrides,
  };
  return { deps, lines, calls, ensured: () => ensured };
};

describe("autostartGatewayWhenRemoteEnabled", () => {
  it("starts the gateway once remote answers enabled", async () => {
    const { deps, lines, ensured } = makeDeps();
    const outcome = await autostartGatewayWhenRemoteEnabled(deps);
    expect(outcome).toBe("started");
    expect(ensured()).toBe(1);
    expect(lines.some((l) => l.includes("remote enabled") && l.includes("started"))).toBe(true);
  });

  it("does not start the gateway when remote is disabled, and says so", async () => {
    const { deps, lines, ensured } = makeDeps({
      callDaemonFn: () => Promise.resolve({ enabled: false }),
    });
    const outcome = await autostartGatewayWhenRemoteEnabled(deps);
    expect(outcome).toBe("disabled");
    expect(ensured()).toBe(0);
    expect(lines.some((l) => l.includes("remote disabled"))).toBe(true);
  });

  it("retries while the daemon is unreachable, then gives up with a diagnostic", async () => {
    let attempts = 0;
    const { deps, lines, ensured } = makeDeps({
      callDaemonFn: () => {
        attempts += 1;
        return Promise.reject(new Error("daemon unreachable"));
      },
      maxAttempts: 3,
    });
    const outcome = await autostartGatewayWhenRemoteEnabled(deps);
    expect(outcome).toBe("unreachable");
    expect(attempts).toBe(3);
    expect(ensured()).toBe(0);
    expect(lines.some((l) => l.includes("daemon never answered") && l.includes("NOT started"))).toBe(true);
  });

  it("recovers when the daemon comes up on a later attempt", async () => {
    let attempts = 0;
    const { deps, ensured } = makeDeps({
      callDaemonFn: () => {
        attempts += 1;
        if (attempts < 3) return Promise.reject(new Error("not yet"));
        return Promise.resolve({ enabled: true });
      },
      maxAttempts: 5,
    });
    const outcome = await autostartGatewayWhenRemoteEnabled(deps);
    expect(outcome).toBe("started");
    expect(ensured()).toBe(1);
  });

  it("retries when the gateway ensure itself throws, and logs the reason", async () => {
    let ensureAttempts = 0;
    const { deps, lines } = makeDeps({
      ensureGatewayFn: () => {
        ensureAttempts += 1;
        if (ensureAttempts < 2) return Promise.reject(new Error("spawn failed"));
        return Promise.resolve("started");
      },
      maxAttempts: 4,
    });
    const outcome = await autostartGatewayWhenRemoteEnabled(deps);
    expect(outcome).toBe("started");
    expect(ensureAttempts).toBe(2);
    expect(lines.some((l) => l.includes("spawn failed"))).toBe(true);
  });
});
