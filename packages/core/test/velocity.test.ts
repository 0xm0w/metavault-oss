import { describe, expect, it } from "vitest";
import {
  isAgentRateLimited,
  recordAgentRequest,
  type AgentVelocityConfig,
  type AgentVelocityTracker,
} from "../src/policy.js";

describe("Agent Velocity, Rate Limiting & Burst Protection (#18)", () => {
  it("permits requests within normal rate limits", () => {
    let tracker: AgentVelocityTracker = {
      windowStartMs: 1000,
      requestsInWindow: 0,
      consecutiveFailures: 0,
      circuitBrokenUntilMs: 0,
    };

    const velocityCfg: AgentVelocityConfig = {
      maxRequestsPerMinute: 5,
      consecutiveFailureThreshold: 3,
      circuitBreakerDurationMs: 60_000,
    };

    const check1 = isAgentRateLimited(tracker, velocityCfg, 1500);
    expect(check1.limited).toBe(false);

    tracker = recordAgentRequest(tracker, 1500, true);
    expect(tracker.requestsInWindow).toBe(1);
    expect(tracker.consecutiveFailures).toBe(0);
  });

  it("blocks requests when exceeding max requests per minute", () => {
    const tracker: AgentVelocityTracker = {
      windowStartMs: 1000,
      requestsInWindow: 5,
      consecutiveFailures: 0,
      circuitBrokenUntilMs: 0,
    };

    const velocityCfg: AgentVelocityConfig = {
      maxRequestsPerMinute: 5,
      consecutiveFailureThreshold: 3,
      circuitBreakerDurationMs: 60_000,
    };

    const check = isAgentRateLimited(tracker, velocityCfg, 2000);
    expect(check.limited).toBe(true);
    expect(check.reason).toBe("rate-limit-velocity");

    // After 60 seconds (61000ms), window slides and allows
    const checkAfter = isAgentRateLimited(tracker, velocityCfg, 62000);
    expect(checkAfter.limited).toBe(false);
  });

  it("trips the burst circuit breaker on repeated consecutive failures", () => {
    let tracker: AgentVelocityTracker = {
      windowStartMs: 1000,
      requestsInWindow: 2,
      consecutiveFailures: 2,
      circuitBrokenUntilMs: 0,
    };

    const velocityCfg: AgentVelocityConfig = {
      maxRequestsPerMinute: 10,
      consecutiveFailureThreshold: 3,
      circuitBreakerDurationMs: 30_000,
    };

    // 3rd failure occurs - pass custom velocityCfg so circuitBreakerDurationMs is 30,000!
    tracker = recordAgentRequest(tracker, 2000, false, velocityCfg);
    expect(tracker.consecutiveFailures).toBe(3);

    const check = isAgentRateLimited(tracker, velocityCfg, 2500);
    expect(check.limited).toBe(true);
    expect(check.reason).toBe("circuit-breaker-tripped");

    // During cooldown period
    const checkMidCooldown = isAgentRateLimited(tracker, velocityCfg, 20000);
    expect(checkMidCooldown.limited).toBe(true);
    expect(checkMidCooldown.reason).toBe("circuit-breaker-tripped");

    // After cooldown expiration (trip was at 2000ms + 30,000ms = 32,000ms)
    // At 35000ms, the circuit breaker expired, but 35000 - 1000 = 34000ms, which is still in the same 60s window (requestsInWindow = 3 <= 10)
    // Wait, let's verify: at 35000ms, circuitBrokenUntilMs is 32000 <= 35000 -> not circuit broken!
    // But check checkAfterCooldown at 33000ms
    const checkAfterCooldown = isAgentRateLimited(tracker, velocityCfg, 33000);
    expect(checkAfterCooldown.limited).toBe(false);
  });
});
