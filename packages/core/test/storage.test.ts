// packages/core/test/storage.test.ts
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect } from "vitest";
import { it } from "@effect/vitest";
import { Effect } from "effect";
import Database from "better-sqlite3";
import { encryptSecret, decryptSecret } from "../src/crypto.js";
import { VaultStore, VaultStoreLive, VaultStoreTest } from "../src/storage.js";
import type { AuditEvent } from "../src/types.js";

describe("vault storage", () => {
  const key = Buffer.alloc(32, 7);
  it("round-trips a secret and never stores plaintext", () => {
    const blob = encryptSecret(key, "[REDACTED]");
    expect(blob).not.toContain("[REDACTED]");
    expect(decryptSecret(key, blob)).toBe("[REDACTED]");
  });
  it.effect("stores ciphertext by alias", () =>
    Effect.gen(function* () {
      const store = yield* VaultStore;
      yield* store.addCredential("stripe", "charges.read", encryptSecret(key, "[REDACTED]"));
      const got = yield* store.getCredential("stripe");
      expect(JSON.stringify(got)).not.toContain("[REDACTED]");
      expect(yield* store.getCredential("nope")).toBeUndefined();
    }).pipe(Effect.provide(VaultStoreTest(key))));
  it.effect("returns audit events in append order with fields intact", () =>
    Effect.gen(function* () {
      const store = yield* VaultStore;
      const events: AuditEvent[] = [
        {
          ts: "2026-10-31T00:00:00.000Z",
          agentId: "agent-a",
          alias: "stripe",
          scope: "charges.read",
          stage: "requested",
          detail: "initial request",
        },
        {
          ts: "2026-10-31T00:00:01.000Z",
          agentId: "agent-a",
          alias: "stripe",
          scope: "charges.read",
          stage: "approved",
          detail: "approved by human",
          modelId: "test-model-1",
        },
        {
          ts: "2026-10-31T00:00:02.000Z",
          agentId: "agent-b",
          alias: "github",
          scope: "repo.read",
          stage: "executed",
          detail: "tool executed",
        },
      ];
      for (const event of events) {
        yield* store.appendAudit(event);
      }
      const listed = yield* store.listAudit();
      expect(listed).toEqual(events);
      expect(listed.map((event) => event.stage)).toEqual([
        "requested",
        "approved",
        "executed",
      ]);
      expect(Object.keys(listed[0] ?? {})).not.toContain("modelId");
      expect(listed[1]?.modelId).toBe("test-model-1");
    }).pipe(Effect.provide(VaultStoreTest(key))));
  it.effect("persists credentials across VaultStoreLive instances on the same file", () => {
    const dir = mkdtempSync(join(tmpdir(), "openvault-storage-test-"));
    const dbPath = join(dir, "vault.db");
    const blob = encryptSecret(key, "persisted-secret");
    return Effect.gen(function* () {
      yield* Effect.gen(function* () {
        const store = yield* VaultStore;
        yield* store.addCredential("github", "repo.read", blob);
      }).pipe(Effect.provide(VaultStoreLive(dbPath, key)));
      const got = yield* Effect.gen(function* () {
        const store = yield* VaultStore;
        return yield* store.getCredential("github");
      }).pipe(Effect.provide(VaultStoreLive(dbPath, key)));
      expect(got).toEqual({ scopeCeiling: "repo.read", ciphertext: blob, website: "" });
      expect(got === undefined ? undefined : decryptSecret(key, got.ciphertext)).toBe(
        "persisted-secret",
      );
    }).pipe(
      // Best-effort cleanup: VaultStore exposes no close handle, so on
      // Windows the open SQLite file may not be deletable until exit.
      Effect.ensuring(
        Effect.sync(() => {
          try {
            rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
          } catch {
            // Ignored: the OS temp reaper removes leftovers after exit.
          }
        }),
      ),
    );
  });
  it.effect("round-trips website and defaults legacy rows to empty website", () =>
    Effect.gen(function* () {
      const store = yield* VaultStore;
      yield* store.addCredential("cf", "dns.read", encryptSecret(key, "s3cret"), "cloudflare.com");
      const got = yield* store.getCredential("cf");
      expect(got?.website).toBe("cloudflare.com");
      expect(got?.scopeCeiling).toBe("dns.read");
      yield* store.addCredential("legacy", "repo.read", encryptSecret(key, "old"));
      expect((yield* store.getCredential("legacy"))?.website).toBe("");
      const metas = yield* store.listCredentials();
      expect(metas).toEqual([
        { alias: "cf", scopeCeiling: "dns.read", website: "cloudflare.com" },
        { alias: "legacy", scopeCeiling: "repo.read", website: "" },
      ]);
      yield* store.updateCredential("cf", "dns.write", encryptSecret(key, "new"), "example.com");
      expect((yield* store.getCredential("cf"))?.website).toBe("example.com");
      yield* store.deleteCredential("cf");
      expect(yield* store.getCredential("cf")).toBeUndefined();
    }).pipe(Effect.provide(VaultStoreTest(key))));
  it("migrates an old DB without a website column", () => {
    const dir = mkdtempSync(join(tmpdir(), "openvault-migrate-test-"));
    const dbPath = join(dir, "vault.db");
    const raw = new Database(dbPath);
    raw.exec("CREATE TABLE credentials (alias TEXT PRIMARY KEY, ceiling TEXT NOT NULL, ciphertext TEXT NOT NULL); CREATE TABLE audit (ts TEXT NOT NULL, agent TEXT NOT NULL, alias TEXT NOT NULL, scope TEXT NOT NULL, stage TEXT NOT NULL, detail TEXT NOT NULL, model_id TEXT);");
    raw.prepare("INSERT INTO credentials (alias, ceiling, ciphertext) VALUES (?, ?, ?)").run("old", "repo.read", encryptSecret(key, "legacy-secret"));
    raw.close();
    return Effect.runPromise(
      Effect.gen(function* () {
        const store = yield* VaultStore;
        const got = yield* store.getCredential("old");
        expect(got?.website).toBe("");
        expect(got === undefined ? undefined : decryptSecret(key, got.ciphertext)).toBe("legacy-secret");
        yield* store.addCredential("fresh", "dns.read", encryptSecret(key, "x"), "example.com");
        expect((yield* store.getCredential("fresh"))?.website).toBe("example.com");
      }).pipe(Effect.provide(VaultStoreLive(dbPath, key))),
    );
  });
  it("rejects decryption with a different key", () => {
    const blob = encryptSecret(key, "top-secret");
    const wrongKey = Buffer.alloc(32, 9);
    expect(wrongKey).not.toEqual(key);
    expect(() => decryptSecret(wrongKey, blob)).toThrow();
  });
  it("rejects decryption when the ciphertext segment is tampered with", () => {
    const blob = encryptSecret(key, "top-secret");
    const parts = blob.split(".");
    const ciphertext = parts[2] ?? "";
    const flipped = (ciphertext.startsWith("A") ? "B" : "A") + ciphertext.slice(1);
    const tampered = [parts[0] ?? "", parts[1] ?? "", flipped].join(".");
    expect(tampered).not.toBe(blob);
    expect(() => decryptSecret(key, tampered)).toThrow();
  });
});
