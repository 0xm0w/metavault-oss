import { describe, expect } from "vitest";
import { it } from "@effect/vitest";
import { Effect } from "effect";
import { VaultStore, VaultStoreTest } from "../src/storage.js";
import { encryptSecret, decryptSecret } from "../src/crypto.js";

describe("Multi-Project Graph and Scoped Credentials in VaultStore", () => {
  const masterKey = Buffer.alloc(32, 42);

  it.effect("creates, retrieves, lists, and deletes projects", () =>
    Effect.gen(function* () {
      const store = yield* VaultStore;
      const proj = yield* store.createProject({
        id: "proj_web_123",
        slug: "web",
        name: "Web Frontend",
        rootPath: "/workspaces/metavault/apps/web",
        stackTags: ["nextjs", "react", "tailwind"],
      });
      expect(proj.slug).toBe("web");
      expect(proj.createdAt).toBeDefined();

      const bySlug = yield* store.getProject("web");
      expect(bySlug?.id).toBe("proj_web_123");
      expect(bySlug?.stackTags).toEqual(["nextjs", "react", "tailwind"]);

      const byId = yield* store.getProject("proj_web_123");
      expect(byId?.slug).toBe("web");

      const list = yield* store.listProjects();
      expect(list.length).toBe(1);
      expect(list[0]?.slug).toBe("web");

      yield* store.deleteProject("proj_web_123");
      const empty = yield* store.getProject("web");
      expect(empty).toBeUndefined();
    }).pipe(Effect.provide(VaultStoreTest(masterKey))));

  it.effect("manages project environments with write/read approval gates", () =>
    Effect.gen(function* () {
      const store = yield* VaultStore;
      yield* store.upsertProjectEnvironment({
        projectId: "proj_api",
        env: "dev",
        requireApprovalForReads: false,
        allowAgentWrites: true,
      });
      yield* store.upsertProjectEnvironment({
        projectId: "proj_api",
        env: "prod",
        requireApprovalForReads: true,
        allowAgentWrites: false,
      });

      const envs = yield* store.listProjectEnvironments("proj_api");
      expect(envs.length).toBe(2);
      const prod = envs.find((e) => e.env === "prod");
      expect(prod?.requireApprovalForReads).toBe(true);
      expect(prod?.allowAgentWrites).toBe(false);
    }).pipe(Effect.provide(VaultStoreTest(masterKey))));

  it.effect("links projects together for Cross-Repo Radar", () =>
    Effect.gen(function* () {
      const store = yield* VaultStore;
      const link = yield* store.addProjectLink({
        sourceProjectId: "proj_web",
        targetProjectId: "proj_api",
        kind: "api-consumer",
        contractPaths: ["src/lib/api-client.ts", "src/types/contracts.ts"],
      });
      expect(link.id).toBeDefined();
      expect(link.contractPaths).toContain("src/lib/api-client.ts");

      const webLinks = yield* store.listProjectLinks("proj_web");
      expect(webLinks.length).toBe(1);
      expect(webLinks[0]?.targetProjectId).toBe("proj_api");

      const apiLinks = yield* store.listProjectLinks("proj_api");
      expect(apiLinks.length).toBe(1);
      expect(apiLinks[0]?.sourceProjectId).toBe("proj_web");

      yield* store.deleteProjectLink(link.id);
      expect((yield* store.listProjectLinks("proj_web")).length).toBe(0);
    }).pipe(Effect.provide(VaultStoreTest(masterKey))));

  it.effect("tracks project environment key requirements for env parity checks", () =>
    Effect.gen(function* () {
      const store = yield* VaultStore;
      yield* store.upsertProjectEnvRequirement({
        projectId: "proj_web",
        env: "all",
        alias: "NEXT_PUBLIC_APP_URL",
        required: true,
        scopeCeiling: "config.read",
        description: "Application base URL",
      });
      yield* store.upsertProjectEnvRequirement({
        projectId: "proj_web",
        env: "prod",
        alias: "STRIPE_SECRET_KEY",
        required: true,
        scopeCeiling: "charges.write",
        description: "Production Stripe Secret Key",
      });

      const allReqs = yield* store.listProjectEnvRequirements("proj_web", "all");
      expect(allReqs.length).toBe(2);

      const prodReqs = yield* store.listProjectEnvRequirements("proj_web", "prod");
      expect(prodReqs.length).toBe(2);
    }).pipe(Effect.provide(VaultStoreTest(masterKey))));

  it.effect("enables/configures plugins per project", () =>
    Effect.gen(function* () {
      const store = yield* VaultStore;
      yield* store.setProjectPlugin({
        projectId: "proj_web",
        pluginId: "@jevault/agent-anti-cheat",
        enabled: true,
        config: { blockDeletedAssertions: true },
      });

      const plugins = yield* store.listProjectPlugins("proj_web");
      expect(plugins.length).toBe(1);
      expect(plugins[0]?.pluginId).toBe("@jevault/agent-anti-cheat");
      expect(plugins[0]?.enabled).toBe(true);
      expect(plugins[0]?.config).toEqual({ blockDeletedAssertions: true });
    }).pipe(Effect.provide(VaultStoreTest(masterKey))));

  it.effect("records and retrieves Shift Handoff flight logs across IDEs", () =>
    Effect.gen(function* () {
      const store = yield* VaultStore;
      const handoff1 = yield* store.recordShiftHandoff({
        projectId: "proj_web",
        branch: "feat/billing",
        agentId: "claude-code",
        ide: "Terminal",
        checkpointType: "shift_change",
        summary: "Implemented checkout session hook; tests still need coverage",
        details: { touchedFiles: ["src/checkout.ts"], remainingBlockers: 1 },
      });
      expect(handoff1.id).toBeDefined();

      const latest = yield* store.getLatestShiftHandoff("proj_web", "feat/billing");
      expect(latest?.agentId).toBe("claude-code");
      expect(latest?.summary).toContain("Implemented checkout session hook");
      expect(latest?.details["remainingBlockers"]).toBe(1);

      const history = yield* store.listShiftHandoffs("proj_web", 10);
      expect(history.length).toBe(1);
    }).pipe(Effect.provide(VaultStoreTest(masterKey))));

  it.effect("resolves scoped credentials with hierarchical fallback", () =>
    Effect.gen(function* () {
      const store = yield* VaultStore;
      const secretGlobal = encryptSecret(masterKey, "sk_global_123");
      const secretProjDev = encryptSecret(masterKey, "sk_proj_dev_456");
      const secretProjProd = encryptSecret(masterKey, "sk_proj_prod_789");

      // 1. Add global credential
      yield* store.addCredential("shared_api_key", "read", secretGlobal);

      // 2. Add project-specific scoped credentials
      yield* store.addCredential("stripe", "charges.read", secretProjDev, "stripe.com", "secret", "", "proj_web", "dev");
      yield* store.addCredential("stripe", "charges.write", secretProjProd, "stripe.com", "secret", "", "proj_web", "prod");

      // Exact match: proj_web dev -> returns dev secret
      const devCred = yield* store.getScopedCredential("stripe", "proj_web", "dev");
      expect(devCred).toBeDefined();
      if (devCred) {
        expect(decryptSecret(masterKey, devCred.ciphertext)).toBe("sk_proj_dev_456");
      }

      // Exact match: proj_web prod -> returns prod secret
      const prodCred = yield* store.getScopedCredential("stripe", "proj_web", "prod");
      expect(prodCred).toBeDefined();
      if (prodCred) {
        expect(decryptSecret(masterKey, prodCred.ciphertext)).toBe("sk_proj_prod_789");
      }

      // Hierarchical fallback to global when scoped key does not exist at project level
      const fallbackGlobal = yield* store.getScopedCredential("shared_api_key", "proj_web", "dev");
      expect(fallbackGlobal).toBeDefined();
      if (fallbackGlobal) {
        expect(decryptSecret(masterKey, fallbackGlobal.ciphertext)).toBe("sk_global_123");
      }

      // Nonexistent alias
      const none = yield* store.getScopedCredential("nonexistent", "proj_web", "dev");
      expect(none).toBeUndefined();
    }).pipe(Effect.provide(VaultStoreTest(masterKey))));
});
