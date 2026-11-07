import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import Database from "better-sqlite3";
import { basename, dirname, join } from "node:path";
import { hardenOwnerOnly } from "./owner-acl.js";
import { Context, Effect, Layer } from "effect";
import { StorageError } from "./errors.js";
import { DEFAULT_AGENT_SECURITY_SETTINGS, DEFAULT_LOCAL_AUTH_RECORD, DEFAULT_WARDEN_SETTINGS, LEGACY_LOCAL_PROVIDERS, SUGGESTED_LOCAL_BASE_URL, defaultWardenSettings, normalizeWardenProvider, type AgentSecuritySettings, type LocalAuthRecord, type WardenSettings } from "./settings.js";
import type { AuditEvent, DecisionSource, Risk } from "./types.js";
import { CARD_KIND, SECRET_KIND, type CredentialKind } from "./card.js";
import type {
  ProjectRecord,
  ProjectEnvironmentRecord,
  ProjectEnvironment,
  ProjectLinkRecord,
  ProjectLinkKind,
  ProjectEnvRequirementRecord,
  ProjectPluginRecord,
  ShiftHandoffRecord,
  ShiftHandoffType,
} from "./spine.js";

// kind is "secret" (API key / token) or "card" (payment card). publicMeta
// is non-secret JSON kept in clear (for cards: brand + last 4 only).
export interface CredentialRecord {
  readonly scopeCeiling: string;
  readonly ciphertext: string;
  readonly website: string;
  readonly kind: CredentialKind;
  readonly publicMeta: string;
  readonly projectId?: string;
  readonly env?: string;
}

export interface CredentialMeta {
  readonly alias: string;
  readonly scopeCeiling: string;
  readonly website: string;
  readonly kind?: CredentialKind;
  readonly publicMeta?: string;
  readonly projectId?: string;
  readonly env?: string;
}

export interface AgentRecord {
  readonly id: string;
  readonly name: string;
  readonly token: string; // Empty on stored/listed records. Raw token is returned only at creation/rotation.
  readonly tokenPrefix?: string;
  readonly createdAt: string;
  readonly revoked: boolean;
  // Set when the token is bound to one paired remote device: it then
  // authenticates only inside that device's mTLS session. NULL = local-only.
  readonly deviceId?: string | null;
}

export interface DeviceRecord {
  readonly id: string;
  readonly name: string;
  readonly platform: string;
  readonly certFingerprint: string;
  readonly transport: string;
  readonly createdAt: string;
  readonly lastSeenAt: string | null;
  readonly revoked: boolean;
}

export interface DeviceAliasPolicy {
  readonly deviceId: string;
  readonly alias: string;
  readonly allowWrite: boolean;
}

export interface VaultStoreService {
  readonly addCredential: (
    alias: string,
    scopeCeiling: string,
    ciphertext: string,
    website?: string,
    kind?: CredentialKind,
    publicMeta?: string,
    projectId?: string,
    env?: string,
  ) => Effect.Effect<void, StorageError>;
  readonly updateCredential: (
    alias: string,
    scopeCeiling: string,
    ciphertext: string,
    website: string,
  ) => Effect.Effect<void, StorageError>;
  readonly deleteCredential: (alias: string) => Effect.Effect<void, StorageError>;
  readonly listCredentials: () => Effect.Effect<CredentialMeta[], StorageError>;
  readonly getCredential: (
    alias: string,
  ) => Effect.Effect<CredentialRecord | undefined, StorageError>;
  readonly getScopedCredential: (
    alias: string,
    projectId?: string,
    env?: string,
  ) => Effect.Effect<CredentialRecord | undefined, StorageError>;
  readonly createProject: (
    project: Omit<ProjectRecord, "createdAt">,
  ) => Effect.Effect<ProjectRecord, StorageError>;
  readonly getProject: (idOrSlug: string) => Effect.Effect<ProjectRecord | undefined, StorageError>;
  readonly listProjects: () => Effect.Effect<ProjectRecord[], StorageError>;
  readonly deleteProject: (id: string) => Effect.Effect<void, StorageError>;
  readonly upsertProjectEnvironment: (
    env: ProjectEnvironmentRecord,
  ) => Effect.Effect<void, StorageError>;
  readonly listProjectEnvironments: (
    projectId: string,
  ) => Effect.Effect<ProjectEnvironmentRecord[], StorageError>;
  readonly addProjectLink: (
    link: Omit<ProjectLinkRecord, "id">,
  ) => Effect.Effect<ProjectLinkRecord, StorageError>;
  readonly listProjectLinks: (
    projectId: string,
  ) => Effect.Effect<ProjectLinkRecord[], StorageError>;
  readonly deleteProjectLink: (id: string) => Effect.Effect<void, StorageError>;
  readonly upsertProjectEnvRequirement: (
    req: Omit<ProjectEnvRequirementRecord, "id">,
  ) => Effect.Effect<ProjectEnvRequirementRecord, StorageError>;
  readonly listProjectEnvRequirements: (
    projectId: string,
    env?: string,
  ) => Effect.Effect<ProjectEnvRequirementRecord[], StorageError>;
  readonly setProjectPlugin: (record: ProjectPluginRecord) => Effect.Effect<void, StorageError>;
  readonly listProjectPlugins: (
    projectId: string,
  ) => Effect.Effect<ProjectPluginRecord[], StorageError>;
  readonly recordShiftHandoff: (
    handoff: Omit<ShiftHandoffRecord, "id" | "createdAt">,
  ) => Effect.Effect<ShiftHandoffRecord, StorageError>;
  readonly getLatestShiftHandoff: (
    projectId: string,
    branch?: string,
  ) => Effect.Effect<ShiftHandoffRecord | undefined, StorageError>;
  readonly listShiftHandoffs: (
    projectId: string,
    limit?: number,
  ) => Effect.Effect<ShiftHandoffRecord[], StorageError>;
  readonly listCredentialAliases: () => Effect.Effect<string[], StorageError>;
  readonly appendAudit: (e: AuditEvent) => Effect.Effect<void, StorageError>;
  readonly listAudit: () => Effect.Effect<AuditEvent[], StorageError>;
  readonly getAgentAuditStats: (
    agentId: string,
    since1hIso: string,
    since24hIso: string,
  ) => Effect.Effect<AgentAuditStats, StorageError>;
  readonly listStandingApprovals: () => Effect.Effect<StandingApprovalRecord[], StorageError>;
  readonly upsertStandingApproval: (record: StandingApprovalRecord) => Effect.Effect<void, StorageError>;
  readonly deleteStandingApprovals: (match: {
    readonly agentId?: string;
    readonly alias?: string;
  }) => Effect.Effect<void, StorageError>;
  readonly getWardenSettings: () => Effect.Effect<WardenSettings, StorageError>;
  readonly setWardenSettings: (settings: WardenSettings) => Effect.Effect<void, StorageError>;
  readonly getLocalAuthRecord: () => Effect.Effect<LocalAuthRecord, StorageError>;
  readonly setLocalAuthRecord: (record: LocalAuthRecord) => Effect.Effect<void, StorageError>;
  readonly getAgentSecuritySettings: () => Effect.Effect<AgentSecuritySettings, StorageError>;
  readonly setAgentSecuritySettings: (settings: AgentSecuritySettings) => Effect.Effect<void, StorageError>;
  readonly listAgents: () => Effect.Effect<AgentRecord[], StorageError>;
  readonly getAgent: (id: string) => Effect.Effect<AgentRecord | undefined, StorageError>;
  readonly getAgentByToken: (token: string) => Effect.Effect<AgentRecord | undefined, StorageError>;
  readonly addAgent: (id: string, name: string, token: string, deviceId?: string) => Effect.Effect<void, StorageError>;
  readonly revokeAgent: (id: string) => Effect.Effect<void, StorageError>;
  readonly listDevices: () => Effect.Effect<DeviceRecord[], StorageError>;
  readonly getDevice: (id: string) => Effect.Effect<DeviceRecord | undefined, StorageError>;
  readonly getDeviceByFingerprint: (fingerprint: string) => Effect.Effect<DeviceRecord | undefined, StorageError>;
  readonly addDevice: (device: DeviceRecord) => Effect.Effect<void, StorageError>;
  readonly renameDevice: (id: string, name: string) => Effect.Effect<void, StorageError>;
  readonly setDeviceRevoked: (id: string, revoked: boolean) => Effect.Effect<void, StorageError>;
  readonly touchDeviceLastSeen: (id: string, ts: string) => Effect.Effect<void, StorageError>;
  readonly listDeviceAliasPolicies: (deviceId: string) => Effect.Effect<DeviceAliasPolicy[], StorageError>;
  readonly setDeviceAliasPolicy: (deviceId: string, alias: string, allowWrite: boolean) => Effect.Effect<void, StorageError>;
  readonly deleteDeviceAliasPolicies: (deviceId: string) => Effect.Effect<void, StorageError>;
  readonly getRemoteSettingsRow: () => Effect.Effect<RemoteSettingsRow, StorageError>;
  readonly setRemoteSettingsRow: (row: RemoteSettingsRow) => Effect.Effect<void, StorageError>;
}

export interface AgentAuditStats {
  readonly requests1h: number;
  readonly denials1h: number;
  readonly requests24h: number;
  readonly denials24h: number;
}

export interface StandingApprovalRecord {
  readonly agentId: string;
  readonly alias: string;
  readonly scope: string;
  readonly verifiedOnly: boolean;
  readonly createdAt: string;
}

export interface RemoteSettingsRow {
  readonly enabled: boolean;
  readonly host: string;
  readonly port: number;
  readonly requireAuthForRemoteApproval: boolean;
}

export class VaultStore extends Context.Tag("VaultStore")<VaultStore, VaultStoreService>() {}

interface LocalAuthRow {
  readonly enabled: number;
  readonly pin_hash: string | null;
  readonly salt: string | null;
  readonly biometric_enabled: number;
  readonly require_on_approval: number;
  readonly require_on_launch: number;
  readonly require_on_settings: number;
  readonly auto_lock_minutes: number;
}

interface CredentialRow {
  readonly ceiling: string;
  readonly ciphertext: string;
  readonly website: string | null;
  readonly kind: string | null;
  readonly public_meta: string | null;
  readonly project_id?: string | null;
  readonly env?: string | null;
}

interface CredentialMetaRow {
  readonly alias: string;
  readonly ceiling: string;
  readonly website: string | null;
  readonly kind: string | null;
  readonly public_meta: string | null;
  readonly project_id?: string | null;
  readonly env?: string | null;
}

function toKind(raw: string | null): CredentialKind {
  return raw === CARD_KIND ? CARD_KIND : SECRET_KIND;
}

interface AliasRow {
  readonly alias: string;
}

export interface WardenSettingsRow {
  readonly provider: string;
  readonly model: string;
  readonly effort: string;
  readonly meta_api_base_url: string;
  readonly local_base_url: string;
  readonly local_api: string;
  readonly local_model: string;
}

// Rows written by earlier builds use provider "ollama" or "builtin" with the
// local tag in `model` and no local_* columns. They migrate to the
// bring-your-own endpoint at the Ollama address those builds always used.
export function wardenSettingsFromRow(row: WardenSettingsRow): WardenSettings {
  const legacyLocal = (LEGACY_LOCAL_PROVIDERS as readonly string[]).includes(row.provider);
  const provider = normalizeWardenProvider(row.provider) ?? DEFAULT_WARDEN_SETTINGS.provider;
  const localApi: WardenSettings["localApi"] = row.local_api === "openai" ? "openai" : "ollama";
  if (legacyLocal && row.local_model === "") {
    return {
      provider,
      model: DEFAULT_WARDEN_SETTINGS.model,
      effort: row.effort as WardenSettings["effort"],
      metaApiBaseUrl: row.meta_api_base_url,
      localBaseUrl: row.local_base_url !== "" ? row.local_base_url : SUGGESTED_LOCAL_BASE_URL.ollama,
      localApi,
      localModel: row.model,
      jevBaseUrl: DEFAULT_WARDEN_SETTINGS.jevBaseUrl,
      jevModel: DEFAULT_WARDEN_SETTINGS.jevModel,
    };
  }
  return {
    provider,
    model: row.model,
    effort: row.effort as WardenSettings["effort"],
    metaApiBaseUrl: row.meta_api_base_url,
    localBaseUrl: row.local_base_url,
    localApi,
    localModel: row.local_model,
    jevBaseUrl: DEFAULT_WARDEN_SETTINGS.jevBaseUrl,
    jevModel: DEFAULT_WARDEN_SETTINGS.jevModel,
  };
}

interface AuditRow {
  readonly ts: string;
  readonly agent: string;
  readonly alias: string;
  readonly scope: string;
  readonly stage: string;
  readonly detail: string;
  readonly model_id: string | null;
  readonly request_id: string | null;
  readonly risk: string | null;
  readonly recommended_scope: string | null;
  readonly decision_source: string | null;
  readonly latency_ms: number | null;
  readonly explanation: string | null;
  readonly verified: number | null;
  readonly client_pid: number | null;
  readonly client_process: string | null;
  readonly device_id: string | null;
  readonly origin: string | null;
  readonly transport: string | null;
}

interface AgentRow {
  readonly id: string;
  readonly name: string;
  readonly device_id: string | null;
  readonly token: string; // Legacy migration only.
  readonly token_hash: string | null;
  readonly token_prefix: string;
  readonly created_at: string;
  readonly revoked: number;
}

export function hashAgentToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function toStorageError(operation: string) {
  return (cause: unknown): StorageError =>
    new StorageError({
      message: cause instanceof Error ? cause.message : String(cause),
      operation,
    });
}

// The store never sees the master key: ciphertext reaches it already
// encrypted via crypto.ts (see KeySession in key-session.ts).
function deleteAgentHashBackups(dbPath: string): void {
  if (dbPath === ":memory:") return;
  const parent = dirname(dbPath);
  const prefix = `${basename(dbPath)}.before-agent-hash-`;
  for (const name of readdirSync(parent)) {
    if (name.startsWith(prefix)) rmSync(join(parent, name), { recursive: true, force: true });
  }
}

function protectDatabaseFile(dbPath: string): void {
  if (dbPath === ":memory:" || dbPath === "") return;
  if (process.platform === "win32") {
    hardenOwnerOnly(dbPath, false);
    return;
  }
  chmodSync(dbPath, 0o600);
}

function makeStore(db: Database.Database): VaultStoreService {
  db.exec("PRAGMA secure_delete=ON");
  if (db.name !== ":memory:") {
    db.pragma("journal_mode = WAL");
    db.pragma("synchronous = NORMAL");
  }
  db.pragma("busy_timeout = 5000");
  protectDatabaseFile(db.name);
  db.exec(
    `CREATE TABLE IF NOT EXISTS credentials (
       alias TEXT PRIMARY KEY,
       ceiling TEXT NOT NULL,
       ciphertext TEXT NOT NULL
     );
     CREATE TABLE IF NOT EXISTS agent_security_settings (
       id INTEGER PRIMARY KEY CHECK (id = 1),
       strict_mode INTEGER NOT NULL DEFAULT 0,
       verify_caller_process INTEGER NOT NULL DEFAULT 0
     );
     CREATE TABLE IF NOT EXISTS warden_settings (
       id INTEGER PRIMARY KEY CHECK (id = 1),
       provider TEXT NOT NULL,
       model TEXT NOT NULL,
       effort TEXT NOT NULL,
       meta_api_base_url TEXT NOT NULL
     );
     CREATE TABLE IF NOT EXISTS local_auth_settings (
        id INTEGER PRIMARY KEY,
        enabled INTEGER NOT NULL DEFAULT 0,
        pin_hash TEXT,
        salt TEXT,
        biometric_enabled INTEGER NOT NULL DEFAULT 0,
        require_on_approval INTEGER NOT NULL DEFAULT 0,
        require_on_launch INTEGER NOT NULL DEFAULT 0,
        require_on_settings INTEGER NOT NULL DEFAULT 0,
        auto_lock_minutes INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS audit (
       ts TEXT NOT NULL,
       agent TEXT NOT NULL,
       alias TEXT NOT NULL,
       scope TEXT NOT NULL,
       stage TEXT NOT NULL,
       detail TEXT NOT NULL,
       model_id TEXT,
       verified INTEGER
     );
     CREATE TABLE IF NOT EXISTS agents (
       id TEXT PRIMARY KEY,
       name TEXT NOT NULL,
       token TEXT NOT NULL UNIQUE,
       created_at TEXT NOT NULL,
       revoked INTEGER NOT NULL DEFAULT 0
     );
     CREATE TABLE IF NOT EXISTS devices (
       id TEXT PRIMARY KEY,
       name TEXT NOT NULL,
       platform TEXT NOT NULL DEFAULT '',
       cert_fingerprint TEXT NOT NULL UNIQUE,
       transport TEXT NOT NULL DEFAULT '',
       created_at TEXT NOT NULL,
       last_seen TEXT,
       revoked INTEGER NOT NULL DEFAULT 0
     );
     CREATE TABLE IF NOT EXISTS device_alias_policies (
       device_id TEXT NOT NULL,
       alias TEXT NOT NULL,
       allow_write INTEGER NOT NULL DEFAULT 0,
       PRIMARY KEY (device_id, alias)
     );
     CREATE TABLE IF NOT EXISTS remote_settings (
       id INTEGER PRIMARY KEY CHECK (id = 1),
       enabled INTEGER NOT NULL DEFAULT 0,
       host TEXT NOT NULL DEFAULT '127.0.0.1',
       port INTEGER NOT NULL DEFAULT 7078,
       require_auth_remote_approval INTEGER NOT NULL DEFAULT 1
     );
     CREATE TABLE IF NOT EXISTS standing_approvals (
       agent_id TEXT NOT NULL,
       alias TEXT NOT NULL,
       scope TEXT NOT NULL,
       verified_only INTEGER NOT NULL DEFAULT 0,
       created_at TEXT NOT NULL,
       PRIMARY KEY (agent_id, alias, scope)
     );
     CREATE TABLE IF NOT EXISTS projects (
       id TEXT PRIMARY KEY,
       slug TEXT UNIQUE NOT NULL,
       name TEXT NOT NULL,
       root_path TEXT UNIQUE NOT NULL,
       stack_tags_json TEXT NOT NULL DEFAULT '[]',
       created_at TEXT NOT NULL
     );
     CREATE TABLE IF NOT EXISTS project_environments (
       project_id TEXT NOT NULL,
       env TEXT NOT NULL,
       require_approval_for_reads INTEGER NOT NULL DEFAULT 0,
       allow_agent_writes INTEGER NOT NULL DEFAULT 0,
       PRIMARY KEY (project_id, env)
     );
     CREATE TABLE IF NOT EXISTS project_links (
       id TEXT PRIMARY KEY,
       source_project_id TEXT NOT NULL,
       target_project_id TEXT NOT NULL,
       kind TEXT NOT NULL,
       contract_paths_json TEXT NOT NULL DEFAULT '[]'
     );
     CREATE TABLE IF NOT EXISTS project_env_requirements (
       id TEXT PRIMARY KEY,
       project_id TEXT NOT NULL,
       env TEXT NOT NULL DEFAULT 'all',
       alias TEXT NOT NULL,
       required INTEGER NOT NULL DEFAULT 1,
       scope_ceiling TEXT NOT NULL DEFAULT '',
       description TEXT NOT NULL DEFAULT ''
     );
     CREATE TABLE IF NOT EXISTS project_plugins (
       project_id TEXT NOT NULL,
       plugin_id TEXT NOT NULL,
       enabled INTEGER NOT NULL DEFAULT 1,
       config_json TEXT NOT NULL DEFAULT '{}',
       PRIMARY KEY (project_id, plugin_id)
     );
     CREATE TABLE IF NOT EXISTS shift_handoffs (
       id TEXT PRIMARY KEY,
       project_id TEXT NOT NULL,
       branch TEXT NOT NULL,
       agent_id TEXT NOT NULL,
       ide TEXT NOT NULL,
       checkpoint_type TEXT NOT NULL,
       summary TEXT NOT NULL,
       details_json TEXT NOT NULL DEFAULT '{}',
       created_at TEXT NOT NULL
     );
     CREATE INDEX IF NOT EXISTS idx_shift_handoffs_proj_branch ON shift_handoffs(project_id, branch, created_at);
     CREATE INDEX IF NOT EXISTS idx_audit_agent_ts ON audit(agent, ts);`,
  );
  const cols = db.prepare("PRAGMA table_info(credentials)").all() as { name: string }[];
  if (!cols.some((c) => c.name === "website")) {
    db.exec("ALTER TABLE credentials ADD COLUMN website TEXT NOT NULL DEFAULT ''");
  }
  if (!cols.some((c) => c.name === "kind")) {
    db.exec("ALTER TABLE credentials ADD COLUMN kind TEXT NOT NULL DEFAULT 'secret'");
  }
  if (!cols.some((c) => c.name === "public_meta")) {
    db.exec("ALTER TABLE credentials ADD COLUMN public_meta TEXT NOT NULL DEFAULT ''");
  }
  if (!cols.some((c) => c.name === "project_id")) {
    db.exec("ALTER TABLE credentials ADD COLUMN project_id TEXT NOT NULL DEFAULT 'global'");
  }
  if (!cols.some((c) => c.name === "env")) {
    db.exec("ALTER TABLE credentials ADD COLUMN env TEXT NOT NULL DEFAULT 'all'");
  }
  const pkCols = (db.prepare("PRAGMA table_info(credentials)").all() as { name: string; pk: number }[]).filter((c) => c.pk > 0);
  if (pkCols.length <= 1) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS credentials_v2 (
        alias TEXT NOT NULL,
        ceiling TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        website TEXT NOT NULL DEFAULT '',
        kind TEXT NOT NULL DEFAULT 'secret',
        public_meta TEXT NOT NULL DEFAULT '',
        project_id TEXT NOT NULL DEFAULT 'global',
        env TEXT NOT NULL DEFAULT 'all',
        PRIMARY KEY (project_id, env, alias)
      );
      INSERT OR IGNORE INTO credentials_v2 (alias, ceiling, ciphertext, website, kind, public_meta, project_id, env)
        SELECT alias, ceiling, ciphertext, website, kind, public_meta, project_id, env FROM credentials;
      DROP TABLE credentials;
      ALTER TABLE credentials_v2 RENAME TO credentials;
    `);
  }
  const auditCols = db.prepare("PRAGMA table_info(audit)").all() as { name: string }[];
  const auditColumnDefs: Record<string, string> = {
    request_id: "TEXT",
    risk: "TEXT",
    recommended_scope: "TEXT",
    decision_source: "TEXT",
    latency_ms: "REAL",
    explanation: "TEXT",
    verified: "INTEGER",
    client_pid: "INTEGER",
    client_process: "TEXT",
    device_id: "TEXT",
    origin: "TEXT",
    transport: "TEXT",
  };
  for (const [name, def] of Object.entries(auditColumnDefs)) {
    if (!auditCols.some((c) => c.name === name)) {
      db.exec(`ALTER TABLE audit ADD COLUMN ${name} ${def}`);
    }
  }
  const insertCredential = db.prepare(
    "INSERT OR REPLACE INTO credentials (alias, ceiling, ciphertext, website, kind, public_meta, project_id, env) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  );
  const selectCredential = db.prepare(
    "SELECT ceiling, ciphertext, website, kind, public_meta, project_id, env FROM credentials WHERE alias = ? ORDER BY CASE WHEN project_id = 'global' THEN 0 ELSE 1 END ASC LIMIT 1",
  );
  const selectScopedExact = db.prepare(
    "SELECT ceiling, ciphertext, website, kind, public_meta, project_id, env FROM credentials WHERE alias = ? AND project_id = ? AND env = ?",
  );
  const selectScopedAllEnv = db.prepare(
    "SELECT ceiling, ciphertext, website, kind, public_meta, project_id, env FROM credentials WHERE alias = ? AND project_id = ? AND env = 'all'",
  );
  const selectScopedGlobal = db.prepare(
    "SELECT ceiling, ciphertext, website, kind, public_meta, project_id, env FROM credentials WHERE alias = ? AND project_id = 'global' AND env = 'all'",
  );
  const updateCredentialStmt = db.prepare(
    "UPDATE credentials SET ceiling = ?, ciphertext = ?, website = ? WHERE alias = ?",
  );
  const deleteCredentialStmt = db.prepare("DELETE FROM credentials WHERE alias = ?");
  const selectCredentials = db.prepare(
    "SELECT alias, ceiling, website, kind, public_meta, project_id, env FROM credentials ORDER BY alias ASC",
  );
  const selectAliases = db.prepare(
    "SELECT alias FROM credentials ORDER BY alias ASC",
  );
  const insertProjectStmt = db.prepare(
    "INSERT INTO projects (id, slug, name, root_path, stack_tags_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
  );
  const selectProjectByIdOrSlug = db.prepare(
    "SELECT id, slug, name, root_path, stack_tags_json, created_at FROM projects WHERE id = ? OR slug = ?",
  );
  const selectProjectsStmt = db.prepare(
    "SELECT id, slug, name, root_path, stack_tags_json, created_at FROM projects ORDER BY name ASC",
  );
  const deleteProjectStmt = db.prepare("DELETE FROM projects WHERE id = ?");
  const upsertProjectEnvStmt = db.prepare(
    "INSERT OR REPLACE INTO project_environments (project_id, env, require_approval_for_reads, allow_agent_writes) VALUES (?, ?, ?, ?)",
  );
  const selectProjectEnvsStmt = db.prepare(
    "SELECT project_id, env, require_approval_for_reads, allow_agent_writes FROM project_environments WHERE project_id = ? ORDER BY env ASC",
  );
  const insertProjectLinkStmt = db.prepare(
    "INSERT OR REPLACE INTO project_links (id, source_project_id, target_project_id, kind, contract_paths_json) VALUES (?, ?, ?, ?, ?)",
  );
  const selectProjectLinksStmt = db.prepare(
    "SELECT id, source_project_id, target_project_id, kind, contract_paths_json FROM project_links WHERE source_project_id = ? OR target_project_id = ?",
  );
  const deleteProjectLinkStmt = db.prepare("DELETE FROM project_links WHERE id = ?");
  const upsertProjectEnvReqStmt = db.prepare(
    "INSERT OR REPLACE INTO project_env_requirements (id, project_id, env, alias, required, scope_ceiling, description) VALUES (?, ?, ?, ?, ?, ?, ?)",
  );
  const selectProjectEnvReqsStmt = db.prepare(
    "SELECT id, project_id, env, alias, required, scope_ceiling, description FROM project_env_requirements WHERE project_id = ? AND (env = ? OR ? = 'all' OR env = 'all') ORDER BY alias ASC",
  );
  const upsertProjectPluginStmt = db.prepare(
    "INSERT OR REPLACE INTO project_plugins (project_id, plugin_id, enabled, config_json) VALUES (?, ?, ?, ?)",
  );
  const selectProjectPluginsStmt = db.prepare(
    "SELECT project_id, plugin_id, enabled, config_json FROM project_plugins WHERE project_id = ?",
  );
  const insertShiftHandoffStmt = db.prepare(
    "INSERT INTO shift_handoffs (id, project_id, branch, agent_id, ide, checkpoint_type, summary, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
  );
  const selectLatestHandoffBranchStmt = db.prepare(
    "SELECT id, project_id, branch, agent_id, ide, checkpoint_type, summary, details_json, created_at FROM shift_handoffs WHERE project_id = ? AND branch = ? ORDER BY created_at DESC LIMIT 1",
  );
  const selectLatestHandoffAnyStmt = db.prepare(
    "SELECT id, project_id, branch, agent_id, ide, checkpoint_type, summary, details_json, created_at FROM shift_handoffs WHERE project_id = ? ORDER BY created_at DESC LIMIT 1",
  );
  const selectShiftHandoffsStmt = db.prepare(
    "SELECT id, project_id, branch, agent_id, ide, checkpoint_type, summary, details_json, created_at FROM shift_handoffs WHERE project_id = ? ORDER BY created_at DESC LIMIT ?",
  );
  const insertAudit = db.prepare(
    "INSERT INTO audit (ts, agent, alias, scope, stage, detail, model_id, request_id, risk, recommended_scope, decision_source, latency_ms, explanation, verified, client_pid, client_process, device_id, origin, transport) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
  );
  // Rebuild the legacy token table transactionally. No raw bearer is retained
  // in the logical database. Existing IDE tokens keep working until rotated.
  db.exec("CREATE TABLE IF NOT EXISTS local_migration_state (name TEXT PRIMARY KEY, cleanup_pending INTEGER NOT NULL)");
  const agentCols = db.prepare("PRAGMA table_info(agents)").all() as { name: string }[];
  if (agentCols.some((c) => c.name === "token")) {
    // A consistent SQLite snapshot precedes any destructive schema change.
    // Local backup retains the old credential data and must stay private.
    if (db.name !== ":memory:") {
      const backupDir = `${db.name}.before-agent-hash-${Date.now().toString()}-${Math.random().toString(16).slice(2)}`;
      mkdirSync(backupDir, {mode:0o700});
      if (process.platform === "win32") {
        const identity = execFileSync("whoami.exe", [], {encoding:"utf8"}).trim();
        // Restrict inheritance BEFORE writing any raw credential data.
        execFileSync("icacls.exe", [backupDir, "/inheritance:r", "/grant:r", `${identity}:(OI)(CI)(F)`, "SYSTEM:(OI)(CI)(F)"], {stdio:"pipe"});
      }
      const backup = `${backupDir}/vault.db.bak`;
      // Keep matching wrapped key and local daemon token with the private DB
      // snapshot. Never move originals or export this directory to agents.
      for (const name of ["metavault.key.json"]) {
        const source = join(dirname(db.name), name);
        if (existsSync(source)) {
          const target = join(backupDir, name);
          copyFileSync(source, target);
          if (process.platform !== "win32") chmodSync(target, 0o600);
        }
      }
      db.prepare("VACUUM INTO ?").run(backup);
      if (process.platform !== "win32") chmodSync(backup, 0o600);
    }
    db.pragma("wal_checkpoint(TRUNCATE)");
    db.exec("PRAGMA secure_delete=ON");
    db.transaction(() => {
      const rows = db.prepare("SELECT * FROM agents").all() as AgentRow[];
      db.exec("ALTER TABLE agents RENAME TO agents_legacy; CREATE TABLE agents (id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT UNIQUE, token_prefix TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)");
      const put = db.prepare("INSERT INTO agents VALUES (?, ?, ?, ?, ?, ?)");
      for (const row of rows) put.run(row.id, row.name, hashAgentToken(row.token), row.token.slice(0, 16), row.created_at, row.revoked);
      db.exec("DROP TABLE agents_legacy");
      db.exec("INSERT OR REPLACE INTO local_migration_state VALUES ('agent-hash',1)");
    })();
  }
  const pendingCleanup = db.prepare("SELECT cleanup_pending FROM local_migration_state WHERE name='agent-hash'").get() as {cleanup_pending:number} | undefined;
  if (pendingCleanup?.cleanup_pending === 1) {
    // A crash after the transaction must retry physical cleanup on startup.
    db.exec("PRAGMA secure_delete=ON; VACUUM");
    const result = db.pragma("wal_checkpoint(TRUNCATE)") as {busy:number}[];
    if (result.some(row=>row.busy !== 0)) throw new Error("agent migration cleanup is busy; close other vault processes and retry");
    db.exec("UPDATE local_migration_state SET cleanup_pending=0 WHERE name='agent-hash'");
    deleteAgentHashBackups(db.name);
  }
  const agentTableCols = db.prepare("PRAGMA table_info(agents)").all() as { name: string }[];
  if (!agentTableCols.some((c) => c.name === "device_id")) {
    db.exec("ALTER TABLE agents ADD COLUMN device_id TEXT");
  }
  const seedAgent = db.prepare("INSERT OR IGNORE INTO agents (id,name,token_hash,token_prefix,created_at,revoked) VALUES (?,?,NULL,'',?,1)");
  for (const [id, name] of [["cursor", "Cursor"], ["claude-code", "Claude Code"], ["vscode", "VS Code"], ["codex", "Codex"], ["opencode", "OpenCode"]]) seedAgent.run(id, name, new Date().toISOString());
  const selectAllAgents = db.prepare("SELECT * FROM agents ORDER BY id ASC");
  const selectAgentById = db.prepare("SELECT * FROM agents WHERE id = ?");
  const selectAgentByToken = db.prepare("SELECT * FROM agents WHERE token_hash = ?");
  const insertAgent = db.prepare(
    "INSERT INTO agents (id,name,token_hash,token_prefix,created_at,revoked,device_id) VALUES (?,?,?,?,?,0,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,token_hash=excluded.token_hash,token_prefix=excluded.token_prefix,revoked=0,device_id=excluded.device_id",
  );
  const revokeAgentStmt = db.prepare(
    "UPDATE agents SET revoked = 1 WHERE id = ?",
  );

  const selectAllDevices = db.prepare("SELECT * FROM devices ORDER BY created_at ASC");
  const selectDeviceById = db.prepare("SELECT * FROM devices WHERE id = ?");
  const selectDeviceByFingerprint = db.prepare("SELECT * FROM devices WHERE cert_fingerprint = ?");
  const insertDevice = db.prepare(
    "INSERT INTO devices (id,name,platform,cert_fingerprint,transport,created_at,last_seen,revoked) VALUES (?,?,?,?,?,?,?,?)",
  );
  const renameDeviceStmt = db.prepare("UPDATE devices SET name = ? WHERE id = ?");
  const setDeviceRevokedStmt = db.prepare("UPDATE devices SET revoked = ? WHERE id = ?");
  const touchDeviceStmt = db.prepare("UPDATE devices SET last_seen = ? WHERE id = ?");
  const selectDevicePolicies = db.prepare("SELECT * FROM device_alias_policies WHERE device_id = ?");
  const upsertDevicePolicy = db.prepare(
    "INSERT INTO device_alias_policies (device_id,alias,allow_write) VALUES (?,?,?) ON CONFLICT(device_id,alias) DO UPDATE SET allow_write=excluded.allow_write",
  );
  const deleteDevicePoliciesStmt = db.prepare("DELETE FROM device_alias_policies WHERE device_id = ?");
  const selectRemoteSettings = db.prepare("SELECT enabled, host, port, require_auth_remote_approval FROM remote_settings WHERE id = 1");
  const upsertRemoteSettings = db.prepare(
    "INSERT INTO remote_settings (id, enabled, host, port, require_auth_remote_approval) VALUES (1, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled, host=excluded.host, port=excluded.port, require_auth_remote_approval=excluded.require_auth_remote_approval",
  );

  interface DeviceRow {
    readonly id: string;
    readonly name: string;
    readonly platform: string;
    readonly cert_fingerprint: string;
    readonly transport: string;
    readonly created_at: string;
    readonly last_seen: string | null;
    readonly revoked: number;
  }
  const toDevice = (row: DeviceRow): DeviceRecord => ({
    id: row.id,
    name: row.name,
    platform: row.platform,
    certFingerprint: row.cert_fingerprint,
    transport: row.transport,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen,
    revoked: row.revoked === 1,
  });

  const upsertSecuritySettings = db.prepare(
    "INSERT INTO agent_security_settings (id, strict_mode, verify_caller_process) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET strict_mode = excluded.strict_mode, verify_caller_process = excluded.verify_caller_process"
  );
  const selectSecuritySettings = db.prepare(
    "SELECT strict_mode, verify_caller_process FROM agent_security_settings WHERE id = 1"
  );
  for (const [name, def] of [
    ["local_base_url", "TEXT NOT NULL DEFAULT ''"],
    ["local_api", "TEXT NOT NULL DEFAULT 'ollama'"],
    ["local_model", "TEXT NOT NULL DEFAULT ''"],
  ] as const) {
    try {
      db.exec(`ALTER TABLE warden_settings ADD COLUMN ${name} ${def}`);
    } catch {
      // Column already exists
    }
  }
  const upsertSettings = db.prepare(
    "INSERT INTO warden_settings (id, provider, model, effort, meta_api_base_url, local_base_url, local_api, local_model) VALUES (1, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET provider = excluded.provider, model = excluded.model, effort = excluded.effort, meta_api_base_url = excluded.meta_api_base_url, local_base_url = excluded.local_base_url, local_api = excluded.local_api, local_model = excluded.local_model",
  );
  try {
    db.exec("ALTER TABLE local_auth_settings ADD COLUMN biometric_enabled INTEGER NOT NULL DEFAULT 0");
  } catch {
    // Column already exists
  }
  try {
    db.exec("ALTER TABLE local_auth_settings ADD COLUMN require_on_settings INTEGER NOT NULL DEFAULT 0");
  } catch {
    // Column already exists
  }
  const upsertLocalAuth = db.prepare(
    "INSERT INTO local_auth_settings (id, enabled, pin_hash, salt, biometric_enabled, require_on_approval, require_on_launch, require_on_settings, auto_lock_minutes) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled, pin_hash = excluded.pin_hash, salt = excluded.salt, biometric_enabled = excluded.biometric_enabled, require_on_approval = excluded.require_on_approval, require_on_launch = excluded.require_on_launch, require_on_settings = excluded.require_on_settings, auto_lock_minutes = excluded.auto_lock_minutes",
  );
  const selectLocalAuth = db.prepare(
    "SELECT enabled, pin_hash, salt, biometric_enabled, require_on_approval, require_on_launch, require_on_settings, auto_lock_minutes FROM local_auth_settings WHERE id = 1",
  );
  const selectSettings = db.prepare(
    "SELECT provider, model, effort, meta_api_base_url, local_base_url, local_api, local_model FROM warden_settings WHERE id = 1",
  );
  const selectAudit = db.prepare(
    "SELECT ts, agent, alias, scope, stage, detail, model_id, request_id, risk, recommended_scope, decision_source, latency_ms, explanation, verified, client_pid, client_process, device_id, origin, transport FROM audit ORDER BY rowid ASC",
  );

  return {
    addCredential: (alias, scopeCeiling, ciphertext, website, kind, publicMeta, projectId, env) =>
      Effect.try({
        try: () => {
          insertCredential.run(
            alias,
            scopeCeiling,
            ciphertext,
            website ?? "",
            kind ?? SECRET_KIND,
            publicMeta ?? "",
            projectId ?? "global",
            env ?? "all",
          );
        },
        catch: toStorageError("addCredential"),
      }),
    updateCredential: (alias, scopeCeiling, ciphertext, website) =>
      Effect.try({
        try: () => {
          updateCredentialStmt.run(scopeCeiling, ciphertext, website, alias);
        },
        catch: toStorageError("updateCredential"),
      }),
    deleteCredential: (alias) =>
      Effect.try({
        try: () => {
          deleteCredentialStmt.run(alias);
        },
        catch: toStorageError("deleteCredential"),
      }),
    getCredential: (alias) =>
      Effect.try({
        try: () => {
          const row = selectCredential.get(alias) as CredentialRow | undefined;
          return row === undefined
            ? undefined
            : {
                scopeCeiling: row.ceiling,
                ciphertext: row.ciphertext,
                website: row.website ?? "",
                kind: toKind(row.kind),
                publicMeta: row.public_meta ?? "",
                ...(row.project_id && row.project_id !== "global" ? { projectId: row.project_id } : {}),
                ...(row.env && row.env !== "all" ? { env: row.env } : {}),
              };
        },
        catch: toStorageError("getCredential"),
      }),
    getScopedCredential: (alias, projectId, env) =>
      Effect.try({
        try: () => {
          let row: CredentialRow | undefined;
          if (projectId && env) {
            row = selectScopedExact.get(alias, projectId, env) as CredentialRow | undefined;
          }
          if (!row && projectId) {
            row = selectScopedAllEnv.get(alias, projectId) as CredentialRow | undefined;
          }
          if (!row) {
            row = selectScopedGlobal.get(alias) as CredentialRow | undefined;
          }
          if (!row) {
            row = selectCredential.get(alias) as CredentialRow | undefined;
          }
          return row === undefined
            ? undefined
            : {
                scopeCeiling: row.ceiling,
                ciphertext: row.ciphertext,
                website: row.website ?? "",
                kind: toKind(row.kind),
                publicMeta: row.public_meta ?? "",
                projectId: row.project_id ?? "global",
                env: row.env ?? "all",
              };
        },
        catch: toStorageError("getScopedCredential"),
      }),
    createProject: (project) =>
      Effect.try({
        try: () => {
          const createdAt = new Date().toISOString();
          insertProjectStmt.run(
            project.id,
            project.slug,
            project.name,
            project.rootPath,
            JSON.stringify(project.stackTags),
            createdAt,
          );
          return {
            ...project,
            stackTags: project.stackTags,
            createdAt,
          };
        },
        catch: toStorageError("createProject"),
      }),
    getProject: (idOrSlug) =>
      Effect.try({
        try: () => {
          const row = selectProjectByIdOrSlug.get(idOrSlug, idOrSlug) as
            | {
                id: string;
                slug: string;
                name: string;
                root_path: string;
                stack_tags_json: string;
                created_at: string;
              }
            | undefined;
          if (!row) return undefined;
          return {
            id: row.id,
            slug: row.slug,
            name: row.name,
            rootPath: row.root_path,
            stackTags: JSON.parse(row.stack_tags_json || "[]") as string[],
            createdAt: row.created_at,
          };
        },
        catch: toStorageError("getProject"),
      }),
    listProjects: () =>
      Effect.try({
        try: () => {
          const rows = selectProjectsStmt.all() as {
            id: string;
            slug: string;
            name: string;
            root_path: string;
            stack_tags_json: string;
            created_at: string;
          }[];
          return rows.map((r) => ({
            id: r.id,
            slug: r.slug,
            name: r.name,
            rootPath: r.root_path,
            stackTags: JSON.parse(r.stack_tags_json || "[]") as string[],
            createdAt: r.created_at,
          }));
        },
        catch: toStorageError("listProjects"),
      }),
    deleteProject: (id) =>
      Effect.try({
        try: () => {
          deleteProjectStmt.run(id);
        },
        catch: toStorageError("deleteProject"),
      }),
    upsertProjectEnvironment: (env) =>
      Effect.try({
        try: () => {
          upsertProjectEnvStmt.run(
            env.projectId,
            env.env,
            env.requireApprovalForReads ? 1 : 0,
            env.allowAgentWrites ? 1 : 0,
          );
        },
        catch: toStorageError("upsertProjectEnvironment"),
      }),
    listProjectEnvironments: (projectId) =>
      Effect.try({
        try: () => {
          const rows = selectProjectEnvsStmt.all(projectId) as {
            project_id: string;
            env: string;
            require_approval_for_reads: number;
            allow_agent_writes: number;
          }[];
          return rows.map((r) => ({
            projectId: r.project_id,
            env: r.env as ProjectEnvironment,
            requireApprovalForReads: r.require_approval_for_reads === 1,
            allowAgentWrites: r.allow_agent_writes === 1,
          }));
        },
        catch: toStorageError("listProjectEnvironments"),
      }),
    addProjectLink: (link) =>
      Effect.try({
        try: () => {
          const id = createHash("sha256")
            .update(`${link.sourceProjectId}:${link.targetProjectId}:${link.kind}`)
            .digest("hex")
            .slice(0, 16);
          insertProjectLinkStmt.run(
            id,
            link.sourceProjectId,
            link.targetProjectId,
            link.kind,
            JSON.stringify(link.contractPaths),
          );
          return {
            id,
            ...link,
            contractPaths: link.contractPaths,
          };
        },
        catch: toStorageError("addProjectLink"),
      }),
    listProjectLinks: (projectId) =>
      Effect.try({
        try: () => {
          const rows = selectProjectLinksStmt.all(projectId, projectId) as {
            id: string;
            source_project_id: string;
            target_project_id: string;
            kind: string;
            contract_paths_json: string;
          }[];
          return rows.map((r) => ({
            id: r.id,
            sourceProjectId: r.source_project_id,
            targetProjectId: r.target_project_id,
            kind: r.kind as ProjectLinkKind,
            contractPaths: JSON.parse(r.contract_paths_json || "[]") as string[],
          }));
        },
        catch: toStorageError("listProjectLinks"),
      }),
    deleteProjectLink: (id) =>
      Effect.try({
        try: () => {
          deleteProjectLinkStmt.run(id);
        },
        catch: toStorageError("deleteProjectLink"),
      }),
    upsertProjectEnvRequirement: (req) =>
      Effect.try({
        try: () => {
          const id = createHash("sha256")
            .update(`${req.projectId}:${req.env}:${req.alias}`)
            .digest("hex")
            .slice(0, 16);
          upsertProjectEnvReqStmt.run(
            id,
            req.projectId,
            req.env,
            req.alias,
            req.required ? 1 : 0,
            req.scopeCeiling,
            req.description,
          );
          return {
            id,
            ...req,
            env: req.env,
            required: req.required,
            scopeCeiling: req.scopeCeiling,
            description: req.description,
          };
        },
        catch: toStorageError("upsertProjectEnvRequirement"),
      }),
    listProjectEnvRequirements: (projectId, env = "all") =>
      Effect.try({
        try: () => {
          const rows = selectProjectEnvReqsStmt.all(projectId, env, env) as {
            id: string;
            project_id: string;
            env: string;
            alias: string;
            required: number;
            scope_ceiling: string;
            description: string;
          }[];
          return rows.map((r) => ({
            id: r.id,
            projectId: r.project_id,
            env: r.env,
            alias: r.alias,
            required: r.required === 1,
            scopeCeiling: r.scope_ceiling,
            description: r.description,
          }));
        },
        catch: toStorageError("listProjectEnvRequirements"),
      }),
    setProjectPlugin: (record) =>
      Effect.try({
        try: () => {
          upsertProjectPluginStmt.run(
            record.projectId,
            record.pluginId,
            record.enabled ? 1 : 0,
            JSON.stringify(record.config),
          );
        },
        catch: toStorageError("setProjectPlugin"),
      }),
    listProjectPlugins: (projectId) =>
      Effect.try({
        try: () => {
          const rows = selectProjectPluginsStmt.all(projectId) as {
            project_id: string;
            plugin_id: string;
            enabled: number;
            config_json: string;
          }[];
          return rows.map((r) => ({
            projectId: r.project_id,
            pluginId: r.plugin_id,
            enabled: r.enabled === 1,
            config: JSON.parse(r.config_json || "{}") as Record<string, unknown>,
          }));
        },
        catch: toStorageError("listProjectPlugins"),
      }),
    recordShiftHandoff: (handoff) =>
      Effect.try({
        try: () => {
          const id = randomBytes(12).toString("hex");
          const createdAt = new Date().toISOString();
          insertShiftHandoffStmt.run(
            id,
            handoff.projectId,
            handoff.branch,
            handoff.agentId,
            handoff.ide,
            handoff.checkpointType,
            handoff.summary,
            JSON.stringify(handoff.details),
            createdAt,
          );
          return {
            id,
            ...handoff,
            details: handoff.details,
            createdAt,
          };
        },
        catch: toStorageError("recordShiftHandoff"),
      }),
    getLatestShiftHandoff: (projectId, branch) =>
      Effect.try({
        try: () => {
          const row = (
            branch
              ? selectLatestHandoffBranchStmt.get(projectId, branch)
              : selectLatestHandoffAnyStmt.get(projectId)
          ) as
            | {
                id: string;
                project_id: string;
                branch: string;
                agent_id: string;
                ide: string;
                checkpoint_type: string;
                summary: string;
                details_json: string;
                created_at: string;
              }
            | undefined;
          if (!row) return undefined;
          return {
            id: row.id,
            projectId: row.project_id,
            branch: row.branch,
            agentId: row.agent_id,
            ide: row.ide,
            checkpointType: row.checkpoint_type as ShiftHandoffType,
            summary: row.summary,
            details: JSON.parse(row.details_json || "{}") as Record<string, unknown>,
            createdAt: row.created_at,
          };
        },
        catch: toStorageError("getLatestShiftHandoff"),
      }),
    listShiftHandoffs: (projectId, limit = 20) =>
      Effect.try({
        try: () => {
          const rows = selectShiftHandoffsStmt.all(projectId, limit) as {
            id: string;
            project_id: string;
            branch: string;
            agent_id: string;
            ide: string;
            checkpoint_type: string;
            summary: string;
            details_json: string;
            created_at: string;
          }[];
          return rows.map((r) => ({
            id: r.id,
            projectId: r.project_id,
            branch: r.branch,
            agentId: r.agent_id,
            ide: r.ide,
            checkpointType: r.checkpoint_type as ShiftHandoffType,
            summary: r.summary,
            details: JSON.parse(r.details_json || "{}") as Record<string, unknown>,
            createdAt: r.created_at,
          }));
        },
        catch: toStorageError("listShiftHandoffs"),
      }),
    listCredentials: () =>
      Effect.try({
        try: () => {
          const rows = selectCredentials.all() as CredentialMetaRow[];
          return rows.map((row) => ({
            alias: row.alias,
            scopeCeiling: row.ceiling,
            website: row.website ?? "",
            kind: toKind(row.kind),
            publicMeta: row.public_meta ?? "",
            ...(row.project_id && row.project_id !== "global" ? { projectId: row.project_id } : {}),
            ...(row.env && row.env !== "all" ? { env: row.env } : {}),
          }));
        },
        catch: toStorageError("listCredentials"),
      }),
    listCredentialAliases: () =>
      Effect.try({
        try: () => {
          const rows = selectAliases.all() as AliasRow[];
          return rows.map((row) => row.alias);
        },
        catch: toStorageError("listCredentialAliases"),
      }),
    appendAudit: (e) =>
      Effect.try({
        try: () => {
          insertAudit.run(e.ts, e.agentId, e.alias, e.scope, e.stage, e.detail, e.modelId ?? null, e.requestId ?? null, e.risk ?? null, e.recommendedScope ?? null, e.decisionSource ?? null, e.latencyMs ?? null, e.explanation ?? null, (e.verified === undefined ? null : e.verified ? 1 : 0), e.clientPid ?? null, e.clientProcess ?? null, e.deviceId ?? null, e.origin ?? null, e.transport ?? null);
        },
        catch: toStorageError("appendAudit"),
      }),
    getAgentAuditStats: (agentId, since1hIso, since24hIso) =>
      Effect.try({
        try: () => {
          const row = db
            .prepare(
              `SELECT
                 COALESCE(SUM(CASE WHEN stage = 'requested' AND ts >= ? THEN 1 ELSE 0 END), 0) AS requests1h,
                 COALESCE(SUM(CASE WHEN stage = 'denied' AND ts >= ? THEN 1 ELSE 0 END), 0) AS denials1h,
                 COALESCE(SUM(CASE WHEN stage = 'requested' AND ts >= ? THEN 1 ELSE 0 END), 0) AS requests24h,
                 COALESCE(SUM(CASE WHEN stage = 'denied' AND ts >= ? THEN 1 ELSE 0 END), 0) AS denials24h
               FROM audit WHERE agent = ?`,
            )
            .get(since1hIso, since1hIso, since24hIso, since24hIso, agentId) as
            | { requests1h: number; denials1h: number; requests24h: number; denials24h: number }
            | undefined;
          return {
            requests1h: row?.requests1h ?? 0,
            denials1h: row?.denials1h ?? 0,
            requests24h: row?.requests24h ?? 0,
            denials24h: row?.denials24h ?? 0,
          };
        },
        catch: toStorageError("getAgentAuditStats"),
      }),
    listStandingApprovals: () =>
      Effect.try({
        try: () => {
          const rows = db
            .prepare(
              "SELECT agent_id, alias, scope, verified_only, created_at FROM standing_approvals ORDER BY created_at ASC",
            )
            .all() as {
            agent_id: string;
            alias: string;
            scope: string;
            verified_only: number;
            created_at: string;
          }[];
          return rows.map((row) => ({
            agentId: row.agent_id,
            alias: row.alias,
            scope: row.scope,
            verifiedOnly: row.verified_only === 1,
            createdAt: row.created_at,
          }));
        },
        catch: toStorageError("listStandingApprovals"),
      }),
    upsertStandingApproval: (record) =>
      Effect.try({
        try: () => {
          db.prepare(
            `INSERT INTO standing_approvals (agent_id, alias, scope, verified_only, created_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(agent_id, alias, scope) DO UPDATE SET verified_only = excluded.verified_only`,
          ).run(record.agentId, record.alias, record.scope, record.verifiedOnly ? 1 : 0, record.createdAt);
        },
        catch: toStorageError("upsertStandingApproval"),
      }),
    deleteStandingApprovals: (match) =>
      Effect.try({
        try: () => {
          if (match.agentId !== undefined && match.alias !== undefined) {
            db.prepare("DELETE FROM standing_approvals WHERE agent_id = ? OR alias = ?").run(match.agentId, match.alias);
          } else if (match.agentId !== undefined) {
            db.prepare("DELETE FROM standing_approvals WHERE agent_id = ?").run(match.agentId);
          } else if (match.alias !== undefined) {
            db.prepare("DELETE FROM standing_approvals WHERE alias = ?").run(match.alias);
          }
        },
        catch: toStorageError("deleteStandingApprovals"),
      }),
    listAudit: () =>
      Effect.try({
        try: () => {
          const rows = selectAudit.all() as AuditRow[];
          return rows.map((row): AuditEvent => {
            const base: AuditEvent = {
              ts: row.ts,
              agentId: row.agent,
              alias: row.alias,
              scope: row.scope,
              stage: row.stage as AuditEvent["stage"],
              detail: row.detail,
            };
            let event: AuditEvent = base;
            if (row.model_id !== null) event = { ...event, modelId: row.model_id };
            if (row.request_id !== null) event = { ...event, requestId: row.request_id };
            if (row.risk !== null) event = { ...event, risk: row.risk as Risk };
            if (row.recommended_scope !== null) event = { ...event, recommendedScope: row.recommended_scope };
            if (row.decision_source !== null) event = { ...event, decisionSource: row.decision_source as DecisionSource };
            if (row.latency_ms !== null) event = { ...event, latencyMs: row.latency_ms };
            if (row.explanation !== null) event = { ...event, explanation: row.explanation };
            if (row.verified !== null) event = { ...event, verified: row.verified === 1 };
            if (row.client_pid !== null) event = { ...event, clientPid: row.client_pid };
            if (row.client_process !== null) event = { ...event, clientProcess: row.client_process };
            if (row.device_id !== null) event = { ...event, deviceId: row.device_id };
            if (row.origin !== null) event = { ...event, origin: row.origin as AuditEvent["origin"] };
            if (row.transport !== null) event = { ...event, transport: row.transport };
            return event;
          });
        },
        catch: toStorageError("listAudit"),
      }),

    getAgentSecuritySettings: () =>
      Effect.try({
        try: () => {
          const row = selectSecuritySettings.get() as { strict_mode: number; verify_caller_process: number } | undefined;
          if (row === undefined) return { ...DEFAULT_AGENT_SECURITY_SETTINGS };
          return {
            strictMode: Boolean(row.strict_mode),
            verifyCallerProcess: Boolean(row.verify_caller_process),
          };
        },
        catch: toStorageError("getAgentSecuritySettings"),
      }),
    setAgentSecuritySettings: (settings) =>
      Effect.try({
        try: () => {
          upsertSecuritySettings.run(settings.strictMode ? 1 : 0, settings.verifyCallerProcess ? 1 : 0);
        },
        catch: toStorageError("setAgentSecuritySettings"),
      }),
    getWardenSettings: () =>
      Effect.try({
        try: () => {
          const row = selectSettings.get() as WardenSettingsRow | undefined;
          if (row === undefined) {
            return defaultWardenSettings();
          }
          return wardenSettingsFromRow(row);
        },
        catch: toStorageError("getWardenSettings"),
      }),
        getLocalAuthRecord: () =>
      Effect.try({
        try: () => {
          const row = selectLocalAuth.get() as LocalAuthRow | undefined;
          if (row === undefined) {
            return { ...DEFAULT_LOCAL_AUTH_RECORD };
          }
          return {
            enabled: Boolean(row.enabled),
            pinHash: row.pin_hash,
            salt: row.salt,
            biometricEnabled: Boolean(row.biometric_enabled),
            requireOnApproval: Boolean(row.require_on_approval),
            requireOnLaunch: Boolean(row.require_on_launch),
            requireOnSettings: Boolean(row.require_on_settings),
            autoLockMinutes: row.auto_lock_minutes,
          };
        },
        catch: toStorageError("getLocalAuthRecord"),
      }),
    setLocalAuthRecord: (record) =>
      Effect.try({
        try: () => {
          upsertLocalAuth.run(
            record.enabled ? 1 : 0,
            record.pinHash,
            record.salt,
            record.biometricEnabled ? 1 : 0,
            record.requireOnApproval ? 1 : 0,
            record.requireOnLaunch ? 1 : 0,
            record.requireOnSettings ? 1 : 0,
            record.autoLockMinutes,
          );
        },
        catch: toStorageError("setLocalAuthRecord"),
      }),
    setWardenSettings: (settings) =>
      Effect.try({
        try: () => {
          upsertSettings.run(
            settings.provider,
            settings.model,
            settings.effort,
            settings.metaApiBaseUrl,
            settings.localBaseUrl,
            settings.localApi,
            settings.localModel,
          );
        },
        catch: toStorageError("setWardenSettings"),
      }),
    listAgents: () =>
      Effect.try({
        try: () => {
          const rows = selectAllAgents.all() as AgentRow[];
          return rows.map((r): AgentRecord => ({
            id: r.id,
            name: r.name,
            token: "",
            tokenPrefix: r.token_prefix,
            createdAt: r.created_at,
            revoked: r.revoked === 1,
            deviceId: r.device_id,
          }));
        },
        catch: toStorageError("listAgents"),
      }),
    getAgent: (id) =>
      Effect.try({
        try: () => {
          const row = selectAgentById.get(id) as AgentRow | undefined;
          return row === undefined
            ? undefined
            : {
                id: row.id,
                name: row.name,
                token: "",
                tokenPrefix: row.token_prefix,
                createdAt: row.created_at,
                revoked: row.revoked === 1,
                deviceId: row.device_id,
              };
        },
        catch: toStorageError("getAgent"),
      }),
    getAgentByToken: (token) =>
      Effect.try({
        try: () => {
          const row = selectAgentByToken.get(hashAgentToken(token)) as AgentRow | undefined;
          return row === undefined || row.token_hash === null || !timingSafeEqual(Buffer.from(row.token_hash), Buffer.from(hashAgentToken(token)))
            ? undefined
            : { id: row.id, name: row.name, token: "", tokenPrefix: row.token_prefix, createdAt: row.created_at, revoked: row.revoked === 1, deviceId: row.device_id };
        },
        catch: toStorageError("getAgentByToken"),
      }),
    addAgent: (id, name, token, deviceId) =>
      Effect.try({
        try: () => {
          insertAgent.run(id, name, hashAgentToken(token), token.slice(0, 16), new Date().toISOString(), deviceId ?? null);
        },
        catch: toStorageError("addAgent"),
      }),
    revokeAgent: (id) =>
      Effect.try({
        try: () => {
          revokeAgentStmt.run(id);
        },
        catch: toStorageError("revokeAgent"),
      }),
    listDevices: () =>
      Effect.try({
        try: () => (selectAllDevices.all() as DeviceRow[]).map(toDevice),
        catch: toStorageError("listDevices"),
      }),
    getDevice: (id) =>
      Effect.try({
        try: () => {
          const row = selectDeviceById.get(id) as DeviceRow | undefined;
          return row === undefined ? undefined : toDevice(row);
        },
        catch: toStorageError("getDevice"),
      }),
    getDeviceByFingerprint: (fingerprint) =>
      Effect.try({
        try: () => {
          const row = selectDeviceByFingerprint.get(fingerprint) as DeviceRow | undefined;
          return row === undefined ? undefined : toDevice(row);
        },
        catch: toStorageError("getDeviceByFingerprint"),
      }),
    addDevice: (device) =>
      Effect.try({
        try: () => {
          insertDevice.run(device.id, device.name, device.platform, device.certFingerprint, device.transport, device.createdAt, device.lastSeenAt, device.revoked ? 1 : 0);
        },
        catch: toStorageError("addDevice"),
      }),
    renameDevice: (id, name) =>
      Effect.try({
        try: () => {
          renameDeviceStmt.run(name, id);
        },
        catch: toStorageError("renameDevice"),
      }),
    setDeviceRevoked: (id, revoked) =>
      Effect.try({
        try: () => {
          setDeviceRevokedStmt.run(revoked ? 1 : 0, id);
        },
        catch: toStorageError("setDeviceRevoked"),
      }),
    touchDeviceLastSeen: (id, ts) =>
      Effect.try({
        try: () => {
          touchDeviceStmt.run(ts, id);
        },
        catch: toStorageError("touchDeviceLastSeen"),
      }),
    listDeviceAliasPolicies: (deviceId) =>
      Effect.try({
        try: () => {
          const rows = selectDevicePolicies.all(deviceId) as { device_id: string; alias: string; allow_write: number }[];
          return rows.map((r) => ({ deviceId: r.device_id, alias: r.alias, allowWrite: r.allow_write === 1 }));
        },
        catch: toStorageError("listDeviceAliasPolicies"),
      }),
    setDeviceAliasPolicy: (deviceId, alias, allowWrite) =>
      Effect.try({
        try: () => {
          upsertDevicePolicy.run(deviceId, alias, allowWrite ? 1 : 0);
        },
        catch: toStorageError("setDeviceAliasPolicy"),
      }),
    deleteDeviceAliasPolicies: (deviceId) =>
      Effect.try({
        try: () => {
          deleteDevicePoliciesStmt.run(deviceId);
        },
        catch: toStorageError("deleteDeviceAliasPolicies"),
      }),
    getRemoteSettingsRow: () =>
      Effect.try({
        try: () => {
          const row = selectRemoteSettings.get() as { enabled: number; host: string; port: number; require_auth_remote_approval: number } | undefined;
          if (row === undefined) {
            return { enabled: false, host: "127.0.0.1", port: 7078, requireAuthForRemoteApproval: true };
          }
          return {
            enabled: row.enabled === 1,
            host: row.host,
            port: row.port,
            requireAuthForRemoteApproval: row.require_auth_remote_approval === 1,
          };
        },
        catch: toStorageError("getRemoteSettingsRow"),
      }),
    setRemoteSettingsRow: (row) =>
      Effect.try({
        try: () => {
          upsertRemoteSettings.run(row.enabled ? 1 : 0, row.host, row.port, row.requireAuthForRemoteApproval ? 1 : 0);
        },
        catch: toStorageError("setRemoteSettingsRow"),
      }),
  };
}

// Closes the database when the layer's scope ends. For one-shot callers
// (the CLI): leaving vault.db open makes Windows refuse to delete or move
// it. Long-lived callers that keep the service past the scope use
// VaultStoreLive, which stays open for the life of the process.
export const VaultStoreScoped = (dbPath: string): Layer.Layer<VaultStore> =>
  Layer.scoped(
    VaultStore,
    Effect.map(
      Effect.acquireRelease(
        Effect.sync(() => new Database(dbPath)),
        (db) => Effect.sync(() => db.close()),
      ),
      makeStore,
    ),
  );

// The optional key argument is accepted for older call sites and ignored.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function VaultStoreLive(dbPath: string, _legacyMasterKey?: Buffer): Layer.Layer<VaultStore> {
  return Layer.sync(VaultStore, () => makeStore(new Database(dbPath)));
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function VaultStoreTest(_legacyMasterKey?: Buffer): Layer.Layer<VaultStore> {
  return Layer.sync(VaultStore, () => makeStore(new Database(":memory:")));
}
