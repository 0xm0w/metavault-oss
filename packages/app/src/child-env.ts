// Vault secrets must not ride into child processes (ssh, PowerShell, gateway,
// MCP self-check). Callers copy process.env through here and then put back
// only the non-secret values that child actually needs.

export const VAULT_SECRET_ENV_KEYS = [
  "METAVAULT_DAEMON_TOKEN",
  "METAVAULT_AGENT_TOKEN",
  "METAVAULT_MASTER_KEY",
  "METAVAULT_GATEWAY_TOKEN",
  "METAVAULT_ALLOW_ENV_MASTER_KEY",
] as const;

export function omitVaultSecrets(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const blocked = new Set<string>(VAULT_SECRET_ENV_KEYS);
  const copy: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(env)) {
    if (!blocked.has(key)) copy[key] = value;
  }
  return copy;
}
