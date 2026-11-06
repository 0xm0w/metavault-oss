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
  const copy: NodeJS.ProcessEnv = { ...env };
  for (const key of VAULT_SECRET_ENV_KEYS) {
    delete copy[key];
  }
  return copy;
}
