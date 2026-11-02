/**
 * Central resolution for MetaVault environment variables. The METAVAULT_*
 * names are canonical after the rebrand; legacy OPENVAULT_* names keep
 * working so existing vaults, IDE configs and scripts are not broken.
 */
export function metavaultEnv(suffix: string): string | undefined {
  return process.env[`METAVAULT_${suffix}`] ?? process.env[`OPENVAULT_${suffix}`];
}
