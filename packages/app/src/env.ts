/**
 * App-local copy of the MetaVault environment resolution (the Electron
 * package builds with rootDir=src and cannot import from packages/core).
 * Only the METAVAULT_* names are read. The pre-rebrand prefix is no longer
 * supported (see CHANGELOG, "Breaking: legacy env var prefix dropped").
 */
export function metavaultEnv(suffix: string): string | undefined {
  return process.env[`METAVAULT_${suffix}`];
}
