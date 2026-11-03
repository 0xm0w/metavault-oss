/**
 * App-local copy of the MetaVault environment resolution (the Electron
 * package builds with rootDir=src and cannot import from packages/core).
 * METAVAULT_* is canonical; legacy METAVAULT_* keeps working.
 */
export function metavaultEnv(suffix: string): string | undefined {
  return process.env[`METAVAULT_${suffix}`] ?? process.env[`METAVAULT_${suffix}`];
}
