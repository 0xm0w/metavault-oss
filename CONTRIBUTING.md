# Contributing to OpenVault

Thanks for helping build the wallet for agents.

## Ground rules

- **Never commit a real secret.** Tests use fake/canary credentials
  only. The canary test (`test/canary.test.ts`) must keep passing.
- **Security invariants are not negotiable.** If a change weakens a
  spec invariant (see `docs/superpowers/specs/`), the PR must say so
  explicitly and explain why the new behaviour is still safe.
- **Effect discipline (daemon-side packages):** services are
  `Context.Tag`s, failures are tagged errors, Effect Schema validates
  every untrusted boundary. The Electron renderer imports no `effect`.
- **`evaluatePolicy` stays pure.** Policy is deterministic by design.

## Development

Use Node 22 (the version CI uses).

```bash
npm ci                  # install from the lockfile, exactly like CI
npm run test            # vitest
npm run typecheck       # tsc --noEmit (strict)
npm run lint            # eslint, --max-warnings 0
npm run test:coverage   # coverage gates (per-package thresholds)
```

All gates must pass locally before a PR, and again in CI. Write tests
first for behaviour changes; keep the smallest durable test in the
project's test layout.

### Gates

| Gate | Command | What it proves |
| --- | --- | --- |
| Tests | `npm run test` | The full Vitest suite passes |
| Types | `npm run typecheck` | Strict `tsc --noEmit` passes |
| Lint | `npm run lint` | ESLint passes with `--max-warnings 0` |
| Coverage | `npm run test:coverage` | Per-package coverage thresholds in `vitest.config.ts` hold (Ubuntu CI) |

CI (`.github/workflows/ci.yml`) runs lint, typecheck, and tests on
`windows-latest` and `ubuntu-latest` with Node 22, plus coverage on
Ubuntu. CodeQL (`.github/workflows/codeql.yml`) analyses
javascript-typescript on PRs and weekly.

## Branches and pull requests

- **`main` is PR-only.** No direct pushes to `main`; every change lands
  through a pull request.
- **CI must be green before merge** — lint, typecheck, and tests on both
  Windows and Ubuntu (and coverage on Ubuntu).
- **At least one review is required** before merging. Changes under
  `packages/core/` and `packages/daemon/` are owned in
  `.github/CODEOWNERS` and need owner review.
- One concern per PR, with the test that proves it.
- Describe user-visible behaviour changes and any threat-model impact.
  Fill in the PR template, including the secret-handling checklist, and
  attach screenshots for UI changes (no secret visible; key fields empty
  or showing only a last-4 status).
- Do not add cloud accounts, sync, or telemetry — local-first is a
  product guarantee, not a gap to fill later.

## Commit style

Use Conventional Commits, matching the history (`git log --oneline`):

```text
feat(daemon): warden settings + encrypted Meta API key path
fix(brain): deep-verify keeps the narrower scope, never widens
test: coverage gates, canary sweep, MCP-daemon e2e
ci: GitHub Actions (test, CodeQL, release) + OSS repo rules
docs: screenshots and end-to-end agent flows
chore(release): v0.1.0-alpha.1
```

Format: `type(optional-scope): short imperative summary`. Keep the
summary focused on what changed and why it is safe; call out any
security-invariant impact in the body.

## Releases

Pushing a tag matching `v*` runs `.github/workflows/release.yml` on
Windows: it gates on lint/typecheck/test, builds the app, packages the
NSIS installer with electron-builder, writes `SHA256SUMS`, and publishes
a GitHub release with the installer and checksums attached. A tag whose
name contains a hyphen (for example `v0.1.0-alpha.2`) is published as a
prerelease. `v0.1.0` is a release.

## Manual repo-settings checklist (repo owner only)

> **Not enforced by any file in this repo.** The items below live in
> GitHub repository settings, which cannot be committed. They are
> **not claimed to be enabled or enforced** until the repo owner has
> toggled each one and checked it off here. Workflow and template files
> in `.github/` do not turn these on.

- [ ] Branch protection / ruleset on `main`: require a pull request,
      require at least one approving review (including Code Owners),
      require status checks (CI on Windows + Ubuntu) to pass, block
      force pushes, and restrict direct pushes.
- [ ] Secret scanning: enable secret scanning and push protection
      (Settings → Code security).
- [ ] Dependabot alerts and security updates: enable (Settings → Code
      security). The version-update schedule itself *is* committed in
      `.github/dependabot.yml`; alerts are the manual part.
- [ ] Private vulnerability reporting: enable (Settings → Code
      security), so `SECURITY.md` reports have a private channel.
- [ ] CodeQL: confirm code-scanning alerts are visible under the
      Security tab after the first `.github/workflows/codeql.yml` run.

## License

By contributing, you agree your contributions are licensed under the
Apache License 2.0 (see `LICENSE`).
