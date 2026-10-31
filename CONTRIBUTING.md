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

```bash
npm install
npm run test        # vitest
npm run typecheck   # tsc --noEmit (strict)
npm run lint        # eslint, --max-warnings 0
```

All three gates must pass before a PR. Write tests first for behaviour
changes; keep the smallest durable test in the project's test layout.

## Pull requests

- One concern per PR, with the test that proves it.
- Describe user-visible behaviour changes and any threat-model impact.
- Do not add cloud accounts, sync, or telemetry — local-first is a
  product guarantee, not a gap to fill later.

## License

By contributing, you agree your contributions are licensed under the
Apache License 2.0 (see `LICENSE`).
