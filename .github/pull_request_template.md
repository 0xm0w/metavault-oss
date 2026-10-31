## Summary

<!-- What does this PR change, and why? One concern per PR. -->

## Behaviour / threat-model impact

<!-- User-visible changes. Does this touch policy, token guards, credential
     handling, the marshal prompt, audit rows, or IPC? Say so explicitly. -->

## Tests run

- [ ] `npm run test`
- [ ] `npm run typecheck`
- [ ] `npm run lint`
- [ ] `npm run test:coverage` (if coverage gates or covered packages changed)
- [ ] New/changed behaviour has a test that would fail without this change

<!-- Paste the relevant pass/fail summary, not just "tests pass". -->

## Secret-handling checklist

- [ ] No real secret, token, vault file, or `.db` is committed; tests use fake/canary values only
- [ ] No secret is logged, put in an audit row, sent to the marshal/model, returned to an agent, or rendered in the UI after save
- [ ] The canary tests still pass (`test/canary.test.ts`, `test/security/canary.test.ts`) if credential paths were touched
- [ ] Human-mutation routes still require `x-openvault-token`; MCP/agent routes still never accept it
- [ ] Deterministic policy can still only be narrowed/escalated by the marshal, never widened

## UI screenshots

<!-- Required for renderer/UI changes: attach before/after screenshots.
     Make sure no secret or key field value is visible (key fields must be
     empty or show only a last-4 status). Write "N/A — no UI change" if so. -->

## Notes for reviewers

<!-- Anything risky, deferred, or worth a second look. -->
