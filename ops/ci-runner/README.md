# MetaVault CI runner (Linux, local Docker)

Runs the Ubuntu CI job on a local Docker host. Windows checks do not run here.

What it is: one container from a pinned Node 22 base image and a checksum-pinned
GitHub runner. It runs as a non-root user, with all capabilities dropped,
`no-new-privileges`, no published ports, no Docker socket and no privileged
mode. It has its own named volumes (`mv_state`, `mv_work`). It shares nothing
with other projects' runners. This is not complete isolation: it is a container
on your Docker host, and job code can reach the network and anything the
container can see. Do not run untrusted code on it.

The runner label is `metavault-ci`. The CI workflow requires
`[self-hosted, linux, metavault-ci]`, so other repos' runners never match it.

## One-time setup (on the PC with Docker)

1. In GitHub: repo Settings > Actions > Runners > New self-hosted runner. Copy
   the registration token (valid about one hour).
2. In `ops/ci-runner`, save the token to `runner-token.txt` (git-ignored):
   `Set-Content -NoNewline runner-token.txt '<token>'`
3. `docker compose up -d --build`
4. Check the runner shows Idle in the repo's Runners page.
5. Delete `runner-token.txt`. The token is single-use. The runner keeps its own
   credential in the `mv_state` volume.

To remove it: `docker compose down -v`, then remove the runner in GitHub.

## Notes

- The workflow uses read-only `contents` permission, `persist-credentials: false`,
  no secrets, and runs the self-hosted leg only for pushes and same-repo pull
  requests (never forks).
- If the box is off, the Ubuntu job queues until it returns. Windows jobs stay on
  `windows-latest`.
- The Ubuntu job needs `sshd` for one integration test. It is installed in the
  image. It runs as a non-root user, so that test may skip. Check the test log.
