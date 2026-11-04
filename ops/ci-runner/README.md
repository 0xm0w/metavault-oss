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

## One-time setup (PowerShell on the PC with Docker Desktop)

Do not merge anything for this. The CI run for the PR branch uses the runner as
soon as it is online.

```powershell
git clone https://github.com/0xm0w/metavault-oss.git
cd metavault-oss
git checkout feat/local-ui-cleanup-lock-grant-status
cd ops\ci-runner
docker compose build
```

1. In GitHub: repo Settings > Actions > Runners > New self-hosted runner. Copy
   the registration token. GitHub documents that it expires after one hour.
2. Run the registration script. It builds, asks for the token with hidden
   input, writes it to `runner-token.txt` only for the register step, deletes
   the file even if a step fails, and starts the runner only if register
   succeeded:
   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\register.ps1
   ```
3. Check the runner shows **Idle** with the label `metavault-ci` under the
   repo's Settings > Actions > Runners. Queued Ubuntu jobs for the PR then start
   by themselves. Jobs queued for more than 24 hours fail, so a new push or a
   re-run of the Ubuntu job may be needed.

To remove it: `docker compose down -v`, then remove the runner in GitHub.

This only touches the `metavault-ci` project, its container
`metavault-ci-1` and the volumes `metavault-ci_mv_state` and
`metavault-ci_mv_work`. Other containers, including the grm runners, are not
touched.

## Resource use

The memory and CPU limits are ceilings (default 4g and 2 CPUs), not
reservations. Change them with `MV_RUNNER_MEM` and `MV_RUNNER_CPUS` if the host
is shared. Other runners on the host are not touched.

## What this does and does not protect

- The one-time token never exists in the long-running container, and the
  workflows get no repository secrets.
- The runner credential is stored in the `mv_state` volume and copied into the
  runner directory at start. Job steps run as the same user as the runner, so
  job code can read that credential. It lets a holder take jobs for this repo
  only. This is why only your own pushes and same-repo PRs run here. Do not
  run untrusted code on it. To rotate it: remove the runner in GitHub, then
  repeat the setup.

## Notes

- The workflow uses read-only `contents` permission, `persist-credentials: false`,
  no secrets, and runs the self-hosted leg only for pushes and same-repo pull
  requests (never forks).
- If the box is off, the Ubuntu job queues until it returns. Windows jobs stay on
  `windows-latest`.
- The Ubuntu job needs `sshd` for one integration test. It is installed in the
  image, and the workflow fails if that test is skipped, so required coverage
  is not lost silently.
