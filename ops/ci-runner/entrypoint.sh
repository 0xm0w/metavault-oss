#!/usr/bin/env bash
# Two modes, so the one-time token never lives in the long-running container:
#   register: read the token file, register once, store the runner credential
#             files in /state, exit. Run via compose.register.yml only.
#   run:      copy the stored credential files in and start the runner.
set -euo pipefail
cd /home/runner/actions-runner
FILES=(.runner .credentials .credentials_rsaparams)

case "${1:-run}" in
  register)
    [ -s /run/secrets/runner_token ] || { echo "No /run/secrets/runner_token. See README." >&2; exit 1; }
    ./config.sh --unattended --replace \
      --url "https://github.com/${RUNNER_REPO:?RUNNER_REPO is required}" \
      --token "$(cat /run/secrets/runner_token)" \
      --name "${RUNNER_NAME:-metavault-ci-1}" \
      --labels "metavault-ci" \
      --work /work
    for f in "${FILES[@]}"; do cp -f "./$f" "/state/$f"; done
    chmod 600 /state/.credentials /state/.credentials_rsaparams
    echo "Registered. Delete runner-token.txt now."
    ;;
  run)
    [ -f /state/.runner ] || { echo "Not registered. Run the register step first (see README)." >&2; exit 1; }
    for f in "${FILES[@]}"; do cp -f "/state/$f" "./$f"; done
    exec ./run.sh
    ;;
  *) echo "usage: entrypoint.sh register|run" >&2; exit 2 ;;
esac
