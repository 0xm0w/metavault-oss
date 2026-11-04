#!/usr/bin/env bash
# Registers once (one-time token read from a mounted file, never an env var),
# keeps the runner credential files in /state, then runs the runner.
set -euo pipefail
cd /home/runner/actions-runner
FILES=(.runner .credentials .credentials_rsaparams)

if [ -f /state/.runner ]; then
  for f in "${FILES[@]}"; do cp -f "/state/$f" "./$f"; done
else
  if [ ! -s /run/secrets/runner_token ]; then
    echo "Not registered and no /run/secrets/runner_token. See ops/ci-runner/README.md." >&2
    exit 1
  fi
  ./config.sh --unattended --replace \
    --url "https://github.com/${RUNNER_REPO:?RUNNER_REPO is required}" \
    --token "$(cat /run/secrets/runner_token)" \
    --name "${RUNNER_NAME:-metavault-ci-1}" \
    --labels "metavault-ci" \
    --work /work
  for f in "${FILES[@]}"; do cp -f "./$f" "/state/$f"; done
  chmod 600 /state/.credentials /state/.credentials_rsaparams
fi
exec ./run.sh
