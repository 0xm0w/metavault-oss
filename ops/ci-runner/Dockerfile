# MetaVault CI runner (Linux). Socket-free, non-root, no Docker-in-Docker.
# Base image pinned by digest (node:22-bookworm-slim, checked 2026-11-04).
FROM node:22-bookworm-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da

# actions/runner v2.338.2, linux-x64. SHA-256 matches both the GitHub release
# asset digest and the release notes.
ARG RUNNER_VERSION=2.338.2
ARG RUNNER_SHA256=baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git openssh-server python3 make g++ \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd --create-home --uid 1001 --shell /bin/bash runner \
 && mkdir -p /home/runner/actions-runner /state /work \
 && chown -R runner:runner /home/runner /state /work

WORKDIR /home/runner/actions-runner
RUN curl -fsSL -o runner.tgz "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz" \
 && echo "${RUNNER_SHA256}  runner.tgz" | sha256sum -c - \
 && tar xzf runner.tgz && rm runner.tgz \
 && ./bin/installdependencies.sh \
 && rm -rf /var/lib/apt/lists/* \
 && chown -R runner:runner /home/runner

COPY --chown=runner:runner entrypoint.sh /home/runner/entrypoint.sh
# Strip CR in case the file was checked out with Windows line endings.
RUN sed -i 's/\r$//' /home/runner/entrypoint.sh && chmod 0755 /home/runner/entrypoint.sh
USER runner

ENTRYPOINT ["/home/runner/entrypoint.sh"]
