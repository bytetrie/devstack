#!/usr/bin/env bash
# Bring this container in line with the project: system packages from
# infra/apt-packages.txt (installed by root through devstack-sync, Debian repos
# only), then npm packages from the lockfile. Safe to run again at any time.
set -euo pipefail
cd "$(dirname "$0")/.."
sudo devstack-sync packages < infra/apt-packages.txt
pnpm install --frozen-lockfile

# If the container's package set changed, the committed inventory is now behind it. Only the host
# can regenerate it (syft runs in here, but incus and the project's git live out there), so the
# reminder goes here -- at the point of change -- rather than in a git hook: .git/hooks is code the
# host executes and is mounted read-only in this container on purpose.
cat <<'EOF'

Environment synced. If anything above changed, the committed dependency
inventory is now behind the container. On the host:
  ./devstack sbom generate     # refresh @@SBOM_DIR@@/
  ./devstack sbom scan         # check it for known vulnerabilities
Commit @@SBOM_DIR@@/ together with the change that caused it; `devstack status`
says whether it looks stale, and `devstack sbom check` is the exact answer.
EOF
