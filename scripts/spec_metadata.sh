#!/usr/bin/env bash
# Generates metadata for handoff documents and specs
# Usage: scripts/spec_metadata.sh

set -euo pipefail

# Git information
COMMIT_HASH=$(git rev-parse HEAD)
BRANCH=$(git rev-parse --abbrev-ref HEAD)
REPO_NAME=$(basename "$(git rev-parse --show-toplevel)")

# Date/time information
ISO_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
DATE_YYYY_MM_DD=$(date +"%Y-%m-%d")
TIME_HH_MM_SS=$(date +"%H-%M-%S")

# Output
cat <<EOF
Metadata for handoff/spec documents:
=====================================
git_commit: ${COMMIT_HASH}
branch: ${BRANCH}
repository: ${REPO_NAME}
date (ISO): ${ISO_DATE}
date (YYYY-MM-DD): ${DATE_YYYY_MM_DD}
time (HH-MM-SS): ${TIME_HH_MM_SS}

Suggested filename pattern:
  ${DATE_YYYY_MM_DD}_${TIME_HH_MM_SS}_description.md
EOF
