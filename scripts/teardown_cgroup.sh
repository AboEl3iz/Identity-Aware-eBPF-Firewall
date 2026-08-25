#!/usr/bin/env bash
set -euo pipefail

CGROUP_ROOT="/sys/fs/cgroup"
WORKLOAD_ALLOWED="${CGROUP_ROOT}/test-app-allowed"
WORKLOAD_BLOCKED="${CGROUP_ROOT}/test-app-blocked"

echo "[-] Cleaning up test cgroup v2 directories..."
rmdir "${WORKLOAD_ALLOWED}" 2>/dev/null || true
rmdir "${WORKLOAD_BLOCKED}" 2>/dev/null || true
echo "[-] Cgroup v2 cleanup complete."
