#!/usr/bin/env bash
set -euo pipefail

CGROUP_ROOT="/sys/fs/cgroup"
WORKLOAD_ALLOWED="${CGROUP_ROOT}/test-app-allowed"
WORKLOAD_BLOCKED="${CGROUP_ROOT}/test-app-blocked"

if [ ! -f "${CGROUP_ROOT}/cgroup.procs" ]; then
    echo "[!] Error: Cgroup v2 is not mounted at ${CGROUP_ROOT}"
    exit 1
fi

echo "[+] Creating test cgroup v2 directories: ${WORKLOAD_ALLOWED}, ${WORKLOAD_BLOCKED}"
mkdir -p "${WORKLOAD_ALLOWED}"
mkdir -p "${WORKLOAD_BLOCKED}"
echo "[+] Cgroup v2 setup complete."
