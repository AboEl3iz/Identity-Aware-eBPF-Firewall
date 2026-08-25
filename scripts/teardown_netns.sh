#!/usr/bin/env bash
set -euo pipefail

CLIENT_NS="client"
SERVER_NS="server"

echo "[-] Cleaning up network namespaces..."
ip netns del "${CLIENT_NS}" 2>/dev/null || true
ip netns del "${SERVER_NS}" 2>/dev/null || true
echo "[-] Netns cleanup complete."
