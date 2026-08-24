#!/usr/bin/env bash
set -euo pipefail

CLIENT_NS="client"
SERVER_NS="server"
VETH_C="veth-c"
VETH_S="veth-s"
CLIENT_IP="10.0.0.1/24"
SERVER_IP="10.0.0.2/24"

echo "[+] Provisioning network namespaces: ${CLIENT_NS}, ${SERVER_NS}"
ip netns add "${CLIENT_NS}" 2>/dev/null || true
ip netns add "${SERVER_NS}" 2>/dev/null || true

echo "[+] Creating veth pair: ${VETH_C} <-> ${VETH_S}"
ip link add "${VETH_C}" type veth peer name "${VETH_S}" 2>/dev/null || true

echo "[+] Moving veth interfaces to respective namespaces"
ip link set "${VETH_C}" netns "${CLIENT_NS}" 2>/dev/null || true
ip link set "${VETH_S}" netns "${SERVER_NS}" 2>/dev/null || true

echo "[+] Assigning IP addresses and bringing up interfaces"
ip netns exec "${CLIENT_NS}" ip addr add "${CLIENT_IP}" dev "${VETH_C}" 2>/dev/null || true
ip netns exec "${CLIENT_NS}" ip link set "${VETH_C}" up
ip netns exec "${CLIENT_NS}" ip link set lo up

ip netns exec "${SERVER_NS}" ip addr add "${SERVER_IP}" dev "${VETH_S}" 2>/dev/null || true
ip netns exec "${SERVER_NS}" ip link set "${VETH_S}" up
ip netns exec "${SERVER_NS}" ip link set lo up

echo "[+] Netns setup complete."
ip netns exec "${CLIENT_NS}" ping -c 1 10.0.0.2 >/dev/null && echo "[+] Connectivity verified: 10.0.0.1 -> 10.0.0.2"
