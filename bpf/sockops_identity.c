// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "headers/common.h"

char __license[] SEC("license") = "GPL";

/* SOCKHASH map — shared with sk_msg program via BPF pin.
 * Key is the socket 4-tuple (sip, dip, sport, dport).
 * The kernel manages socket references internally; value is a dummy __u32. */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65536);
    __type(key, struct sock_key);
    __type(value, __u32);
} sock_hash SEC(".maps");

/* Per-CPU stats for sockops event monitoring.
 * rx_packets  = total sockops callback invocations
 * pass_packets = successful sock_hash insertions
 * drop_packets = failed insertions (duplicate, map full, etc.)
 * rx_bytes     = reserved for future use */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_value);
} sockops_stats_map SEC(".maps");

/* Shared Ring Buffer map for emitting sockops registration audit events to userspace TUI */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} audit_ringbuf SEC(".maps");

SEC("sockops")
int sockops_identity_func(struct bpf_sock_ops *skops) {
    /* Only handle IPv4 TCP sockets */
    if (skops->family != 2)   /* AF_INET */
        return 0;

    __u32 op = skops->op;

    /* Intercept TCP connection establishment events only.
     * ACTIVE_ESTABLISHED  (op=4): fires on the connecting (client) side
     * PASSIVE_ESTABLISHED (op=5): fires on the listening (server) side
     * Both endpoints must register in sock_hash for redirect to work. */
    if (op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
        op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
        return 0;

    /* Build 4-tuple key from sock_ops context.
     *
     * CRITICAL BYTE ORDER NOTE:
     *   skops->local_port  is in HOST byte order
     *   skops->remote_port is in NETWORK byte order (kernel inconsistency)
     *
     * We normalize remote_port to host order with bpf_ntohl() so that
     * the key matches what sk_msg constructs (where both ports are host order). */
    struct sock_key key = {
        .sip   = skops->local_ip4,
        .dip   = skops->remote_ip4,
        .sport = skops->local_port,
        .dport = bpf_ntohl(skops->remote_port),
    };

    /* Insert this socket into the SOCKHASH map.
     * BPF_NOEXIST prevents overwriting if the key already exists. */
    int ret = bpf_sock_hash_update(skops, &sock_hash, &key, BPF_NOEXIST);

    /* Update per-CPU statistics */
    __u32 zero = 0;
    struct stats_value *stats = bpf_map_lookup_elem(&sockops_stats_map, &zero);
    if (stats) {
        stats->rx_packets++;       /* total sockops events processed */
        if (ret == 0) {
            stats->pass_packets++; /* successful registration */
        } else {
            stats->drop_packets++; /* registration failed */
        }
    }

    if (ret == 0) {
        /* Emit audit event for sockops registration to TUI ring buffer consumer */
        struct audit_event *event = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*event), 0);
        if (event) {
            event->timestamp_ns = bpf_ktime_get_ns();
            event->src_ip       = skops->local_ip4;
            event->dst_ip       = skops->remote_ip4;
            event->src_port     = (unsigned short)skops->local_port;
            event->dst_port     = (unsigned short)bpf_ntohl(skops->remote_port);
            event->protocol     = 6; /* TCP */
            event->verdict      = VERDICT_PASS; /* 0 */
            event->reason_code  = REASON_SOCKOPS_REDIRECT; /* 7 */
            event->rule_id      = 701;
            event->cgroup_id    = bpf_get_current_cgroup_id();
            event->identity_id  = 0;
            event->pad          = 0;
            bpf_ringbuf_submit(event, 0);
        }
    }

    return 0;
}
