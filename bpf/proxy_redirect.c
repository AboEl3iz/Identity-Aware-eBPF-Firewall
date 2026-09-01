// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "headers/common.h"

char __license[] SEC("license") = "GPL";

/* SOCKHASH map — MUST be the same kernel instance as sockops via BPF pin.
 * If loaded independently without map sharing, each object gets its own
 * private map and redirect silently fails (no errors, just no acceleration). */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65536);
    __type(key, struct sock_key);
    __type(value, __u32);
} sock_hash SEC(".maps");

/* Shared per-CPU stats map for redirect accounting.
 * rx_bytes     = total bytes processed by sk_msg
 * pass_packets = successful redirects
 * drop_packets = failed redirects (peer not in map, non-local traffic) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_value);
} sockops_stats_map SEC(".maps");

/* Shared Ring Buffer map for emitting redirect audit events to userspace TUI */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} audit_ringbuf SEC(".maps");

SEC("sk_msg")
int proxy_redirect_func(struct sk_msg_md *msg) {
    /*
     * Construct the PEER socket's lookup key.
     *
     * This socket was registered in sock_hash as:
     *   key = {local_ip, remote_ip, local_port, remote_port}
     *
     * The peer socket registered itself as:
     *   key = {peer_local_ip, peer_remote_ip, peer_local_port, peer_remote_port}
     *
     * From our perspective, the peer's key is:
     *   {our_remote_ip, our_local_ip, our_remote_port, our_local_port}
     *
     * In sk_msg context, both local_port and remote_port are in HOST byte order
     * (unlike sockops where remote_port is network byte order).
     * The bpf_ntohl() applied during sockops registration and the raw access
     * here produce matching keys.
     */
    struct sock_key peer_key = {
        .sip   = msg->remote_ip4,
        .dip   = msg->local_ip4,
        .sport = msg->remote_port,
        .dport = msg->local_port,
    };

    /* Attempt direct socket-to-socket redirect.
     * BPF_F_INGRESS delivers the message into the target socket's
     * receive queue (not back through send path). */
    int ret = bpf_msg_redirect_hash(msg, &sock_hash, &peer_key, BPF_F_INGRESS);

    /* Update per-CPU statistics */
    __u32 zero = 0;
    struct stats_value *stats = bpf_map_lookup_elem(&sockops_stats_map, &zero);
    if (stats) {
        stats->rx_bytes += (msg->data_end - msg->data);
        if (ret == SK_PASS) {
            stats->pass_packets++;   /* redirect succeeded */
        } else {
            stats->drop_packets++;   /* redirect failed, will fall through */
        }
    }

    if (ret == SK_PASS) {
        /* Emit audit event over ring buffer for TUI observability */
        struct audit_event *event = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*event), 0);
        if (event) {
            event->timestamp_ns = bpf_ktime_get_ns();
            event->src_ip       = msg->local_ip4;
            event->dst_ip       = msg->remote_ip4;
            event->src_port     = (unsigned short)msg->local_port;
            event->dst_port     = (unsigned short)msg->remote_port;
            event->protocol     = 6; /* TCP */
            event->verdict      = VERDICT_REDIRECT; /* 2 */
            event->reason_code  = REASON_SOCKOPS_REDIRECT; /* 7 */
            event->rule_id      = 701;
            event->cgroup_id    = bpf_get_current_cgroup_id();
            event->identity_id  = 0;
            event->pad          = 0;
            bpf_ringbuf_submit(event, 0);
        }
    }

    /*
     * ALWAYS return SK_PASS.
     *
     * If redirect succeeded: data went directly to peer socket recv buffer.
     * If redirect failed: data flows through normal TCP/IP stack (non-local peer).
     *
     * We NEVER return SK_DROP here. This program is a transparent acceleration
     * layer, not a policy enforcement layer. Dropping would silently kill
     * legitimate traffic to remote (non-co-located) endpoints.
     */
    return SK_PASS;
}
