// +build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "headers/bpf_endian.h"
#include "headers/common.h"
#include "headers/maps.h"
#include "headers/state_machine.h"

char __license[] SEC("license") = "GPL";

/* Conntrack LRU Hash Map storing 5-tuple flow states */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_state);
} conntrack_map SEC(".maps");

/* Per-CPU Array for TC statistics counters */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_value);
} tc_stats_map SEC(".maps");

/* Ring buffer map for emitting verdict events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} audit_ringbuf SEC(".maps");

SEC("tc")
int tc_firewall_func(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return TC_ACT_OK;
    }

    /* Non-TCP traffic (UDP, ICMP) is allowed through TC fast-path */
    if (iph->protocol != PROTO_TCP) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcp = (void *)(iph + 1);
    if ((void *)(tcp + 1) > data_end) {
        return TC_ACT_OK;
    }

    __u32 key_idx = 0;
    struct stats_value *stats = bpf_map_lookup_elem(&tc_stats_map, &key_idx);
    if (stats) {
        stats->rx_packets++;
        stats->rx_bytes += skb->len;
    }

    /* Construct 5-Tuple Forward Key */
    struct flow_key key_fwd = {
        .src_ip   = iph->saddr,
        .dst_ip   = iph->daddr,
        .src_port = bpf_ntohs(tcp->source),
        .dst_port = bpf_ntohs(tcp->dest),
        .protocol = iph->protocol,
        .pad      = {0, 0, 0},
    };

    /* Construct 5-Tuple Reverse Key (reply direction) */
    struct flow_key key_rev = {
        .src_ip   = iph->daddr,
        .dst_ip   = iph->saddr,
        .src_port = bpf_ntohs(tcp->dest),
        .dst_port = bpf_ntohs(tcp->source),
        .protocol = iph->protocol,
        .pad      = {0, 0, 0},
    };

    /* Lookup existing flow in conntrack map */
    struct flow_state *state = bpf_map_lookup_elem(&conntrack_map, &key_fwd);
    if (!state) {
        state = bpf_map_lookup_elem(&conntrack_map, &key_rev);
    }

    __u64 now = bpf_ktime_get_ns();

    if (!state) {
        /* Untracked flow */
        if (is_tcp_syn(tcp)) {
            /* New TCP Connection Initialization */
            struct flow_state new_state = {
                .state     = TCP_STATE_SYN_SENT,
                .packets   = 1,
                .bytes     = skb->len,
                .last_seen = now,
                .flags     = 0,
                .pad       = 0,
            };
            bpf_map_update_elem(&conntrack_map, &key_fwd, &new_state, BPF_ANY);
            bpf_map_update_elem(&conntrack_map, &key_rev, &new_state, BPF_ANY);

            if (stats) {
                stats->pass_packets++;
            }
            return TC_ACT_OK;
        }

        /* REJECT: Untracked non-SYN packet */
        if (stats) {
            stats->drop_packets++;
        }

        struct audit_event *event = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*event), 0);
        if (event) {
            event->timestamp_ns = now;
            event->src_ip       = iph->saddr;
            event->dst_ip       = iph->daddr;
            event->src_port     = bpf_ntohs(tcp->source);
            event->dst_port     = bpf_ntohs(tcp->dest);
            event->protocol     = iph->protocol;
            event->verdict      = VERDICT_DROP;
            event->reason_code  = REASON_UNTRACKED_NON_SYN;
            event->rule_id      = 201;
            event->cgroup_id    = bpf_get_current_cgroup_id();
            event->identity_id  = 0;
            event->pad          = 0;
            bpf_ringbuf_submit(event, 0);
        }

        return TC_ACT_SHOT; /* Drop packet */
    }

    /* Existing Tracked Flow Execution */
    if (state->state == TCP_STATE_SYN_SENT) {
        if (is_tcp_syn_ack(tcp) || tcp->ack) {
            state->state = TCP_STATE_ESTABLISHED;
            /* Update reverse key state as well */
            struct flow_state *rev_state = bpf_map_lookup_elem(&conntrack_map, &key_rev);
            if (rev_state) {
                rev_state->state = TCP_STATE_ESTABLISHED;
            }
        }
    }

    if (is_tcp_fin_or_rst(tcp)) {
        bpf_map_delete_elem(&conntrack_map, &key_fwd);
        bpf_map_delete_elem(&conntrack_map, &key_rev);
    } else {
        state->packets++;
        state->bytes += skb->len;
        state->last_seen = now;
    }

    if (stats) {
        stats->pass_packets++;
    }

    return TC_ACT_OK;
}
