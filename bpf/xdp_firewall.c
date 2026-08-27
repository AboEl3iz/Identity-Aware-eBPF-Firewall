// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "headers/bpf_endian.h"
#include "headers/common.h"
#include "headers/maps.h"

char __license[] SEC("license") = "GPL";

/* 1-element array map holding active policy generation index */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} active_generation_map SEC(".maps");

/* LPM Trie blocklist map for IPv4 CIDRs (generation-aware) */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct lpm_key_ipv4);
    __type(value, __u32); /* Value stores rule_id */
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_blocklist SEC(".maps");

/* Cgroup v2 Identity Map (generation-aware) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct cgroup_key);
    __type(value, __u32); /* Security identity ID or Rule ID */
} cgroup_identity_map SEC(".maps");

/* Port & Protocol Rules Map (generation-aware) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct port_rule_key);
    __type(value, struct port_rule_val);
} port_rules_map SEC(".maps");

/* Per-CPU Array for statistics counters */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_value);
} xdp_stats_map SEC(".maps");

/* Ring buffer map for emitting verdict events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB ring buffer */
} audit_ringbuf SEC(".maps");

SEC("xdp")
int xdp_firewall_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 zero = 0;
    struct stats_value *stats = bpf_map_lookup_elem(&xdp_stats_map, &zero);
    if (stats) {
        stats->rx_packets++;
        stats->rx_bytes += ((void *)data_end - (void *)data);
    }

    /* Query active policy generation */
    __u32 active_gen = 0;
    __u32 *gen_ptr = bpf_map_lookup_elem(&active_generation_map, &zero);
    if (gen_ptr) {
        active_gen = *gen_ptr;
    }

    /* Extract L4 Ports for TCP/UDP */
    __u16 src_port = 0;
    __u16 dst_port = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(iph + 1);
        if ((void *)(tcp + 1) <= data_end) {
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(iph + 1);
        if ((void *)(udp + 1) <= data_end) {
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);
        }
    }

    __u64 cgroup_id = bpf_get_current_cgroup_id();

    /* 1. Check Cgroup v2 Identity Map (generation-aware) */
    if (cgroup_id > 0) {
        struct cgroup_key cg_key = {
            .gen = active_gen,
            .pad = 0,
            .cgroup_id = cgroup_id,
        };
        __u32 *identity_rule_id = bpf_map_lookup_elem(&cgroup_identity_map, &cg_key);
        if (identity_rule_id) {
            if (stats) {
                stats->drop_packets++;
            }

            struct audit_event *event = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*event), 0);
            if (event) {
                event->timestamp_ns = bpf_ktime_get_ns();
                event->src_ip = iph->saddr;
                event->dst_ip = iph->daddr;
                event->src_port = src_port;
                event->dst_port = dst_port;
                event->protocol = iph->protocol;
                event->verdict = VERDICT_DROP;
                event->reason_code = REASON_IDENTITY_DENY;
                event->rule_id = *identity_rule_id;
                event->cgroup_id = cgroup_id;
                event->identity_id = *identity_rule_id;
                event->pad = 0;
                bpf_ringbuf_submit(event, 0);
            }

            return XDP_DROP;
        }
    }

    /* 2. Check IPv4 LPM Blocklist Trie (generation-aware) */
    struct lpm_key_ipv4 lpm_key = {
        .prefixlen = 64, /* 32 bits gen + 32 bits IPv4 address */
        .gen = active_gen,
        .addr = iph->saddr,
    };

    __u32 *rule_id = bpf_map_lookup_elem(&lpm_blocklist, &lpm_key);
    if (rule_id) {
        if (stats) {
            stats->drop_packets++;
        }

        struct audit_event *event = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*event), 0);
        if (event) {
            event->timestamp_ns = bpf_ktime_get_ns();
            event->src_ip = iph->saddr;
            event->dst_ip = iph->daddr;
            event->src_port = src_port;
            event->dst_port = dst_port;
            event->protocol = iph->protocol;
            event->verdict = VERDICT_DROP;
            event->reason_code = REASON_CIDR_BLOCKED;
            event->rule_id = *rule_id;
            event->cgroup_id = cgroup_id;
            event->identity_id = 0;
            event->pad = 0;
            bpf_ringbuf_submit(event, 0);
        }

        return XDP_DROP;
    }

    /* 3. Check Port & Protocol Rules Map (generation-aware) */
    if (dst_port > 0) {
        struct port_rule_key pr_key = {
            .gen = active_gen,
            .dst_port = dst_port,
            .protocol = iph->protocol,
            .pad = 0,
        };

        struct port_rule_val *pr_val = bpf_map_lookup_elem(&port_rules_map, &pr_key);
        if (pr_val) {
            if (pr_val->action == ACTION_DENY) {
                if (stats) {
                    stats->drop_packets++;
                }

                struct audit_event *event = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*event), 0);
                if (event) {
                    event->timestamp_ns = bpf_ktime_get_ns();
                    event->src_ip = iph->saddr;
                    event->dst_ip = iph->daddr;
                    event->src_port = src_port;
                    event->dst_port = dst_port;
                    event->protocol = iph->protocol;
                    event->verdict = VERDICT_DROP;
                    event->reason_code = REASON_PORT_BLOCKED;
                    event->rule_id = pr_val->rule_id;
                    event->cgroup_id = cgroup_id;
                    event->identity_id = 0;
                    event->pad = 0;
                    bpf_ringbuf_submit(event, 0);
                }

                return XDP_DROP;
            } else if (pr_val->action == ACTION_ALLOW) {
                if (stats) {
                    stats->pass_packets++;
                }

                struct audit_event *event = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*event), 0);
                if (event) {
                    event->timestamp_ns = bpf_ktime_get_ns();
                    event->src_ip = iph->saddr;
                    event->dst_ip = iph->daddr;
                    event->src_port = src_port;
                    event->dst_port = dst_port;
                    event->protocol = iph->protocol;
                    event->verdict = VERDICT_PASS;
                    event->reason_code = REASON_OK;
                    event->rule_id = pr_val->rule_id;
                    event->cgroup_id = cgroup_id;
                    event->identity_id = 0;
                    event->pad = 0;
                    bpf_ringbuf_submit(event, 0);
                }

                return XDP_PASS;
            }
        }
    }

    if (stats) {
        stats->pass_packets++;
    }

    return XDP_PASS;
}

