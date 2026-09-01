#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/types.h>

/* Verdict Codes */
#define VERDICT_PASS     0
#define VERDICT_DROP     1
#define VERDICT_REDIRECT 2

/* Action Codes */
#define ACTION_ALLOW     1
#define ACTION_DENY      2

/* Reason Codes for Explainability */
#define REASON_OK                   0
#define REASON_CIDR_BLOCKED         1
#define REASON_PORT_BLOCKED         2
#define REASON_INVALID_TCP_FLAGS    3
#define REASON_IDENTITY_DENY        4
#define REASON_UNTRACKED_NON_SYN    5
#define REASON_DEFAULT_DROP         6

/* Network Protocol Identifiers */
#define PROTO_ICMP 1
#define PROTO_TCP  6
#define PROTO_UDP  17

/* Generation-aware IPv4 LPM Trie Key Structure */
struct lpm_key_ipv4 {
    __u32 prefixlen; /* Prefix length in bits (32 for gen + 0..32 for IPv4) */
    __u32 gen;       /* Generation index */
    __u32 addr;      /* IPv4 address in network byte order */
};

/* Generation-aware Cgroup Key Structure */
struct cgroup_key {
    __u32 gen;       /* Generation index */
    __u32 pad;       /* Alignment padding */
    __u64 cgroup_id; /* 64-bit cgroup v2 ID */
};

/* Generation-aware Port/Protocol Rule Key Structure */
struct port_rule_key {
    __u32 gen;       /* Generation index */
    __u16 dst_port;  /* Destination port */
    __u8  protocol;  /* IP protocol (TCP, UDP, etc.) */
    __u8  pad;       /* Alignment padding */
};

/* Port/Protocol Rule Value Structure */
struct port_rule_val {
    __u32 action;    /* ACTION_ALLOW or ACTION_DENY */
    __u32 rule_id;   /* Matched rule identifier */
};

/* 5-Tuple Flow Key for Conntrack */
struct flow_key {
    __u32 src_ip;    /* Source IPv4 address (network byte order) */
    __u32 dst_ip;    /* Destination IPv4 address (network byte order) */
    __u16 src_port;  /* Source port (network byte order) */
    __u16 dst_port;  /* Destination port (network byte order) */
    __u8  protocol;  /* IP protocol (TCP, UDP, ICMP) */
    __u8  pad[3];    /* Explicit alignment padding */
};

/* Conntrack Entry Value */
struct flow_state {
    __u32 state;        /* TCP state (e.g. ESTABLISHED, SYN_SENT) */
    __u64 packets;      /* Total packets observed for flow */
    __u64 bytes;        /* Total bytes observed for flow */
    __u64 last_seen;    /* Kernel timestamp (bpf_ktime_get_ns) */
    __u32 flags;        /* Flow flags */
    __u32 pad;          /* Explicit alignment padding */
};

/* Audit Event emitted over BPF_MAP_TYPE_RINGBUF to Userspace */
struct audit_event {
    __u64 timestamp_ns;  /* Kernel timestamp */
    __u32 src_ip;        /* Source IPv4 address */
    __u32 dst_ip;        /* Destination IPv4 address */
    __u16 src_port;      /* Source port */
    __u16 dst_port;      /* Destination port */
    __u8  protocol;      /* IP protocol */
    __u8  verdict;       /* VERDICT_PASS / VERDICT_DROP */
    __u16 reason_code;   /* Explainability reason code */
    __u32 rule_id;       /* Matched rule identifier */
    __u64 cgroup_id;     /* Source Cgroup v2 numeric ID */
    __u32 identity_id;   /* Resolved security identity ID */
    __u32 pad;           /* Alignment padding */
};

/* Per-CPU Statistics Counter Value */
struct stats_value {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 pass_packets;
    __u64 drop_packets;
};

/* Socket 4-tuple key for SOCKHASH map (used by sockops + sk_msg).
 * Ports are __u32 to match bpf_sock_ops->local_port / remote_port widths.
 * Using __u16 would introduce padding mismatches between sockops and sk_msg
 * key construction, silently breaking SOCKHASH lookups. */
struct sock_key {
    __u32 sip;    /* Source IPv4 address (network byte order) */
    __u32 dip;    /* Destination IPv4 address (network byte order) */
    __u32 sport;  /* Source port (host byte order) */
    __u32 dport;  /* Destination port (host byte order) */
};

/* Reason code for sockops redirect events */
#define REASON_SOCKOPS_REDIRECT  7

#endif /* __COMMON_H__ */
