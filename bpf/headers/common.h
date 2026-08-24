#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/types.h>

/* Verdict Codes */
#define VERDICT_PASS     0
#define VERDICT_DROP     1
#define VERDICT_REDIRECT 2

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

/* IPv4 LPM Trie Key Structure */
struct lpm_key_ipv4 {
    __u32 prefixlen; /* Prefix length in bits (0..32) */
    __u32 addr;      /* IPv4 address in network byte order */
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

#endif /* __COMMON_H__ */
