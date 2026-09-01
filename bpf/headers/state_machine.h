#ifndef __STATE_MACHINE_H__
#define __STATE_MACHINE_H__

#include <linux/types.h>
#include <linux/tcp.h>

/* TCP State Definitions for Custom Conntrack */
#define TCP_STATE_NONE        0
#define TCP_STATE_SYN_SENT    1
#define TCP_STATE_SYN_RECV    2
#define TCP_STATE_ESTABLISHED 3
#define TCP_STATE_FIN_WAIT    4
#define TCP_STATE_CLOSED      5

/* Inline helpers to test TCP flags */
static __always_inline int is_tcp_syn(const struct tcphdr *tcp) {
    return tcp->syn && !tcp->ack;
}

static __always_inline int is_tcp_syn_ack(const struct tcphdr *tcp) {
    return tcp->syn && tcp->ack;
}

static __always_inline int is_tcp_fin_or_rst(const struct tcphdr *tcp) {
    return tcp->fin || tcp->rst;
}

#endif /* __STATE_MACHINE_H__ */
