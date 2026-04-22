#ifndef CONNTRACK_H
#define CONNTRACK_H

#include <bpf/bpf_core_read.h>
#include "common_kern.h"


#define BPF_F_CURRENT_NETNS -1

/* Bitset representing status of connection. */
enum ip_conntrack_status {
	/* We've seen packets both ways */
	IPS_SEEN_REPLY_BIT = 1,
	IPS_SEEN_REPLY = (1 << IPS_SEEN_REPLY_BIT),
};

struct bpf_ct_opts {
	__s32 netns_id;
	__s32 error;
	__u8 l4proto;
	__u8 dir;
	__u8 reserved[2];
};

//struct nf_conn { };
struct nf_conn {
    unsigned long status;
} __attribute__((preserve_access_index));

struct nf_conn *bpf_xdp_ct_lookup(struct xdp_md *xdp_ctx, struct bpf_sock_tuple *bpf_tuple,
	__u32 tuple__sz, struct bpf_ct_opts *opts, __u32 opts__sz) __ksym;
struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *skb_ctx, struct bpf_sock_tuple *bpf_tuple,
	__u32 tuple__sz, struct bpf_ct_opts *opts, __u32 opts__sz) __ksym;

void bpf_ct_release(struct nf_conn *nfct) __ksym;


__always_inline static
bool conntrack_lookup_from_tuple(struct packet_data *pkt, struct bpf_sock_tuple *tuple,
                                 sa_family_t family, __u8 l4proto)
{
    __u32 tuple_size = family == AF_INET ? sizeof(tuple->ipv4) : sizeof(tuple->ipv6);
    struct bpf_ct_opts bpf_opts = {
        .netns_id = BPF_F_CURRENT_NETNS,
        .l4proto = l4proto,
    };
    unsigned long status;
    struct nf_conn *ct;
    bool seen_reply;

    ct = pkt->is_xdp ? bpf_xdp_ct_lookup(pkt->ctx, tuple, tuple_size, &bpf_opts, sizeof(bpf_opts)) :
        bpf_skb_ct_lookup(pkt->ctx, tuple, tuple_size, &bpf_opts, sizeof(bpf_opts));

    if (!ct) {
        bpf_printk("bpf_ct_lookup: %d", bpf_opts.error);
        return false;
    }

    status = BPF_CORE_READ(ct, status);
    seen_reply = status & IPS_SEEN_REPLY;

    bpf_ct_release(ct);
    return seen_reply;
}

__always_inline static
bool conntrack_lookup_from_header(struct packet_data *pkt, struct l3_header *l3, struct l4_header *l4)
{
    struct bpf_sock_tuple tuple;
    //__u32 tuple_size;

    switch (l3->family) {
        case AF_INET:
            tuple.ipv4.saddr = *l3->src_ip;
            tuple.ipv4.daddr = *l3->dest_ip;
            tuple.ipv4.sport =  l4->src_port;
            tuple.ipv4.dport =  l4->dest_port;
            //tuple_size = sizeof(tuple.ipv4);
            break;
        case AF_INET6:
            ip6cpy(tuple.ipv6.saddr, l3->src_ip);
            ip6cpy(tuple.ipv6.daddr, l3->dest_ip);
            tuple.ipv6.sport = l4->src_port;
            tuple.ipv6.dport = l4->dest_port;
            //tuple_size = sizeof(tuple.ipv6);
            break;
        default:
            return false;
    }

    return conntrack_lookup_from_tuple(pkt, &tuple, /*tuple_size*/ l3->family, l3->proto);
}


#endif
