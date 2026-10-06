#ifndef CONNTRACK_H
#define CONNTRACK_H

#include "common_kern.h"
#include <bits/sockaddr.h>
#include <bpf/bpf_helpers.h>
#include <sys/socket.h>

#include <linux/netfilter/nf_conntrack_tcp.h>


SEC(BPFWG_CT_SECTION)
struct bpfwg_ct ct_config = {
    .timeout_tcp = 0,
    .timeout_udp = 0
};

/* Bitset representing status of connection. */
enum ip_conntrack_status {
	IPS_ASSURED_BIT = 2,
	IPS_ASSURED = (1 << IPS_ASSURED_BIT),

	IPS_CONFIRMED_BIT = 3,
	IPS_CONFIRMED = (1 << IPS_CONFIRMED_BIT),

	IPS_SRC_NAT_BIT = 4,
	IPS_SRC_NAT = (1 << IPS_SRC_NAT_BIT),

	IPS_DST_NAT_BIT = 5,
	IPS_DST_NAT = (1 << IPS_DST_NAT_BIT),

	IPS_NAT_MASK = (IPS_DST_NAT | IPS_SRC_NAT),

	IPS_SEQ_ADJUST_BIT = 6,
	IPS_SEQ_ADJUST = (1 << IPS_SEQ_ADJUST_BIT),

	IPS_UNTRACKED_BIT = 12,
	IPS_UNTRACKED = (1 << IPS_UNTRACKED_BIT),

	IPS_NAT_CLASH_BIT = IPS_UNTRACKED_BIT,
	IPS_NAT_CLASH = IPS_UNTRACKED,

	IPS_HELPER_BIT = 13,
	IPS_HELPER = (1 << IPS_HELPER_BIT),

	IPS_OFFLOAD_BIT = 14,
	IPS_OFFLOAD = (1 << IPS_OFFLOAD_BIT),

	IPS_HW_OFFLOAD_BIT = 15,
	IPS_HW_OFFLOAD = (1 << IPS_HW_OFFLOAD_BIT),
};

enum ip_conntrack_dir {
	IP_CT_DIR_ORIGINAL,
	IP_CT_DIR_REPLY
};

enum nf_ct_ext_id {
	NF_CT_EXT_HELPER = 0,
};

struct bpf_ct_opts {
	__s32 netns_id;
	__s32 error;
	__u8 l4proto;
	__u8 dir;
	__u8 reserved[2];
};

struct nf_conntrack_man {
    union {
        __be32 all[4];
    } u3;
    union {
        __be16 all;
    } u;
} __attribute__((preserve_access_index));

struct nf_conntrack_tuple {
    struct nf_conntrack_man src;
    struct {
        union {
            __be32 all[4];
        } u3;
        union {
            __be16 all;
        } u;
        __u8 protonum;
        __u8 dir;
    } dst;
} __attribute__((preserve_access_index));

struct nf_conntrack_tuple_hash {
    struct nf_conntrack_tuple tuple;
} __attribute__((preserve_access_index));

struct nf_ct_ext {
	__u8 offset[0];
} __attribute__((preserve_access_index));

struct ip_ct_tcp {
	__u8 state;
} __attribute__((preserve_access_index));

union nf_conntrack_proto {
	struct ip_ct_tcp tcp;
} __attribute__((preserve_access_index));

struct nf_conn {
    unsigned long status;
    struct nf_conntrack_tuple_hash tuplehash[2];
    struct nf_ct_ext *ext;
    union nf_conntrack_proto proto;
} __attribute__((preserve_access_index));

struct nf_conn *bpf_xdp_ct_lookup(struct xdp_md *xdp_ctx, struct bpf_sock_tuple *bpf_tuple,
	__u32 tuple__sz, struct bpf_ct_opts *opts, __u32 opts__sz) __ksym;
struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *skb_ctx, struct bpf_sock_tuple *bpf_tuple,
	__u32 tuple__sz, struct bpf_ct_opts *opts, __u32 opts__sz) __ksym;

int bpf_ct_change_timeout(struct nf_conn *nfct, __u32 timeout) __ksym;
void bpf_ct_release(struct nf_conn *nfct) __ksym;


__always_inline static
__sum16 csum_add(__sum16 csum, const __be16 *add, size_t len)
{
	__u16 res = (__u16)csum;
    int i;

    #pragma unroll
	for (i = 0; i < len; i++) {
		res += (__u16)add[i];
		res += res < (__u16)add[i];
	}

	return (__sum16)res;
}

__always_inline static
__sum16 csum_sub(__sum16 csum, const __be16 *sub, size_t len)
{
	__be16 sub_neg[len];
    int i;

    #pragma unroll
	for (i = 0; i < len; i++)
		sub_neg[i] = ~sub[i];

	return csum_add(csum, sub_neg, len);
}

__always_inline static
void csum_replace(__sum16 *csum, const __be16 *old, const __be16 *new, size_t len)
{
    csum && (*csum = ~csum_add(csum_sub(~(*csum), old, len), new, len));
}

__always_inline static
bool nf_ct_ext_exist(const struct nf_conn *ct, __u8 id)
{
    return ct->ext && ct->ext->offset[id];
}

__always_inline static
bool nf_conntrack_tcp_established(const struct nf_conn *ct)
{
	return ct->proto.tcp.state == TCP_CONNTRACK_ESTABLISHED && ct->status & IPS_ASSURED;
}

__always_inline static
bool update_timeout(struct nf_conn *ct, __u8 l4proto)
{
    __u32 timeout;
    int ret;

    timeout = l4proto == IPPROTO_TCP ?
        ct_config.timeout_tcp : ct_config.timeout_udp;
    ret = bpf_ct_change_timeout(ct, timeout);

    if (ret) {
        bpf_printk("bpf_ct_change_timeout: %d", ret);
        return false;
    }

    return true;
}

__always_inline static
void apply_nat(struct nf_conn *ct, __u8 dir, sa_family_t family,
               __be32 *saddr, __be32 *daddr, __be16 *sport, __be16 *dport,
               __sum16 *l3_check, __sum16 *l4_check)
{
    struct nf_conntrack_tuple *tuple;
    bool apply_src, apply_dst;

    if (!(ct->status & IPS_NAT_MASK))
        return;

    apply_src = (dir == IP_CT_DIR_ORIGINAL && (ct->status & IPS_SRC_NAT)) ||
                (dir == IP_CT_DIR_REPLY    && (ct->status & IPS_DST_NAT));
    apply_dst = (dir == IP_CT_DIR_ORIGINAL && (ct->status & IPS_DST_NAT)) ||
                (dir == IP_CT_DIR_REPLY    && (ct->status & IPS_SRC_NAT));

    tuple = dir == IP_CT_DIR_ORIGINAL ? &ct->tuplehash[IP_CT_DIR_REPLY].tuple :
                                        &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

    if (apply_src) {
        if (family == AF_INET) {
            csum_replace(l3_check, (const __be16 *)saddr, (const __be16 *)&tuple->dst.u3.all[0], 2);
            csum_replace(l4_check, (const __be16 *)saddr, (const __be16 *)&tuple->dst.u3.all[0], 2);
            *saddr = tuple->dst.u3.all[0];
        } else {
            csum_replace(l4_check, (const __be16 *)saddr, (const __be16 *)tuple->dst.u3.all, 8);
            ip6cpy(saddr, tuple->dst.u3.all);
        }

        csum_replace(l4_check, sport, &tuple->dst.u.all, 1);
        *sport = tuple->dst.u.all;
    }

    if (apply_dst) {
        if (family == AF_INET) {
            csum_replace(l3_check, (const __be16 *)daddr, (const __be16 *)&tuple->src.u3.all[0], 2);
            csum_replace(l4_check, (const __be16 *)daddr, (const __be16 *)&tuple->src.u3.all[0], 2);
            *daddr = tuple->src.u3.all[0];
        } else {
            csum_replace(l4_check, (const __be16 *)daddr, (const __be16 *)tuple->src.u3.all, 8);
            ip6cpy(daddr, tuple->src.u3.all);
        }

        csum_replace(l4_check, dport, &tuple->src.u.all, 1);
        *dport = tuple->src.u.all;
    }
}

__always_inline static
struct nf_conn *conntrack_lookup(struct packet_data *pkt, struct bpf_sock_tuple *tuple,
                                 __u32 tuple_size, __u8 l4proto, __u8 *dir)
{
    struct bpf_ct_opts bpf_opts = {
        .netns_id = BPF_F_CURRENT_NETNS,
        .l4proto = l4proto,
    };
    struct nf_conn *ct;

    ct = pkt->is_xdp ? bpf_xdp_ct_lookup(pkt->ctx, tuple, tuple_size, &bpf_opts, sizeof(bpf_opts)) :
        bpf_skb_ct_lookup(pkt->ctx, tuple, tuple_size, &bpf_opts, sizeof(bpf_opts));

    if (!ct) {
        bpf_printk("bpf_ct_lookup: %d", bpf_opts.error);
        return NULL;
    }

    if (ct->status & (IPS_OFFLOAD | IPS_HW_OFFLOAD))
        goto update_timeout;

    if (l4proto == IPPROTO_TCP && !nf_conntrack_tcp_established(ct))
        goto bpf_ct_release;

    if (nf_ct_ext_exist(ct, NF_CT_EXT_HELPER) ||
            ct->status & (IPS_SEQ_ADJUST | IPS_NAT_CLASH))
        goto bpf_ct_release;

    if (!(ct->status & IPS_CONFIRMED))
        goto bpf_ct_release;

update_timeout:
    update_timeout(ct, l4proto);
    *dir = bpf_opts.dir;
    return ct;

bpf_ct_release:
    bpf_ct_release(ct);
    return NULL;
}

__always_inline static
bool conntrack_lookup_from_tuple(struct packet_data *pkt, struct bpf_sock_tuple *tuple,
                                 __u32 tuple_size, __u8 l4proto)
{
    __be16 *sport, *dport;
    void *saddr, *daddr;
    struct nf_conn *ct;
    sa_family_t family;
    __u8 dir;

    ct = conntrack_lookup(pkt, tuple, tuple_size, l4proto, &dir);
    if (!ct)
        return false;

    if (tuple_size == sizeof(tuple->ipv4)) {
        saddr = &tuple->ipv4.saddr;
        daddr = &tuple->ipv4.daddr;
        sport = &tuple->ipv4.sport;
        dport = &tuple->ipv4.dport;
        family = AF_INET;
    } else {
        saddr = &tuple->ipv6.saddr;
        daddr = &tuple->ipv6.daddr;
        sport = &tuple->ipv6.sport;
        dport = &tuple->ipv6.dport;
        family = AF_INET6;
    }

    apply_nat(ct, dir, family, saddr, daddr, sport, dport, NULL, NULL);
    bpf_ct_release(ct);

    return true;
}

__always_inline static
bool conntrack_lookup_from_header(struct packet_data *pkt, struct l3_header *l3, struct l4_header *l4)
{
    struct bpf_sock_tuple tuple;
    struct nf_conn *ct;
    __u32 tuple_size;
    __u8 dir;

    if (l3->family == AF_INET) {
        tuple.ipv4.saddr = *l3->src_ip;
        tuple.ipv4.daddr = *l3->dest_ip;
        tuple.ipv4.sport = *l4->src_port;
        tuple.ipv4.dport = *l4->dest_port;
        tuple_size = sizeof(tuple.ipv4);
    } else {
        ip6cpy(tuple.ipv6.saddr, l3->src_ip);
        ip6cpy(tuple.ipv6.daddr, l3->dest_ip);
        tuple.ipv6.sport = *l4->src_port;
        tuple.ipv6.dport = *l4->dest_port;
        tuple_size = sizeof(tuple.ipv6);
    }

    ct = conntrack_lookup(pkt, &tuple, tuple_size, l3->proto, &dir);
    if (!ct)
        return false;

    apply_nat(ct, dir, l3->family, l3->src_ip, l3->dest_ip,
        l4->src_port, l4->dest_port, l3->check, l4->check);
    bpf_ct_release(ct);

    return true;
}


#endif
