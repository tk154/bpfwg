#ifndef TRANSMIT_H
#define TRANSMIT_H

#include <linux/bpf.h>
#include <linux/in.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include <sys/socket.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "dsa/dsa.h"


__u32 bpf_xdp_checksum(struct xdp_md *xdp, __u32 offset,
                       __u32 len, __u32 csum) __ksym;
__u32 bpf_skb_checksum(struct __sk_buff *skb, __u32 offset,
                       __u32 len, __u32 csum) __ksym;


__always_inline static
__u32 push_eth_header(struct ethhdr *ethh, struct packet_data *pkt, struct bpf_fib_lookup *fib)
{
    __push_eth_header(ethh, pkt, fib);
    return fib->ifindex;
}

__always_inline static
__u32 push_l2_header(void *l2, struct packet_data *pkt, struct bpf_fib_lookup *fib)
{
    switch (config.dsa_proto) {
        case DSA_PROTO_NONE:
            return push_eth_header(l2, pkt, fib);
        case DSA_PROTO_MTK:
            return push_mtk_header(l2, pkt, fib);
        default:
            return -1;
    }
}

__always_inline static
void restore_eth_header(struct packet_data *pkt, __u16 offset)
{
    memmove(pkt->data + offset, pkt->data, sizeof(struct ethhdr));
}

__always_inline static
void restore_l2_header(struct packet_data *pkt, __u16 offset)
{
    if (!pkt->is_xdp)
        return;

    switch (config.dsa_proto) {
        case DSA_PROTO_NONE:
            return restore_eth_header(pkt, offset);
        case DSA_PROTO_MTK:
            return restore_mtk_header(pkt, offset);
    }
}

__always_inline static
__sum16 ip_checksum(struct iphdr *iph)
{
    int i, num_u32 = sizeof(*iph) >> 2;
    __u32 *data = (__u32 *)iph;
    __u64 sum = 0;

    iph->check = 0;

    #pragma unroll
    for (i = 0; i < num_u32; i++)
        sum += data[i];

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = ~sum & 0xFFFF;

    return sum;
}

__always_inline static
__sum16 udp_checksum(struct packet_data *pkt, __u8 offset, __u16 len, __u64 sum)
{
    struct udphdr *udph;

    udph = pkt->data + offset;
    if ((void *)(udph + 1) > pkt->data_end)
        return 0;

    udph->check = 0;

    sum += IPPROTO_UDP << 8;
    sum += udph->len;

    sum = pkt->is_xdp ? bpf_xdp_checksum(pkt->ctx, offset, len, sum):
        bpf_skb_checksum(pkt->ctx, offset, len, sum);

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = ~sum & 0xFFFF;

    if (!sum)
        sum = 0xFFFF;

    return (__sum16)sum;
}

__always_inline static
__sum16 udp_v4_checksum(struct packet_data *pkt, __u8 offset, __u16 len, __be32 saddr, __be32 daddr)
{
    __u64 sum = 0;

    if (len > MAX_MTU - sizeof(struct iphdr))
        return 0;

    sum += saddr >> 16;
    sum += saddr & 0xFFFF;

    sum += daddr >> 16;
    sum += daddr & 0xFFFF;

    return udp_checksum(pkt, offset, len, sum);
}

__always_inline static
__sum16 udp_v6_checksum(struct packet_data *pkt, __u8 offset, __u16 len,
                        const struct in6_addr *saddr, const struct in6_addr *daddr)
{
    __u64 sum = 0;
    int i;

    if (len > MAX_MTU - sizeof(struct ipv6hdr))
        return 0;

    #pragma unroll
    for (i = 0; i < 4; i++) {
        sum += saddr->in6_u.u6_addr32[i] >> 16;
        sum += saddr->in6_u.u6_addr32[i] & 0xFFFF;
    }

    #pragma unroll
    for (i = 0; i < 4; i++) {
        sum += daddr->in6_u.u6_addr32[i] >> 16;
        sum += daddr->in6_u.u6_addr32[i] & 0xFFFF;
    }

    return udp_checksum(pkt, offset, len, sum);
}


__always_inline static
bool create_udp4_tunnel(struct packet_data *pkt, struct bpf_sock_tuple *tuple,
                        __u8 iph_offset, __u16 tot_len)
{
    struct iphdr *ip4h = pkt->data + iph_offset;
    __u16 udp_off = iph_offset + sizeof(*ip4h);
    struct udphdr *udph = pkt->data + udp_off;
    __u16 udp_len = tot_len - sizeof(*ip4h);

    if ((void *)(ip4h + 1) > pkt->data_end)
        return false;

    ip4h->version = 4;
    ip4h->ihl = sizeof(*ip4h) >> 2;
    ip4h->tos = 0;
    ip4h->tot_len = bpf_htons(tot_len);
    ip4h->id = 0;
    ip4h->frag_off = 0;
    ip4h->ttl = IPDEFTTL;
    ip4h->protocol = IPPROTO_UDP;
    ip4h->saddr = tuple->ipv4.saddr;
    ip4h->daddr = tuple->ipv4.daddr;
    ip4h->check = ip_checksum(ip4h);

    if ((void *)(udph + 1) > pkt->data_end)
        return false;

    udph->source = tuple->ipv4.sport;
    udph->dest = tuple->ipv4.dport;
    udph->len = bpf_htons(udp_len);

    if (!config.udp_nocheck) {
        udph->check = udp_v4_checksum(pkt, iph_offset + sizeof(*ip4h), udp_len,
                                ip4h->saddr, ip4h->daddr);
        if (!udph->check) {
            bpf_printk("udp_v4_checksum error");
            return false;
        }
    }

    return true;
}

__always_inline static
bool create_udp6_tunnel(struct packet_data *pkt, struct bpf_sock_tuple *tuple, __u8 iph_offset, __u16 tot_len)
{
    struct ipv6hdr *ip6h = pkt->data + iph_offset;
    __u16 udp_off = iph_offset + sizeof(*ip6h);
    struct udphdr *udph = pkt->data + udp_off;
    __u16 udp_len = tot_len - sizeof(*ip6h);
    __be16 payload_len = bpf_htons(udp_len);

    if ((void *)(ip6h + 1) > pkt->data_end)
        return false;

    ip6h->version = 6;
    ip6h->priority = 0;
    memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
    ip6h->payload_len = payload_len;
    ip6h->nexthdr = IPPROTO_UDP;
    ip6h->hop_limit = IPDEFTTL;
    ip6cpy(ip6h->saddr.in6_u.u6_addr32, tuple->ipv6.saddr);
    ip6cpy(ip6h->daddr.in6_u.u6_addr32, tuple->ipv6.daddr);

    if ((void *)(udph + 1) > pkt->data_end)
        return false;

    udph->source = tuple->ipv6.sport;
    udph->dest = tuple->ipv6.dport;
    udph->len = payload_len;

    udph->check = udp_v6_checksum(pkt, iph_offset + sizeof(*ip6h), udp_len,
                            &ip6h->saddr, &ip6h->daddr);
    if (!udph->check) {
        bpf_printk("udp_v6_checksum error");
        return false;
    }

    return true;
}

__always_inline static
bool create_udp_tunnel(struct packet_data *pkt, sa_family_t family,
                struct bpf_sock_tuple *tuple, __u8 iph_offset, __u16 tot_len)
{
    return family == AF_INET ? create_udp4_tunnel(pkt, tuple, iph_offset, tot_len):
                               create_udp6_tunnel(pkt, tuple, iph_offset, tot_len);
}


__always_inline static
int output(struct packet_data *pkt, sa_family_t family, __u16 offset, __u16 eth_len)
{
    void *ethh = pkt->data + offset;
    struct bpf_fib_lookup fib = {};
    long ret;

    fib.ifindex = pkt->ifindex;
    fib.family = family;

    if (family == AF_INET) {
        struct iphdr *ip4h = (struct iphdr *)(ethh + eth_len);
        if ((void *)(ip4h + 1) > pkt->data_end)
            return -1;

        fib.ipv4_src = ip4h->saddr;
        fib.ipv4_dst = ip4h->daddr;

        //ethh->h_proto = bpf_htons(ETH_P_IP);
    }
    else {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(ethh + eth_len);
        if ((void *)(ip6h + 1) > pkt->data_end)
            return -1;

        ip6cpy(fib.ipv6_src, ip6h->saddr.in6_u.u6_addr32);
        ip6cpy(fib.ipv6_dst, ip6h->daddr.in6_u.u6_addr32);

        //ethh->h_proto = bpf_htons(ETH_P_IPV6);
    }

    ret = bpf_fib_lookup(pkt->ctx, &fib, sizeof(fib), 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
        if (ret != BPF_FIB_LKUP_RET_NOT_FWDED)
            bpf_printk("%s: bpf_fib_lookup: %d", __func__, ret);

        /*if (offset)
            memmove(pkt->data + offset, pkt->data, 2 * ETH_ALEN);*/

        return 0;
    }

    return push_l2_header(pkt->is_xdp ? ethh : pkt->data, pkt, &fib);
}


#endif
