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
__sum16 udp_checksum(struct udphdr *udph, int len, __u64 sum, void *data_end)
{
    void *data = (void *)udph;
    barrier_var(data_end);
    int i = 0;

    udph->check = 0;

    sum += IPPROTO_UDP << 8;
    sum += udph->len;

    while (len >= 4) {
        __u32 *p = data + i;

        if ((void *)(p + 1) > data_end)
            return 0;

        sum += *p;
        len -= 4;
        i += 4;
    }

    if (len)
        bpf_printk("BUG: len = %u", bpf_ntohs(udph->len));

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = ~sum & 0xFFFF;

    return sum ? sum : 0xFFFF;
}

__always_inline static
__sum16 udp_v4_checksum(struct udphdr *udph, __be32 saddr, __be32 daddr, void *data_end)
{
    int len = bpf_ntohs(udph->len);
    __u64 sum = 0;

    if (len > MAX_MTU - sizeof(struct iphdr))
        return 0;

    sum += saddr >> 16;
    sum += saddr & 0xFFFF;

    sum += daddr >> 16;
    sum += daddr & 0xFFFF;

    return udp_checksum(udph, len, sum, data_end);
}

__always_inline static
__sum16 udp_v6_checksum(struct udphdr *udph, const struct in6_addr *saddr,
                        const struct in6_addr *daddr, void *data_end)
{
    int i, len = bpf_ntohs(udph->len);
    __u64 sum = 0;

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

    return udp_checksum(udph, len, sum, data_end);
}


__always_inline static
bool create_udp4_tunnel(void *data, void *data_end, struct bpf_sock_tuple *tuple,
                        __u16 tot_len, bool udp_check)
{
    struct iphdr *ip4h = data;
    struct udphdr *udph;

    udph = (struct udphdr *)(ip4h + 1);
    if ((void *)(udph + 1) > data_end)
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

    udph->source = tuple->ipv4.sport;
    udph->dest = tuple->ipv4.dport;
    udph->len = bpf_htons(tot_len - sizeof(*ip4h));

    if (udp_check) {
        udph->check = udp_v4_checksum(udph, ip4h->saddr, ip4h->daddr, data_end);
        if (!udph->check) {
            bpf_printk("udp_v4_checksum error");
            return false;
        }
    }
    else
        udph->check = 0;

    return true;
}

__always_inline static
bool create_udp6_tunnel(void *data, void *data_end,
                        struct bpf_sock_tuple *tuple, __u16 tot_len)
{
    struct ipv6hdr *ip6h = data;
    struct udphdr *udph;
    __be16 payload_len;

    udph = (struct udphdr *)(ip6h + 1);
    if ((void *)(udph + 1) > data_end)
        return false;

    payload_len = bpf_htons(tot_len - sizeof(*ip6h));

    ip6h->version = 6;
    ip6h->priority = 0;
    memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
    ip6h->payload_len = payload_len;
    ip6h->nexthdr = IPPROTO_UDP;
    ip6h->hop_limit = IPDEFTTL;
    ip6cpy(ip6h->saddr.in6_u.u6_addr32, tuple->ipv6.saddr);
    ip6cpy(ip6h->daddr.in6_u.u6_addr32, tuple->ipv6.daddr);

    udph->source = tuple->ipv6.sport;
    udph->dest = tuple->ipv6.dport;
    udph->len = payload_len;
    udph->check = udp_v6_checksum(udph, &ip6h->saddr, &ip6h->daddr, data_end);

    if (!udph->check) {
        bpf_printk("udp_v6_checksum error");
        return false;
    }

    return true;
}

__always_inline static
bool create_udp_tunnel(void *data, void *data_end, sa_family_t family,
                       struct bpf_sock_tuple *tuple, __u16 tot_len, bool udp_check)
{
    return family == AF_INET ? create_udp4_tunnel(data, data_end, tuple, tot_len, udp_check):
                               create_udp6_tunnel(data, data_end, tuple, tot_len);
}


__always_inline static
__u32 output(struct packet_data *pkt, sa_family_t family, __u16 offset)
{
    struct ethhdr *ethh = pkt->data + offset;
    struct bpf_fib_lookup fib = {};
    long ret;

    fib.ifindex = pkt->ifindex;
    fib.family = family;

    if (family == AF_INET) {
        struct iphdr *ip4h = (struct iphdr *)(ethh + 1);
        if ((void *)(ip4h + 1) > pkt->data_end)
            return 0;

        fib.ipv4_src = ip4h->saddr;
        fib.ipv4_dst = ip4h->daddr;

        ethh->h_proto = bpf_htons(ETH_P_IP);
    }
    else {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(ethh + 1);
        if ((void *)(ip6h + 1) > pkt->data_end)
            return 0;

        ip6cpy(fib.ipv6_src, ip6h->saddr.in6_u.u6_addr32);
        ip6cpy(fib.ipv6_dst, ip6h->daddr.in6_u.u6_addr32);

        ethh->h_proto = bpf_htons(ETH_P_IPV6);
    }

    ret = bpf_fib_lookup(pkt->ctx, &fib, sizeof(fib), 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
        if (ret != BPF_FIB_LKUP_RET_NOT_FWDED)
            bpf_printk("bpf_fib_lookup: %d", ret);

        if (offset)
            memmove(pkt->data + offset, pkt->data, 2 * ETH_ALEN);

        return 0;
    }

    memcpy(ethh->h_dest, fib.dmac, ETH_ALEN);
    memcpy(ethh->h_source, fib.smac, ETH_ALEN);

    return fib.ifindex;
}


#endif
