#ifndef COMMON_KERN_H
#define COMMON_KERN_H

#include <bits/sockaddr.h>
#include <stdbool.h>
#include <string.h>

#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <sys/socket.h>

#include "../common.h"

#define MAX_MTU 9000

// Helper macro to make the out-of-bounds check on a packet header
#define parse_header(hdr, pkt) \
    do { \
        hdr = pkt->p; \
        pkt->p += sizeof(*hdr); \
        if (pkt->p > pkt->data_end) { \
            bpf_printk("%s: "#hdr" > data_end", __func__); \
            return false; \
        } \
    } while (0);

#define __parse_eth_header(hdr, pkt, l2) \
    do { \
        parse_header(hdr, pkt) \
        l2->proto = hdr->h_proto; \
    } while (0);

#define __push_eth_header(eth, pkt, fib) \
    do { \
        /* Force the compiler to not optimize out of bounds check */ \
        asm volatile("" : "+r"(eth)); \
        if ((void *)(eth + 1) > pkt->data_end) \
            return -1; \
        memcpy(eth->h_dest, fib->dmac, ETH_ALEN); \
        memcpy(eth->h_source, fib->smac, ETH_ALEN); \
        eth->h_proto = fib->family == AF_INET ? \
            bpf_htons(ETH_P_IP) : bpf_htons(ETH_P_IPV6); \
    } while (0);


struct packet_data {
    void *ctx;

    void *data;
    void *data_end;
    void *p;

    __u32 ifindex;
    bool is_xdp;
};

struct l2_header {
    __be16 proto;
};

struct l3_header {
    __be32 *src_ip, *dest_ip;
    __sum16 *check;
    sa_family_t family;
    __u16 tot_len;
    __u8 proto, offset, hdr_len;
};

struct l4_header {
    __be16 *src_port, *dest_port;
    __sum16 *check;
    __u16 payload_len;
};

struct wg_header {
    __le32 type;
    __le32 key_idx;
    __le64 counter;
};

struct packet_header {
    struct l2_header  l2;
    struct l3_header  l3;
    struct l4_header  l4;
    struct wg_header *wg;
};


int bpf_dynptr_from_xdp(struct xdp_md *xdp, __u64 flags, struct bpf_dynptr *ptr) __ksym;
int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags, struct bpf_dynptr *ptr) __ksym;
int bpf_dynptr_adjust(const struct bpf_dynptr *p, __u64 start, __u64 end) __ksym;

__always_inline static
bool bpf_dynptr_from_packet(struct bpf_dynptr *ptr, struct packet_data *pkt,
                            __u32 offset, __u32 length)
{
    int ret;

    ret = pkt->is_xdp ? bpf_dynptr_from_xdp(pkt->ctx, 0, ptr):
        bpf_dynptr_from_skb(pkt->ctx, 0, ptr);

    if (ret) {
        bpf_printk("bpf_dynptr_from_xdp/sbk: %d", ret);
        return false;
    }

    ret = bpf_dynptr_adjust(ptr, offset, offset + length);
    if (ret) {
        bpf_printk("bpf_dynptr_adjust: %d", ret);
        return false;
    }

    return true;
}

__always_inline static
bool bpf_skb_linearize(struct packet_data *pkt, __u16 offset)
{
    struct __sk_buff *skb = (struct __sk_buff *)pkt->ctx;
    int ret;

    ret = bpf_skb_pull_data(skb, skb->len);
    if (ret) {
        bpf_printk("bpf_skb_pull_data: %d", ret);
        return false;
    }

    pkt->data = (void *)(long)skb->data;
    pkt->data_end = (void *)(long)skb->data_end;
    pkt->p = pkt->data + offset;
    return true;
}


__always_inline static
bool bpf_xdp_adjust_packet(struct packet_data *pkt, int head, int tail)
{
    struct xdp_md *xdp = (struct xdp_md *)pkt->ctx;
    long ret;

    ret = bpf_xdp_adjust_head(xdp, head);
    if (ret) {
        bpf_printk("bpf_xdp_adjust_head: %d", ret);
        return false;
    }

    ret = bpf_xdp_adjust_tail(xdp, tail);
    if (ret) {
        bpf_printk("bpf_xdp_adjust_tail: %d", ret);
        return false;
    }

    pkt->data = (void *)(long)xdp->data;
    pkt->data_end = (void *)(long)xdp->data_end;

    return true;
}

__always_inline static
bool bpf_skb_adjust_packet(struct packet_data *pkt, __s32 head, __s32 tail, sa_family_t family)
{
    struct __sk_buff *skb = (struct __sk_buff *)pkt->ctx;
    __u64 flags;
    long ret;

    if (head > 0) {
        flags = family == AF_INET ? BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 : BPF_F_ADJ_ROOM_ENCAP_L3_IPV6;
        flags |= BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
    }
    else {
        flags = family == AF_INET ? BPF_F_ADJ_ROOM_DECAP_L3_IPV4 : BPF_F_ADJ_ROOM_DECAP_L3_IPV6;
    }

    if (tail > 0 || (skb->data_end - skb->data) == skb->len) {
        ret = bpf_skb_change_tail(skb, skb->len + tail, 0);
        if (ret) {
            bpf_printk("bpf_skb_change_tail: %d", ret);
            return false;
        }
    }

    ret = bpf_skb_adjust_room(skb, head, BPF_ADJ_ROOM_MAC, flags /*| BPF_F_ADJ_ROOM_FIXED_GSO*/);
    if (ret) {
        bpf_printk("bpf_skb_adjust_room: %d", ret);
        return false;
    }

    pkt->data = (void *)(long)skb->data;
    pkt->data_end = (void *)(long)skb->data_end;

    return true;
}

__always_inline static
bool bpf_adjust_packet(struct packet_data *pkt, int head, int tail, sa_family_t family)
{
    return pkt->is_xdp ? bpf_xdp_adjust_packet(pkt, -head, tail) :
        bpf_skb_adjust_packet(pkt, head, tail, family);
}


__always_inline static
void ip6cpy(__be32 dest[4], const __be32 src[4])
{
    #pragma unroll
    for (int i = 0; i < 4; i++)
        dest[i] = src[i];
}

__always_inline static
__u32 bpf_sock_tuple_from_header(struct bpf_sock_tuple *tuple,
                                 struct l3_header *l3, struct l4_header *l4)
{
    __u32 tuple_size;

    if (l3->family == AF_INET) {
        tuple->ipv4.saddr = *l3->src_ip;
        tuple->ipv4.daddr = *l3->dest_ip;
        tuple->ipv4.sport = *l4->src_port;
        tuple->ipv4.dport = *l4->dest_port;
        tuple_size = sizeof(tuple->ipv4);
    }
    else {
        ip6cpy(tuple->ipv6.saddr, l3->src_ip);
        ip6cpy(tuple->ipv6.daddr, l3->dest_ip);
        tuple->ipv6.sport = *l4->src_port;
        tuple->ipv6.dport = *l4->dest_port;
        tuple_size = sizeof(tuple->ipv6);
    }

    return tuple_size;
}

__always_inline static
void packet_set_offset(struct packet_data *pkt, __u16 offset)
{
    pkt->p = pkt->data + offset;
}


__always_inline static
void bpf_print_ipv4(const char *prefix, const void *ip_addr)
{
    const __u8 *ip = ip_addr;

    bpf_printk("%s%u.%u.%u.%u", prefix, ip[0], ip[1], ip[2], ip[3]);
}

__always_inline static
void bpf_print_ipv6(const char *prefix, const void *ip_addr)
{
    const __u16 *ip = ip_addr;

    bpf_printk("%s%x:%x:%x:%x:%x:%x:%x:%x", prefix,
        bpf_ntohs(ip[0]), bpf_ntohs(ip[1]), bpf_ntohs(ip[2]), bpf_ntohs(ip[3]),
        bpf_ntohs(ip[4]), bpf_ntohs(ip[5]), bpf_ntohs(ip[6]), bpf_ntohs(ip[7]));
}

__always_inline static
void bpf_print_ip(const char *prefix, const void *ip_addr, sa_family_t family)
{
    family == AF_INET ? bpf_print_ipv4(prefix, ip_addr) : bpf_print_ipv6(prefix, ip_addr);
}


#endif
