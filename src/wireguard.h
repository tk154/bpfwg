#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <linux/bpf.h>
#include <linux/kernel.h>

#include <linux/ip.h>
#include <linux/ipv6.h>

#include <bpf/bpf_helpers.h>

#include "common_kern.h"


#define CHACHA20POLY1305_AUTHTAG_SIZE 16
#define MESSAGE_PADDING_MULTIPLE 16

#define WG_MESSAGE_MINIMUM_LENGTH \
    (sizeof(struct wg_header) + CHACHA20POLY1305_AUTHTAG_SIZE)

#define WG_DECRYPT_MINIMUM_LEN \
    (WG_MESSAGE_MINIMUM_LENGTH + MESSAGE_PADDING_MULTIPLE)


struct wg_device { void *dummy; };
struct wg_peer { void *dummy; };

struct wg_device *
bpf_xdp_wg_device_get_by_index(struct xdp_md *xdp_ctx, __u32 ifindex) __ksym;
struct wg_device *
bpf_xdp_wg_device_get_by_port(struct xdp_md *xdp_ctx, __u16 port) __ksym;

struct wg_device *
bpf_skb_wg_device_get_by_index(struct __sk_buff *skb_ctx, __u32 ifindex) __ksym;
struct wg_device *
bpf_skb_wg_device_get_by_port(struct __sk_buff *skb_ctx, __u16 port) __ksym;

struct wg_peer *
bpf_wg_peer_hashtable_lookup(struct wg_device *wg, __le32 idx) __ksym;
struct wg_peer *
bpf_wg_peer_allowedips_lookup(struct wg_device *wg, const void *addr,
                              __u32 addr__sz) __ksym;

int bpf_wg_endpoint_tuple_get(struct wg_peer *peer, struct bpf_sock_tuple *tuple,
                              __u32 tuple__sz) __ksym;

int bpf_xdp_wg_encrypt(struct xdp_md *xdp_ctx, __u32 offset, __u32 length,
                       struct wg_peer *peer) __ksym;
int bpf_xdp_wg_decrypt(struct xdp_md *xdp_ctx, __u32 offset, __u32 length,
                       struct wg_peer *peer) __ksym;

int bpf_skb_wg_encrypt(struct __sk_buff *skb_ctx, __u32 offset, __u32 length,
                       struct wg_peer *peer) __ksym;
int bpf_skb_wg_decrypt(struct __sk_buff *skb_ctx, __u32 offset, __u32 length,
                       struct wg_peer *peer) __ksym;

void bpf_wg_device_put(struct wg_device *wg) __ksym;
void bpf_wg_peer_put(struct wg_peer *peer) __ksym;


__always_inline static
__u16 calculate_padding(__u16 tot_len)
{
    return __ALIGN_KERNEL(tot_len, MESSAGE_PADDING_MULTIPLE) - tot_len;
}

__always_inline static
int wg_encrypt(struct packet_data *pkt, struct packet_header *header, int wg_ifindex, bool udp_check)
{
    __u16 trailer_len, iph_offset, wg_offset, wg_len, tot_len;
    __u16 daddr_len, iph_len, header_len, padding_len;
    int ret, family, out_ifindex = -1;
    struct bpf_sock_tuple tuple;
    struct wg_header *wg_header;
    struct wg_device *wg_device;
    struct wg_peer *wg_peer;

    wg_device = pkt->is_xdp ?
        bpf_xdp_wg_device_get_by_index(pkt->ctx, wg_ifindex):
        bpf_skb_wg_device_get_by_index(pkt->ctx, wg_ifindex);

    if (!wg_device)
        return 0;

    daddr_len = header->l3.family == AF_INET ? 4 : 16;
    wg_peer = bpf_wg_peer_allowedips_lookup(wg_device, header->l3.dest_ip, daddr_len);

    if (!wg_peer) {
        bpf_printk("bpf_wg_peer_allowedips_lookup error");
        goto bpf_wg_put_device;
    }

    family = bpf_wg_endpoint_tuple_get(wg_peer, &tuple, sizeof(tuple));
    switch (family) {
        case AF_INET:
            iph_len = sizeof(struct iphdr);
            break;
        case AF_INET6:
            iph_len = sizeof(struct ipv6hdr);
            break;
        default:
            bpf_printk("bpf_wg_endpoint_tuple_get error: %d", family);
            goto bpf_wg_peer_put;
    }

    header_len = iph_len + sizeof(struct udphdr) + sizeof(*wg_header);

    tot_len = header->l3.tot_len;
    padding_len = calculate_padding(tot_len);
    trailer_len = padding_len + CHACHA20POLY1305_AUTHTAG_SIZE;

    tot_len += header_len + trailer_len;
    wg_len = tot_len - iph_len - sizeof(struct udphdr);

    iph_offset = header->l3.offset;
    wg_offset = iph_offset + iph_len + sizeof(struct udphdr);

    if (!bpf_adjust_packet(pkt, header_len, trailer_len, family))
        goto bpf_wg_peer_put;

    ret = pkt->is_xdp ?
        bpf_xdp_wg_encrypt(pkt->ctx, wg_offset, wg_len, wg_peer):
        bpf_skb_wg_encrypt(pkt->ctx, wg_offset, wg_len, wg_peer);

    if (ret) {
        bpf_printk("bpf_wg_encrypt error: %d", ret);
        goto bpf_wg_peer_put;
    }

    if (!create_udp_tunnel(pkt, family, &tuple, iph_offset, tot_len, udp_check))
        goto bpf_wg_peer_put;

    out_ifindex = output(pkt, family, 0);

bpf_wg_peer_put:
    bpf_wg_peer_put(wg_peer);
bpf_wg_put_device:
    bpf_wg_device_put(wg_device);

    return out_ifindex;
}

__always_inline static
int wg_decrypt(struct packet_data *pkt, struct packet_header *header)
{
    __u16 iph_len, header_len, wgh_offset, trailer_len, src_addr_len;
    struct wg_peer *wg_peer, *routed_peer;
    struct wg_device *wg_device;
    const void *src_addr;
    int ret, out_ifindex;
    bool success = false;
    sa_family_t family;
    __u16 payload_len;
    void *iph;

    wg_device = pkt->is_xdp ?
        bpf_xdp_wg_device_get_by_port(pkt->ctx, bpf_ntohs(header->l4.dest_port)):
        bpf_skb_wg_device_get_by_port(pkt->ctx, bpf_ntohs(header->l4.dest_port));

    if (!wg_device)
        return 0;

    wg_peer = bpf_wg_peer_hashtable_lookup(wg_device, header->wg->receiver);
    if (!wg_peer) {
        bpf_printk("bpf_wg_peer_hashtable_lookup error");
        goto bpf_wg_put_device;
    }

    iph_len = header->l3.family == AF_INET ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
    wgh_offset = header->l3.offset + iph_len + sizeof(struct udphdr);
    payload_len = header->l4.payload_len;

    ret = pkt->is_xdp ?
        bpf_xdp_wg_decrypt(pkt->ctx, wgh_offset, payload_len, wg_peer):
        bpf_skb_wg_decrypt(pkt->ctx, wgh_offset, payload_len, wg_peer);

    if (ret) {
        bpf_printk("bpf_wg_decrypt error: %d", ret);
        goto bpf_wg_peer_put;
    }

    header_len = iph_len + sizeof(struct udphdr) + sizeof(struct wg_header);
    iph = pkt->data + wgh_offset + sizeof(struct wg_header);

    if (iph + 1 > pkt->data_end)
        goto bpf_wg_peer_put;

    switch (IP_VERSION(iph)) {
        case 4:
            struct iphdr *ip4h = iph;
            if (iph + sizeof(*ip4h) > pkt->data_end)
                goto bpf_wg_peer_put;

            family = AF_INET;
            src_addr = &ip4h->saddr;
            src_addr_len = sizeof(ip4h->saddr);

            trailer_len = header->l3.tot_len - header_len -
                bpf_ntohs(ip4h->tot_len);
            break;

        case 6:
            struct ipv6hdr *ip6h = iph;
            if (iph + sizeof(*ip6h) > pkt->data_end)
                goto bpf_wg_peer_put;

            family = AF_INET6;
            src_addr = &ip6h->saddr;
            src_addr_len = sizeof(ip6h->saddr);

            trailer_len = header->l3.tot_len - header_len -
                bpf_ntohs(ip6h->payload_len) - sizeof(*ip6h);
            break;

        default:
            goto bpf_wg_peer_put;
    }

    routed_peer = bpf_wg_peer_allowedips_lookup(wg_device, src_addr, src_addr_len);
    if (routed_peer)
        bpf_wg_peer_put(routed_peer);

    if (wg_peer != routed_peer) {
        family == AF_INET ? bpf_print_ipv4("Packet has unallowed source IP ", src_addr) :
            bpf_print_ipv6("Packet has unallowed source IP ", src_addr);
        goto bpf_wg_peer_put;
    }

    out_ifindex = output(pkt, family, pkt->is_xdp ? header_len : 0);

    if (!bpf_adjust_packet(pkt, -header_len, -trailer_len, family))
        goto bpf_wg_peer_put;

    success = true;

bpf_wg_peer_put:
    bpf_wg_peer_put(wg_peer);
bpf_wg_put_device:
    bpf_wg_device_put(wg_device);

    return success ? out_ifindex : -1;
}


#endif
