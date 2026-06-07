#ifndef WG_DECRYPT_PATH_H
#define WG_DECRYPT_PATH_H

#include <errno.h>

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <sys/socket.h>

#include "common_kern.h"
#include "receive.h"


struct wg_decrypt_inner {
    struct l3_header l3;
    struct l4_header l4;
    __u32 addr_len;
    __u16 header_len;
    __u16 trailer_len;
};

struct wg_decrypt_layout {
    __u16 iph_len;
    __u16 header_len;
    __u16 wgh_offset;
    __u16 payload_len;
};


__always_inline static
void wg_decrypt_build_layout(struct packet_header *header, struct wg_decrypt_layout *layout)
{
    layout->iph_len = header->l3.family == AF_INET ? sizeof(struct iphdr) : sizeof(struct ipv6hdr);
    layout->header_len = layout->iph_len + sizeof(struct udphdr) + sizeof(struct wg_header);
    layout->wgh_offset = header->l3.offset + layout->iph_len + sizeof(struct udphdr);
    layout->payload_len = header->l4.payload_len;
}

__always_inline static
struct wg_device *wg_decrypt_lookup_device(struct packet_data *pkt, __be16 dport)
{
    __u16 port = bpf_ntohs(dport);

    return pkt->is_xdp ?
        bpf_xdp_wg_device_get_by_port(pkt->ctx, port) :
        bpf_skb_wg_device_get_by_port(pkt->ctx, port);
}

__always_inline static
enum wg_action bpf_wg_decrypt(struct packet_data *pkt, struct wg_peer *wg_peer,
                              struct wg_decrypt_layout *layout)
{
    int ret = pkt->is_xdp ?
        bpf_xdp_wg_decrypt(pkt->ctx, layout->wgh_offset, layout->payload_len, wg_peer) :
        bpf_skb_wg_decrypt(pkt->ctx, layout->wgh_offset, layout->payload_len, wg_peer);

    switch (ret) {
        case 0:
            return WG_ACTION_REDIRECT;
        case -ENOKEY:
            bpf_printk("bpf_wg_decrypt: key not available");
            return WG_ACTION_PASS;
        case -EKEYEXPIRED:
            bpf_printk("bpf_wg_decrypt: key has expired");
            return WG_ACTION_PASS;
        case -EPROTO:
            bpf_printk("bpf_wg_decrypt: counter is invalid");
            return WG_ACTION_DROP;
        default:
            bpf_printk("bpf_wg_decrypt: %d", ret);
            return WG_ACTION_DROP;
    }
}

__always_inline static
bool wg_parse_inner_l3(struct packet_data *pkt, struct packet_header *header,
                       struct wg_decrypt_layout *layout, struct wg_decrypt_inner *inner)
{
    if (pkt->p + 1 > pkt->data_end)
        return false;

    switch (IP_VERSION(pkt->p)) {
        case 4:
            if (!parse_ipv4_header(pkt, &inner->l3))
                return false;
            inner->addr_len = 4;
            inner->header_len = layout->header_len;
            inner->trailer_len = header->l3.tot_len -
                layout->header_len - inner->l3.tot_len;
            return true;
        case 6:
            if (!parse_ipv6_header(pkt, &inner->l3))
                return false;
            inner->addr_len = 16;
            inner->header_len = layout->header_len;
            inner->trailer_len = header->l3.tot_len -
                layout->header_len - inner->l3.tot_len;
            return true;
        default:
            return false;
    }
}

__always_inline static
bool wg_source_allowed(struct wg_device *wg_device, struct wg_peer *wg_peer,
                       struct wg_decrypt_inner *inner)
{
    struct wg_peer *routed_peer;

    routed_peer = bpf_wg_peer_allowedips_lookup(wg_device, inner->l3.src_ip,
                                                inner->addr_len);
    if (routed_peer)
        bpf_wg_peer_put(routed_peer);

    if (wg_peer == routed_peer)
        return true;

    if (inner->l3.family == AF_INET)
        bpf_print_ipv4("Packet has unallowed source IP ", inner->l3.src_ip);
    else
        bpf_print_ipv6("Packet has unallowed source IP ", inner->l3.src_ip);

    return false;
}

__always_inline static
enum wg_action wg_decrypt(struct packet_data *pkt, struct packet_header *header,
                          struct wg_decrypt_inner *inner)
{
    struct wg_decrypt_layout layout;
    struct wg_device *wg_device;
    struct wg_peer *wg_peer;
    enum wg_action action;

    wg_device = wg_decrypt_lookup_device(pkt, header->l4.dest_port);
    if (!wg_device)
        return WG_ACTION_PASS;

    wg_peer = bpf_wg_peer_hashtable_lookup(wg_device, header->wg->receiver);
    if (!wg_peer) {
        bpf_printk("bpf_wg_peer_hashtable_lookup error");
        action = WG_ACTION_DROP;
        goto bpf_wg_device_put;
    }

    wg_decrypt_build_layout(header, &layout);

    action = bpf_wg_decrypt(pkt, wg_peer, &layout);
    if (action != WG_ACTION_REDIRECT) {
        /* Workaround for !read_ok */
        bpf_wg_peer_put(wg_peer);
        goto bpf_wg_device_put;
    }

    if (!wg_parse_inner_l3(pkt, header, &layout, inner)) {
        /* Workaround for !read_ok */
        bpf_wg_peer_put(wg_peer);
        action = WG_ACTION_DROP;
        goto bpf_wg_device_put;
    }

    if (!wg_source_allowed(wg_device, wg_peer, inner))
        action = WG_ACTION_DROP;

    bpf_wg_peer_put(wg_peer);
bpf_wg_device_put:
    bpf_wg_device_put(wg_device);
    return action;
}


#endif
