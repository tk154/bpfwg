#ifndef WG_ENCRYPT_PATH_H
#define WG_ENCRYPT_PATH_H

#include <errno.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include <sys/socket.h>

#include "common_kern.h"
#include "transmit.h"


struct wg_encrypt_endpoint {
    struct bpf_sock_tuple tuple;
    sa_family_t family;
    __u16 iph_len;
};

struct wg_encrypt_layout {
    __u16 header_len;
    __u16 trailer_len;
    __u16 tot_len;
    __u16 wg_len;
    __u16 iph_offset;
    __u16 wg_offset;
};


__always_inline static
struct wg_device *wg_encrypt_lookup_device(struct packet_data *pkt, int wg_ifindex)
{
    return pkt->is_xdp ? bpf_xdp_wg_device_get_by_index(pkt->ctx, wg_ifindex) :
        bpf_skb_wg_device_get_by_index(pkt->ctx, wg_ifindex);
}

__always_inline static
struct wg_peer *wg_encrypt_lookup_peer(struct wg_device *wg_device,
                                       struct packet_header *header)
{
    __u16 daddr_len = header->l3.family == AF_INET ? 4 : 16;

    return bpf_wg_peer_allowedips_lookup(wg_device, header->l3.dest_ip, daddr_len);
}

__always_inline static
bool wg_encrypt_resolve_endpoint(struct wg_peer *wg_peer,
                                 struct wg_encrypt_endpoint *endpoint)
{
    int family;

    family = bpf_wg_endpoint_tuple_get(wg_peer, &endpoint->tuple, sizeof(endpoint->tuple));
    switch (family) {
        case AF_INET:
            endpoint->family = AF_INET;
            endpoint->iph_len = sizeof(struct iphdr);
            return true;
        case AF_INET6:
            endpoint->family = AF_INET6;
            endpoint->iph_len = sizeof(struct ipv6hdr);
            return true;
        default:
            bpf_printk("bpf_wg_endpoint_tuple_get error: %d", family);
            return false;
    }
}

__always_inline static
__u16 wg_encrypt_padding(__u16 tot_len)
{
    return __ALIGN_KERNEL(tot_len, MESSAGE_PADDING_MULTIPLE) - tot_len;
}

__always_inline static
void wg_encrypt_build_layout(struct packet_header *header, __u16 iph_len,
                             struct wg_encrypt_layout *layout)
{
    __u16 padding_len;

    layout->header_len = iph_len + sizeof(struct udphdr) + sizeof(struct wg_header);

    layout->tot_len = header->l3.tot_len;
    padding_len = wg_encrypt_padding(layout->tot_len);
    layout->trailer_len = padding_len + CHACHA20POLY1305_AUTHTAG_SIZE;

    layout->tot_len += layout->header_len + layout->trailer_len;
    layout->wg_len = layout->tot_len - iph_len - sizeof(struct udphdr);

    layout->iph_offset = header->l3.offset;
    layout->wg_offset = layout->iph_offset + iph_len + sizeof(struct udphdr);
}

__always_inline static
int bpf_wg_encrypt(struct packet_data *pkt, struct wg_peer *wg_peer,
                   struct wg_encrypt_layout *layout)
{
    int ret = pkt->is_xdp ?
        bpf_xdp_wg_encrypt(pkt->ctx, layout->wg_offset, layout->wg_len, wg_peer):
        bpf_skb_wg_encrypt(pkt->ctx, layout->wg_offset, layout->wg_len, wg_peer);

    switch (ret) {
        case 0:
            return true;
        case -ENOKEY:
            bpf_printk("%s: key not available", __func__);
            return false;
        case -EKEYEXPIRED:
            bpf_printk("%s: key has expired", __func__);
            return false;
        case -EPROTO:
            bpf_printk("%s: counter has expired", __func__);
            return false;
        default:
            bpf_printk("%s: %d", __func__, ret);
            return false;
    }
}

__always_inline static
enum wg_action wg_encrypt(struct packet_data *pkt, struct packet_header *header,
                          int wg_ifindex, struct wg_encrypt_endpoint *endpoint)
{
    enum wg_action action = WG_ACTION_DROP;
    struct wg_encrypt_layout layout;
    struct wg_device *wg_device;
    struct wg_peer *wg_peer;

    wg_device = wg_encrypt_lookup_device(pkt, wg_ifindex);
    if (!wg_device)
        return WG_ACTION_PASS;

    wg_peer = wg_encrypt_lookup_peer(wg_device, header);
    if (!wg_peer) {
        bpf_printk("bpf_wg_peer_allowedips_lookup error");
        goto bpf_wg_device_put;
    }

    if (!wg_encrypt_resolve_endpoint(wg_peer, endpoint))
        goto bpf_wg_peer_put;

    wg_encrypt_build_layout(header, endpoint->iph_len, &layout);

    if (!bpf_adjust_packet(pkt, layout.header_len, layout.trailer_len, endpoint->family))
        goto bpf_wg_peer_put;

    if (!bpf_wg_encrypt(pkt, wg_peer, &layout))
        goto bpf_wg_peer_put;

    if (!create_udp_tunnel(pkt, endpoint->family, &endpoint->tuple,
                           layout.iph_offset, layout.tot_len))
        goto bpf_wg_peer_put;

    action = WG_ACTION_REDIRECT;

bpf_wg_peer_put:
    bpf_wg_peer_put(wg_peer);
bpf_wg_device_put:
    bpf_wg_device_put(wg_device);
    return action;
}


#endif
