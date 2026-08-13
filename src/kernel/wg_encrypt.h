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
enum wg_action wg_encrypt_lookup_device(struct packet_data *pkt, int wg_ifindex,
                                        struct wg_device **wg_device)
{
    int err;

    *wg_device = pkt->is_xdp ?
        bpf_xdp_wg_device_get_by_index(pkt->ctx, wg_ifindex, BPF_F_CURRENT_NETNS, &err):
        bpf_skb_wg_device_get_by_index(pkt->ctx, wg_ifindex, BPF_F_CURRENT_NETNS, &err);

    if (*wg_device)
        return WG_ACTION_REDIRECT;

    if (err != -ENODEV) {
        bpf_printk("bpf_wg_device_get_by_index error: %d", err);
        return WG_ACTION_DROP;
    }

    return WG_ACTION_PASS;
}

__always_inline static
enum wg_action wg_encrypt_lookup_peer(struct wg_device *wg_device,
                                      struct packet_header *header,
                                      struct wg_peer **peer)
{
    __u16 daddr_len = header->l3.family == AF_INET ? 4 : 16;

    *peer = bpf_wg_peer_allowedips_lookup(wg_device, header->l3.dest_ip,
                                          daddr_len);
    if (*peer)
        return WG_ACTION_REDIRECT;

    bpf_print_ip("No peer has allowed IPs matching ",
        header->l3.dest_ip, header->l3.family);
    return WG_ACTION_DROP;
}

__always_inline static
bool wg_encrypt_resolve_endpoint(struct wg_peer *peer,
                                 struct wg_encrypt_endpoint *endpoint)
{
    int family;

    family = bpf_wg_endpoint_tuple_get(peer, &endpoint->tuple);
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
            bpf_printk("bpf_wg_endpoint_tuple_get: %d", family);
            return false;
    }
}

__always_inline static
__u16 wg_encrypt_padding(__u16 tot_len)
{
    return __ALIGN_KERNEL(tot_len, MESSAGE_PADDING_MULTIPLE) - tot_len;
}

__always_inline static
void wg_encrypt_build_layout(struct l3_header *l3, __u16 iph_len,
                             struct wg_encrypt_layout *layout)
{
    __u16 padding_len;

    layout->header_len = iph_len + sizeof(struct udphdr) + sizeof(struct wg_header);

    layout->tot_len = l3->tot_len;
    padding_len = wg_encrypt_padding(layout->tot_len);
    layout->trailer_len = padding_len + CHACHA20POLY1305_AUTHTAG_SIZE;

    layout->tot_len += layout->header_len + layout->trailer_len;
    layout->wg_len = layout->tot_len - iph_len -
        sizeof(struct udphdr) - sizeof(struct wg_header);

    layout->iph_offset = l3->offset;
    layout->wg_offset = layout->iph_offset + iph_len +
        sizeof(struct udphdr) + sizeof(struct wg_header);
}

__always_inline static
enum wg_action wg_encrypt_packet(struct packet_data *pkt, struct wg_encrypt_layout *layout,
                                 struct wg_peer *peer, __le32 *key_idx, __u64 *nonce)
{
    struct bpf_dynptr ptr;
    long ret;

    if (!bpf_dynptr_from_packet(&ptr, pkt, layout->wg_offset, layout->wg_len))
        return WG_ACTION_DROP;

    ret = bpf_wg_encrypt(&ptr, peer, nonce);
    if (ret >= 0) {
        *key_idx = (__le32)ret;
        return WG_ACTION_REDIRECT;
    }

    switch (ret) {
        case -EKEYEXPIRED:
            bpf_printk("bpf_wg_encrypt: key has expired");
            return WG_ACTION_PASS;
        default:
            bpf_printk("bpf_wg_encrypt: %d", ret);
            return WG_ACTION_DROP;
    }
}

__always_inline static
enum wg_action wg_encrypt(struct packet_data *pkt, struct packet_header *header,
                          int wg_ifindex, struct wg_encrypt_endpoint *endpoint)
{
    struct wg_encrypt_layout layout;
    struct wg_device *wg_device;
    enum wg_action action;
    struct wg_peer *peer;
    __le32 key_idx;
    __u64 counter;

    action = wg_encrypt_lookup_device(pkt, wg_ifindex, &wg_device);
    if (action != WG_ACTION_REDIRECT)
        return action;

    action = wg_encrypt_lookup_peer(wg_device, header, &peer);
    if (action != WG_ACTION_REDIRECT)
        goto bpf_wg_device_put;

    if (!wg_encrypt_resolve_endpoint(peer, endpoint)) {
        action = WG_ACTION_PASS;
        goto bpf_wg_keypair_put;
    }

    wg_encrypt_build_layout(&header->l3, endpoint->iph_len, &layout);

    if (!bpf_adjust_packet(pkt, layout.header_len, layout.trailer_len, endpoint->family)) {
        bpf_printk("wg_encrypt: bpf_adjust_packet error");
        action = WG_ACTION_DROP;
        goto bpf_wg_keypair_put;
    }

    action = wg_encrypt_packet(pkt, &layout, peer, &key_idx, &counter);
    if (action != WG_ACTION_REDIRECT)
        goto bpf_wg_keypair_put;

    if (!create_wg_tunnel(pkt, endpoint->family, &endpoint->tuple,
                          layout.iph_offset, layout.tot_len, key_idx, counter))
        action = WG_ACTION_DROP;

bpf_wg_keypair_put:
    bpf_wg_peer_put(peer);
bpf_wg_device_put:
    bpf_wg_device_put(wg_device);
    return action;
}


#endif
