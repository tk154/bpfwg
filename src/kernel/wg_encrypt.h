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
    __u64 tuple_size;
    sa_family_t family;
    __u16 tot_len;
    __u8 iph_len;
};

struct wg_encrypt_layout {
    __u16 header_len;
    __u16 trailer_len;
    __u16 plain_len;
    __u16 message_len;
    __u16 wg_offset;
    __u16 plain_offset;
};


__always_inline static
bool push_wg_header(struct packet_data *pkt, __u16 wg_offset,
                    __le32 key_idx, __u64 counter)
{
    struct wg_header *wgh = pkt->data + wg_offset;

    if ((void *)(wgh + 1) > pkt->data_end)
        return false;

    wgh->type = bpf_cpu_to_le32(WG_MESSAGE_DATA);
    wgh->key_idx = key_idx;
    wgh->counter = bpf_cpu_to_le64(counter);
    return true;
}

__always_inline static
enum wg_action wg_encrypt_lookup_device(struct packet_data *pkt, __u32 wg_ifindex,
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
    int ret;

    ret = bpf_wg_endpoint_tuple_get(peer, &endpoint->tuple);
    switch (ret) {
        case AF_INET:
            endpoint->family = AF_INET;
            endpoint->iph_len = sizeof(struct iphdr);
            endpoint->tuple_size = sizeof(endpoint->tuple.ipv4);
            return true;
        case AF_INET6:
            endpoint->family = AF_INET6;
            endpoint->iph_len = sizeof(struct ipv6hdr);
            endpoint->tuple_size = sizeof(endpoint->tuple.ipv6);
            return true;
        default:
            bpf_printk("bpf_wg_endpoint_tuple_get: %d", ret);
            return false;
    }
}

__always_inline static
__u16 wg_encrypt_padding(__u16 tot_len)
{
    return __ALIGN_KERNEL(tot_len, MESSAGE_PADDING_MULTIPLE) - tot_len;
}

__always_inline static
void wg_encrypt_build_layout(struct l3_header *l3, struct wg_encrypt_layout *layout,
                             struct wg_encrypt_endpoint *endpoint)
{
    layout->header_len = endpoint->iph_len + sizeof(struct udphdr) + sizeof(struct wg_header);
    layout->trailer_len = wg_encrypt_padding(l3->tot_len) + CHACHA20POLY1305_AUTHTAG_SIZE;

    endpoint->tot_len = l3->tot_len + layout->header_len + layout->trailer_len;
    layout->message_len = endpoint->tot_len - endpoint->iph_len - sizeof(struct udphdr);
    layout->plain_len = layout->message_len - sizeof(struct wg_header);

    layout->wg_offset = l3->offset + endpoint->iph_len + sizeof(struct udphdr);
    layout->plain_offset = layout->wg_offset + sizeof(struct wg_header);
}

__always_inline static
enum wg_action wg_encrypt_packet(struct packet_data *pkt, struct wg_encrypt_layout *layout,
                                 struct wg_peer *peer, __le32 *key_idx, __u64 *nonce)
{
    struct bpf_dynptr ptr;
    long ret;

    if (!bpf_dynptr_from_packet(&ptr, pkt, layout->plain_offset, layout->plain_len))
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
                          __u32 wg_ifindex, struct wg_encrypt_endpoint *endpoint)
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
        goto bpf_wg_peer_put;
    }

    wg_encrypt_build_layout(&header->l3, &layout, endpoint);

    if (!bpf_adjust_packet(pkt, layout.header_len, layout.trailer_len, endpoint->family)) {
        bpf_printk("wg_encrypt: bpf_adjust_packet error");
        action = WG_ACTION_DROP;
        goto bpf_wg_peer_put;
    }

    action = wg_encrypt_packet(pkt, &layout, peer, &key_idx, &counter);
    if (action != WG_ACTION_REDIRECT)
        goto bpf_wg_peer_put;

    if (!push_wg_header(pkt, layout.wg_offset, key_idx, counter)) {
        action = WG_ACTION_DROP;
        goto bpf_wg_peer_put;
    }

    bpf_wg_peer_update_tx_stats(peer, layout.message_len);

bpf_wg_peer_put:
    bpf_wg_peer_put(peer);
bpf_wg_device_put:
    bpf_wg_device_put(wg_device);
    return action;
}


#endif
