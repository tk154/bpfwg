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
    __u16 header_len;
    __u16 payload_offset;
    __u16 payload_len;
};


__always_inline static
enum wg_action wg_decrypt_lookup_key(struct wg_device *wg_device, struct wg_header *wg_header,
                                     struct noise_keypair **keypair, struct wg_peer **peer)
{
    *keypair = bpf_wg_keypair_hashtable_lookup(wg_device, wg_header->key_idx, (unsigned long *)peer);
    if (*keypair)
        return WG_ACTION_REDIRECT;

    if (*peer) {
        bpf_printk("Key has expired for key index %u", wg_header->key_idx);
        return WG_ACTION_PASS; 
    }

    bpf_printk("No peer has key index matching %u", wg_header->key_idx);
    return WG_ACTION_DROP;
}

__always_inline static
void wg_decrypt_build_layout(struct packet_header *header, struct wg_decrypt_layout *layout)
{
    layout->header_len = header->l3.hdr_len +
        sizeof(struct udphdr) + sizeof(struct wg_header);
    layout->payload_offset = header->l3.offset + header->l3.hdr_len +
        sizeof(struct udphdr) + sizeof(struct wg_header);
    layout->payload_len = header->l4.payload_len - sizeof(struct wg_header);
}

__always_inline static
enum wg_action wg_decrypt_packet(struct packet_data *pkt, struct wg_decrypt_layout *layout,
                                 struct noise_keypair *keypair, __u64 nonce)
{
    struct bpf_dynptr ptr;
    long ret;

    /*if (!pkt->is_xdp && !bpf_skb_linearize(pkt, layout->payload_offset))
        return WG_ACTION_DROP;*/

    if (!bpf_dynptr_from_packet(&ptr, pkt, layout->payload_offset, layout->payload_len))
        return WG_ACTION_DROP;

    ret = bpf_wg_decrypt(&ptr, keypair, nonce);
    switch (ret) {
        case 0:
            return WG_ACTION_REDIRECT;
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
            inner->addr_len = sizeof(struct in_addr);
            break;
        case 6:
            if (!parse_ipv6_header(pkt, &inner->l3))
                return false;
            inner->addr_len = sizeof(struct in6_addr);
            break;
        default:
            return false;
    }

    inner->header_len = layout->header_len;
    inner->trailer_len = header->l3.tot_len -
        layout->header_len - inner->l3.tot_len;
    return true;
}

__always_inline static
bool wg_source_allowed(struct wg_device *wg_device, struct wg_peer *peer,
                       struct wg_decrypt_inner *inner)
{
    struct wg_peer *routed_peer;

    routed_peer = bpf_wg_peer_allowedips_lookup(wg_device, inner->l3.src_ip,
                                                inner->addr_len);
    if (routed_peer) {
        bpf_wg_peer_put(routed_peer);
        if (routed_peer == peer)
            return true;
    }

    bpf_print_ip("Packet has unallowed source IP ",
        inner->l3.src_ip, inner->l3.family);
    return false;
}

__always_inline static
enum wg_action wg_decrypt(struct packet_data *pkt, struct packet_header *header,
                          struct bpf_sock *sock, struct wg_decrypt_inner *inner)
{
    struct wg_decrypt_layout layout;
    struct noise_keypair *keypair = NULL;
    struct wg_device *wg_device;
    enum wg_action action;
    struct wg_peer *peer;
    __u64 counter;

    wg_device = bpf_wg_device_get_from_sk((struct sock *)sock);
    if (!wg_device)
        return WG_ACTION_PASS;

    action = wg_decrypt_lookup_key(wg_device, header->wg, &keypair, &peer);
    if (action != WG_ACTION_REDIRECT)
        goto bpf_wg_device_put;

    wg_decrypt_build_layout(header, &layout);
    counter = bpf_le64_to_cpu(header->wg->counter);

    action = wg_decrypt_packet(pkt, &layout, keypair, counter);
    if (action != WG_ACTION_REDIRECT) {
        /* Workaround for !read_ok */
        bpf_wg_keypair_put(keypair);
        goto bpf_wg_device_put;
    }

    if (!wg_parse_inner_l3(pkt, header, &layout, inner)) {
        /* Workaround for !read_ok */
        bpf_wg_keypair_put(keypair);
        action = WG_ACTION_DROP;
        goto bpf_wg_device_put;
    }

    if (!wg_source_allowed(wg_device, peer, inner))
        action = WG_ACTION_DROP;

//bpf_wg_keypair_put:
    bpf_wg_keypair_put(keypair);
bpf_wg_device_put:
    bpf_wg_device_put(wg_device);
    return action;
}


#endif
