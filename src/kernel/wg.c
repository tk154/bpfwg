#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/kernel.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

#include "common_kern.h"
#include "config.h"

#include "wireguard.h"
#include "receive.h"
#include "transmit.h"

#include "conntrack.h"
#include "rss/rss.h"


__always_inline static
int wg_encrypt_path(struct packet_data *pkt, struct packet_header *header,
                    int wg_ifindex)
{
    struct wg_encrypt_endpoint endpoint;
    enum wg_action action;
    int out;

    if (config.conntrack) {
        if (header->l3.proto == IPPROTO_TCP) {
            if (!parse_tcp_header(pkt, &header->l4))
                return WG_ACTION_PASS;
        }
        else if (header->l3.proto != IPPROTO_UDP)
            return WG_ACTION_PASS;

        if (!conntrack_lookup_from_header(pkt, &header->l3, &header->l4)) {
            bpf_printk("conntrack pass before encryption");
            return WG_ACTION_PASS;
        }
    }

    action = wg_encrypt(pkt, header, wg_ifindex, &endpoint);
    if (action != WG_ACTION_REDIRECT)
        return action;

    if (config.conntrack) {
        if (!conntrack_lookup_from_tuple(pkt, &endpoint.tuple, endpoint.family, IPPROTO_UDP)) {
            bpf_printk("conntrack pass after encryption");
            return WG_ACTION_PASS;
        }
    }

    out = output(pkt, endpoint.family, 0, header->l3.offset);
    /*if (out <= 0)
        bpf_printk("%s: out = %d", __func__, out);*/

    return out;
}

__always_inline static
int wg_decrypt_path(struct packet_data *pkt, struct packet_header *header,
                    struct bpf_sock *sock, struct bpf_sock_tuple *tuple)
{
    struct wg_decrypt_inner inner;
    enum wg_action action;
    int out_ifindex = 0;

    if (config.conntrack) {
        if (!conntrack_lookup_from_tuple(pkt, tuple, header->l3.family, header->l3.proto)) {
            bpf_printk("conntrack pass before encryption");
            return WG_ACTION_PASS;
        }
    }

    action = wg_decrypt(pkt, header, sock, &inner);
    if (action != WG_ACTION_REDIRECT)
        return action;

    if (config.conntrack) {
        if (!parse_l4_header(pkt, inner.l3.proto, &inner.l4)) {
            restore_l2_header(pkt, inner.header_len);
            goto bpf_adjust_packet;
        }

        if (!conntrack_lookup_from_header(pkt, &inner.l3, &inner.l4)) {
            bpf_printk("conntrack pass after decryption");
            restore_l2_header(pkt, inner.header_len);
            goto bpf_adjust_packet;
        }
    }

    out_ifindex = output(pkt, inner.l3.family, inner.header_len, header->l3.offset);
    if (out_ifindex <= 0) {
        //bpf_printk("%s: out = %d", __func__, out_ifindex);
        restore_l2_header(pkt, inner.header_len);
    }

bpf_adjust_packet:
    if (!bpf_adjust_packet(pkt, -inner.header_len, -inner.trailer_len, inner.l3.family)) {
        bpf_printk("wg_decrypt: bpf_adjust_packet error");
        return WG_ACTION_DROP;
    }

    return out_ifindex;
}

__always_inline static
int wg_process_packet(struct packet_data *pkt)
{
    struct packet_header header;
    struct bpf_sock_tuple tuple;
    struct bpf_sock *sock;
    int ifindex, ret;
    __u32 tuple_size;

    if (!parse_l2_header(pkt, &header.l2) ||
            !parse_l3_header(pkt, header.l2.proto, &header.l3))
        return WG_ACTION_PASS;

    if (header.l3.proto != IPPROTO_UDP)
        goto encrypt;

    if (!parse_udp_header(pkt, &header.l4))
        return WG_ACTION_PASS;

    if (header.l4.payload_len < WG_DECRYPT_MINIMUM_LEN)
        goto encrypt;

    if (!parse_wg_header(pkt, &header.wg))
        return WG_ACTION_PASS;

    if (header.wg->type != bpf_le32_to_cpu(WG_MESSAGE_DATA))
        goto encrypt;

    tuple_size = bpf_sock_tuple_from_header(&tuple, &header.l3, &header.l4);
    sock = bpf_sk_lookup_udp(pkt->ctx, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0);
    if (!sock)
        goto encrypt;

    ret = wg_decrypt_path(pkt, &header, sock, &tuple);
    bpf_sk_release(sock);
    return ret;

encrypt:
    ifindex = fib_lookup(pkt, &header.l3);
    if (ifindex)
        return wg_encrypt_path(pkt, &header, ifindex);

    return WG_ACTION_PASS;
}


__always_inline static
int __xdp_wg(struct xdp_md *xdp)
{
    struct packet_data pkt = {
        .ctx = (void *)xdp,
        .data = (void *)(long)xdp->data,
        .data_end = (void *)(long)xdp->data_end,
        .p = (void *)(long)xdp->data,
        .ifindex = xdp->ingress_ifindex,
        .is_xdp = true,
    };
    int out_ifindex;

    out_ifindex = wg_process_packet(&pkt);
    if (out_ifindex > 0)
        return bpf_redirect(out_ifindex, 0);
    if (out_ifindex == 0)
        return XDP_PASS;
    return XDP_DROP;
}

__always_inline static
int __tc_wg(struct __sk_buff *skb)
{
    struct packet_data pkt = {
        .ctx = (void *)skb,
        .data = (void *)(long)skb->data,
        .data_end = (void *)(long)skb->data_end,
        .p = (void *)(long)skb->data,
        .ifindex = skb->ingress_ifindex,
        .is_xdp = false,
    };
    int out_ifindex;

    out_ifindex = wg_process_packet(&pkt);
    if (out_ifindex > 0) {
        bpf_set_hash_invalid(skb);
        return bpf_redirect(out_ifindex, 0);
    }
    if (out_ifindex == 0)
        return TC_ACT_UNSPEC;
    return TC_ACT_SHOT;
}


SEC("xdp.frags")
int xdp_wg(struct xdp_md *xdp)
{
    return __xdp_wg(xdp);
}

SEC("xdp/cpumap")
int xdp_wg_cpumap(struct xdp_md *xdp)
{
    return __xdp_wg(xdp);
}

SEC("tcx/ingress")
int tc_wg(struct __sk_buff *skb)
{
    if (skb->gso_size) {
        bpf_printk("GSO isn't supported");
        return TC_ACT_UNSPEC;
    }

    return __tc_wg(skb);
}


char __license[] SEC("license") = "GPL";
