#include <stdbool.h>
#include <stddef.h>

#include <linux/bpf.h>
#include <linux/kernel.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

#include "common_kern.h"
#include "config.h"

#ifdef WOLFGUARD
#include "wolfguard.h"
#else
#include "wireguard.h"
#endif
#include "receive.h"
#include "transmit.h"

#include "conntrack.h"
#include "rss/rss.h"


__always_inline static
int wg_encrypt_path(struct packet_data *pkt, struct packet_header *header,
                    __u32 wg_ifindex)
{
    struct wg_encrypt_endpoint endpoint;
    int ret;

    ret = wg_encrypt(pkt, header, wg_ifindex, &endpoint);
    if (ret != WG_ACTION_REDIRECT)
        return ret;

    if (config.conntrack) {
        if (!conntrack_lookup_from_tuple(pkt, &endpoint.tuple,
                endpoint.tuple_size, IPPROTO_UDP)) {
            //bpf_printk("conntrack pass after encryption");
            return WG_ACTION_PASS;
        }
    }

    if (!create_udp_tunnel(pkt, endpoint.family, &endpoint.tuple,
            header->l3.offset, endpoint.tot_len))
        return WG_ACTION_DROP;

    return output(pkt, endpoint.family, 0, header->l3.offset);
}

__always_inline static
int wg_decrypt_path(struct packet_data *pkt, struct packet_header *header,
                    struct bpf_sock *wg_sock)
{
    struct wg_decrypt_inner inner;
    int ret;

    ret = wg_decrypt(pkt, header, wg_sock, &inner);
    if (ret != WG_ACTION_REDIRECT)
        goto bpf_sk_release;

    if (config.conntrack) {
        if (!parse_l4_header(pkt, inner.l3.proto, &inner.l4)) {
            ret = WG_ACTION_PASS;
            goto bpf_adjust_packet;
        }

        if (!conntrack_lookup_from_header(pkt, &inner.l3, &inner.l4)) {
            //bpf_printk("conntrack pass after decryption");
            ret = WG_ACTION_PASS;
            goto bpf_adjust_packet;
        }
    }

    ret = output(pkt, inner.l3.family, inner.header_len, header->l3.offset);

bpf_adjust_packet:
    if (ret <= 0)
        restore_l2_header(pkt, inner.header_len);

    if (!bpf_adjust_packet(pkt, -inner.header_len, -inner.trailer_len,
            inner.l3.family)) {
        bpf_printk("wg_decrypt: bpf_adjust_packet error");
        ret = WG_ACTION_DROP;
    }

bpf_sk_release:
    bpf_sk_release(wg_sock);
    return ret;
}

__always_inline static
__u32 lookup_wg_ifindex(struct packet_data *pkt, struct packet_header *header)
{
    if (config.conntrack) {
        packet_set_offset(pkt, header->l3.offset + header->l3.hdr_len);

        if (!parse_l4_header(pkt, header->l3.proto, &header->l4))
            return 0;

        if (!conntrack_lookup_from_header(pkt, &header->l3, &header->l4)) {
            //bpf_printk("conntrack pass before encryption");
            return 0;
        }
    }

    return fib_lookup(pkt, &header->l3);
}

__always_inline static
bool lookup_wg_socket(struct packet_data *pkt, struct packet_header *header,
                      struct bpf_sock **sock)
{
    struct bpf_sock_tuple tuple;
    __u32 tuple_size;

    tuple_size = bpf_sock_tuple_from_header(&tuple, &header->l3, &header->l4);

    if (config.conntrack) {
        if (!conntrack_lookup_from_tuple(pkt, &tuple, tuple_size, header->l3.proto)) {
            //bpf_printk("conntrack pass before decryption");
            return false;
        }
    }

    *sock = sock_lookup(pkt, &tuple, tuple_size);
    return true;
}

__always_inline static
int wg_process_packet(struct packet_data *pkt)
{
    struct packet_header header;
    struct bpf_sock *wg_sock;
    __u32 wg_ifindex;

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

    if (!lookup_wg_socket(pkt, &header, &wg_sock))
        return WG_ACTION_PASS;

    if (wg_sock)
        return wg_decrypt_path(pkt, &header, wg_sock);

encrypt:
    wg_ifindex = lookup_wg_ifindex(pkt, &header);
    if (wg_ifindex)
        return wg_encrypt_path(pkt, &header, wg_ifindex);

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
