#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/kernel.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

#include "common_kern.h"
#include "receive.h"
#include "transmit.h"
#include "wireguard.h"


__always_inline static
int wg_func(struct packet_data *pkt, bool udp_check)
{
    struct packet_header header;
    int ifindex;

    if (!parse_l2_header(pkt, &header.l2) ||
            !parse_l3_header(pkt, header.l2.proto, &header.l3))
        return 0;

    ifindex = fib_lookup(pkt, &header.l3);

    if (ifindex > 0) {
        if (header.l3.tot_len > MAX_MTU)
            return 0;

        return wg_encrypt(pkt, &header, ifindex, udp_check);
    }
    else if (!ifindex) {
        if (!parse_l4_header(pkt, header.l3.proto, &header.l4) ||
                header.l4.payload_len < WG_DECRYPT_MINIMUM_LEN ||
                !parse_wg_header(pkt, &header.wg))
            return 0;

        return wg_decrypt(pkt, &header);
    }

    return 0;
}


__always_inline static
int __xdp_wg(struct xdp_md *xdp, bool udp_check)
{
	struct packet_data pkt = {
        .ctx        = (void *)xdp,
		.data 	  	= (void *)(long)xdp->data,
		.data_end 	= (void *)(long)xdp->data_end,
        .p          = (void *)(long)xdp->data,
        .ifindex    = xdp->ingress_ifindex,
        .is_xdp     = true
	};

    int out_ifindex = wg_func(&pkt, udp_check);

    if (out_ifindex > 0)
        return bpf_redirect(out_ifindex, 0);
    if (out_ifindex < 0)
        return XDP_DROP;

    return XDP_PASS;
}

__always_inline static
int __tc_wg(struct __sk_buff *skb, bool udp_check)
{
	struct packet_data pkt = {
        .ctx        = (void *)skb,
		.data 	  	= (void *)(long)skb->data,
		.data_end 	= (void *)(long)skb->data_end,
        .p          = (void *)(long)skb->data,
        .ifindex    = skb->ingress_ifindex,
        .is_xdp     = false
	};

    int out_ifindex = wg_func(&pkt, udp_check);

    if (out_ifindex > 0)
        return bpf_redirect(out_ifindex, 0);
    if (out_ifindex < 0)
        return TC_ACT_SHOT;

    return TC_ACT_UNSPEC;
}


SEC("xdp.frags")
int xdp_wg(struct xdp_md *xdp)
{
    return __xdp_wg(xdp, true);
}

SEC("xdp.frags")
int xdp_wg_nocheck(struct xdp_md *xdp)
{
    return __xdp_wg(xdp, false);
}


SEC("tc")
int tc_wg(struct __sk_buff *skb)
{
    return __tc_wg(skb, true);
}

SEC("tc")
int tc_wg_nocheck(struct __sk_buff *skb)
{
    return __tc_wg(skb, false);
}


char __license[] SEC("license") = "GPL";
