#ifndef RECEIVE_H
#define RECEIVE_H

#include <linux/in.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <sys/socket.h>

#include "endian.h"
#include "dsa/dsa.h"

#define IP_VERSION(ip)	(*(__u8 *)(ip) >> 4)
#define WG_MESSAGE_DATA bpf_le32_to_cpu(4)


__always_inline static
bool parse_eth_header(struct packet_data *pkt, struct l2_header *l2)
{
    struct ethhdr *ethh;
    __parse_eth_header(ethh, pkt, l2);

    return true;
}

__always_inline static
bool parse_ipv4_header(struct packet_data *pkt, struct l3_header *l3)
{
    struct iphdr *ip4h;
    parse_header(ip4h, pkt);

    l3->family  = AF_INET;
	l3->src_ip  = &ip4h->saddr;
	l3->dest_ip = &ip4h->daddr;

	l3->proto   = ip4h->protocol;
	l3->tot_len = bpf_ntohs(ip4h->tot_len);

    return true;
}

__always_inline static
bool parse_ipv6_header(struct packet_data *pkt, struct l3_header *l3)
{
    struct ipv6hdr *ip6h;
    parse_header(ip6h, pkt);

    l3->family  = AF_INET6;
	l3->src_ip  = ip6h->saddr.in6_u.u6_addr32;
	l3->dest_ip = ip6h->daddr.in6_u.u6_addr32;

	l3->proto   = ip6h->nexthdr;
	l3->tot_len = bpf_ntohs(ip6h->payload_len) + sizeof(*ip6h);

    return true;
}

__always_inline static
bool parse_tcp_header(struct packet_data *pkt, struct l4_header *l4)
{
	struct tcphdr *tcph;
	parse_header(tcph, pkt);

    l4->src_port = tcph->source;
	l4->dest_port = tcph->dest;

	return true;
}

__always_inline static
bool parse_udp_header(struct packet_data *pkt, struct l4_header *l4)
{
	struct udphdr *udph;
	parse_header(udph, pkt);

    l4->src_port = udph->source;
	l4->dest_port = udph->dest;
	l4->payload_len = bpf_ntohs(udph->len) - sizeof(*udph);

	return true;
}

__always_inline static
bool parse_wg_header(struct packet_data *pkt, struct wg_header **wg)
{
    struct wg_header *wg_header;
    parse_header(wg_header, pkt);

    if (wg_header->type != WG_MESSAGE_DATA)
        return false;

    *wg = wg_header;
    return true;
}


__always_inline static
bool parse_l2_header(struct packet_data *pkt, struct l2_header *l2)
{
    if (dsa.proto != DSA_PROTO_NONE)
        return parse_dsa_header(pkt, l2);

    return parse_eth_header(pkt, l2);
}

__always_inline static
bool parse_l3_header(struct packet_data *pkt, __be16 proto, struct l3_header *l3)
{
	l3->offset = pkt->p - pkt->data;

	switch (proto) {
		case bpf_ntohs(ETH_P_IP):
			return parse_ipv4_header(pkt, l3);
        case bpf_ntohs(ETH_P_IPV6):
            return parse_ipv6_header(pkt, l3);
		default:
			return false;
	}
}

__always_inline static
bool parse_l4_header(struct packet_data *pkt, __u8 proto, struct l4_header *l4)
{
	switch (proto) {
		case IPPROTO_TCP:
			return parse_tcp_header(pkt, l4);
		case IPPROTO_UDP:
			return parse_udp_header(pkt, l4);
		default:
			return false;
	}
}


__always_inline static
int fib_lookup(struct packet_data *pkt, struct l3_header *l3)
{
    struct bpf_fib_lookup fib = {};
    long ret;

    fib.ifindex = pkt->ifindex;
    fib.tot_len = l3->tot_len;
    fib.family = l3->family;

    if (l3->family == AF_INET) {
        fib.ipv4_src = *l3->src_ip;
        fib.ipv4_dst = *l3->dest_ip;
    }
    else {
        ip6cpy(fib.ipv6_src, l3->src_ip);
        ip6cpy(fib.ipv6_dst, l3->dest_ip);
    }

    ret = bpf_fib_lookup(pkt->ctx, &fib, sizeof(fib), 0);
    switch (ret) {
        case BPF_FIB_LKUP_RET_SUCCESS:
            return fib.ifindex;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
            return 0;
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            bpf_printk("Fragmentation required: len = %u, mtu = %u",
                l3->tot_len, fib.tot_len);
        default:
            //bpf_printk("%s: %d", __func__, ret);
            return -1;
    }
}


#endif
