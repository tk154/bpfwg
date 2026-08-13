#ifndef MATCH_PORT_H
#define MATCH_PORT_H

#define SOURCE_BASE 5000
#define DEST_BASE   5200


SEC("xdp")
int match_port(struct xdp_md *xdp) {
    void *data_end = (void *)(long)xdp->data_end;
    void *data = (void *)(long)xdp->data;
    __u32 cpu, key;
    __be16 h_proto;
    __u8 l4_proto;
    __u16 dport;

    h_proto = check_l2_header(&data, data_end);
    switch (h_proto) {
        case bpf_htons(ETH_P_IP):
            struct iphdr *ip4h;
            check_header(ip4h, data, data_end, XDP_PASS);
            l4_proto = ip4h->protocol;
            break;
        case bpf_htons(ETH_P_IPV6):
            struct ipv6hdr *ip6h;
            check_header(ip6h, data, data_end, XDP_PASS);
            l4_proto = ip6h->nexthdr;
            break;
        default:
            return XDP_PASS;
    }

    switch (l4_proto) {
        case IPPROTO_TCP:
            struct tcphdr *tcph;
            check_header(tcph, data, data_end, XDP_PASS);
            dport = bpf_ntohs(tcph->dest);
            break;
        case IPPROTO_UDP:
            struct udphdr *udph;
            check_header(udph, data, data_end, XDP_PASS);
            dport = bpf_ntohs(udph->dest);
            break;
        default:
            return XDP_PASS;
    }

    key = dport - (dport < DEST_BASE ? SOURCE_BASE : DEST_BASE);
    cpu = rss_lookup_cpu(key);

    return bpf_redirect_map(&BPFWG_RSS_CPU_MAP, cpu, XDP_ABORTED);
}

#endif
