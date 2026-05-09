#define PORT_BASE 5200

SEC("xdp")
int match_port(struct xdp_md *xdp) {
    void *data_end = (void *)(long)xdp->data_end;
    void *data = (void *)(long)xdp->data;
    struct ethhdr *ethh;
    __u16 dport;
    __u8 proto;
    __u32 cpu;

    check_header(ethh, data, data_end);

    switch (ethh->h_proto) {
        case bpf_htons(ETH_P_IP):
            struct iphdr *ip4h;
            check_header(ip4h, data, data_end);
            proto = ip4h->protocol;
            break;
        case bpf_htons(ETH_P_IPV6):
            struct ipv6hdr *ip6h;
            check_header(ip6h, data, data_end);
            proto = ip6h->nexthdr;
            break;
        default:
            return XDP_PASS;
    }

    switch (proto) {
        case IPPROTO_TCP:
            struct tcphdr *tcph;
            check_header(tcph, data, data_end);
            dport = bpf_ntohs(tcph->dest);
            break;
        case IPPROTO_UDP:
            struct udphdr *udph;
            check_header(udph, data, data_end);
            dport = bpf_ntohs(udph->dest);
            break;
        default:
            return XDP_PASS;
    }

    //cpu = (dport - PORT_BASE) & (cpu_count - 1);
    cpu = rss_lookup_cpu(dport - PORT_BASE);
    /*while (cpu_excluded(cpu))
        cpu = (cpu + 1) & (cpu_count - 1);*/

    return bpf_redirect_map(&BPFWG_RSS_CPU_MAP, cpu, XDP_ABORTED);
}
