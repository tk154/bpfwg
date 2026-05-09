#define RSS_TUPLE_MAP_MAX_ENTRIES    64

typedef typeof(((struct bpf_sock_tuple *)0)->ipv4) bpf_sock_tuple_ipv4_t;
typedef typeof(((struct bpf_sock_tuple *)0)->ipv6) bpf_sock_tuple_ipv6_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, bpf_sock_tuple_ipv4_t);
    __type(value, __u32);
    __uint(max_entries, RSS_TUPLE_MAP_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_COMMON_LRU);
} ipv4_tuple_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, bpf_sock_tuple_ipv6_t);
    __type(value, __u32);
    __uint(max_entries, RSS_TUPLE_MAP_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_COMMON_LRU);
} ipv6_tuple_map SEC(".maps");

SEC("xdp")
int tuple_steering(struct xdp_md *xdp)
{
    void *data_end = (void *)(long)xdp->data_end;
    void *data = (void *)(long)xdp->data;
    __u32 *cpu_idx, new_cpu, key = 0;
    struct cpu_iterator *iterator;
    struct bpf_sock_tuple tuple;
    struct ethhdr *ethh;
    void *tuple_map;
    __be16 *ports;
    __u8 proto;

    check_header(ethh, data, data_end);

    switch (ethh->h_proto) {
        case bpf_htons(ETH_P_IP):
            struct iphdr *ip4h;
            check_header(ip4h, data, data_end);
            tuple.ipv4.saddr = ip4h->saddr;
            tuple.ipv4.daddr = ip4h->daddr;
            tuple_map = &ipv4_tuple_map;
            ports = &tuple.ipv4.sport;
            proto = ip4h->protocol;
            break;
        case bpf_htons(ETH_P_IPV6):
            struct ipv6hdr *ip6h;
            check_header(ip6h, data, data_end);
            memcpy(tuple.ipv6.saddr, &ip6h->saddr, sizeof(tuple.ipv6.saddr));
            memcpy(tuple.ipv6.daddr, &ip6h->daddr, sizeof(tuple.ipv6.daddr));
            tuple_map = &ipv6_tuple_map;
            ports = &tuple.ipv6.sport;
            proto = ip6h->nexthdr;
            break;
        default:
            return XDP_PASS;
    }

    switch (proto) {
        case IPPROTO_TCP:
            struct tcphdr *tcph;
            check_header(tcph, data, data_end);
            ports[0] = bpf_ntohs(tcph->source);
            ports[1] = bpf_ntohs(tcph->dest);
            break;
        case IPPROTO_UDP:
            struct udphdr *udph;
            check_header(udph, data, data_end);
            ports[0] = bpf_ntohs(udph->source);
            ports[1] = bpf_ntohs(udph->dest);
            break;
        default:
            return XDP_PASS;
    }

    cpu_idx = bpf_map_lookup_elem(tuple_map, &tuple);
    if (!cpu_idx) {
        iterator = bpf_map_lookup_elem(&cpu_iterator_map, &key);
        if (!iterator)
            return XDP_ABORTED;

        bpf_spin_lock(&iterator->semaphore);

        new_cpu = iterator->cpu;
        if (++iterator->cpu == cpu_count)
            iterator->cpu = 0;

        bpf_spin_unlock(&iterator->semaphore);

        bpf_map_update_elem(tuple_map, &tuple, &new_cpu, BPF_NOEXIST);
        cpu_idx = &new_cpu;
    }

    return bpf_redirect_map(&BPFWG_RSS_CPU_MAP, *cpu_idx, 0);
}
