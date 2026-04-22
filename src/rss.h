#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#define check_header(hdr, data, data_end) \
    do { \
        hdr = data; \
        data += sizeof(*hdr); \
        if (data > data_end) \
            return XDP_PASS; \
    } while (0);

struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __type(key, __u32);
    __type(value, struct bpf_cpumap_val);
    __uint(max_entries, 1);
} BPFWG_CPU_MAP SEC(".maps");

SEC(BPFWG_CPU_COUNT_SECTION)
__u32 cpu_count = 1;


/* ROUND ROBIN */
struct cpu_iterator {
    struct bpf_spin_lock semaphore;
    __u32 cpu;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct cpu_iterator);
    __uint(max_entries, 1);
} cpu_iterator_map SEC(".maps");

SEC("xdp")
int round_robin(struct xdp_md *xdp)
{
    struct cpu_iterator *iterator;
    __u32 cpu, key = 0;

    iterator = bpf_map_lookup_elem(&cpu_iterator_map, &key);
    if (!iterator)
        return XDP_ABORTED;

    bpf_spin_lock(&iterator->semaphore);
    cpu = iterator->cpu;

    if (++iterator->cpu == cpu_count)
        iterator->cpu = 0;

    bpf_spin_unlock(&iterator->semaphore);

    return bpf_redirect_map(&BPFWG_CPU_MAP, cpu, XDP_ABORTED);
}
/* END ROUND ROBIN */

/* MATCH PORT */
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

    cpu = dport - PORT_BASE;
    if (cpu >= cpu_count)
        return XDP_PASS;

    return bpf_redirect_map(&BPFWG_CPU_MAP, cpu, XDP_ABORTED);
}
/* END MATCH PORT */

/* RX_HASH */
enum xdp_rss_hash_type { _ };
int bpf_xdp_metadata_rx_hash(const struct xdp_md *ctx, __u32 *hash, enum xdp_rss_hash_type *rss_type) __ksym;

SEC("xdp")
int rx_hash(struct xdp_md *xdp) {
    enum xdp_rss_hash_type rss_type;
    __u32 cpu, hash;
    int ret;

    ret = bpf_xdp_metadata_rx_hash(xdp, &hash, &rss_type);
    if (ret)
        return XDP_PASS;

    cpu = (hash >> (__builtin_ctz(cpu_count) + 1)) & (cpu_count - 1);
    //bpf_printk("hash = %u, cpu = %u", hash, cpu);

    return bpf_redirect_map(&BPFWG_CPU_MAP, cpu, XDP_ABORTED);
}
/* END RX_HASH */
