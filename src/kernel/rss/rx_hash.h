#ifndef RX_HASH_H
#define RX_HASH_H

enum xdp_rss_hash_type { _ };
int bpf_xdp_metadata_rx_hash(const struct xdp_md *ctx, __u32 *hash,
                             enum xdp_rss_hash_type *rss_type) __ksym;

SEC("xdp")
int rx_hash(struct xdp_md *xdp) {
    enum xdp_rss_hash_type rss_type;
    __u32 cpu, hash;
    int ret;

    ret = bpf_xdp_metadata_rx_hash(xdp, &hash, &rss_type);
    if (ret)
        return XDP_PASS;

    //hash >>= __builtin_ctz(rss.cpu_count);
    cpu = rss_lookup_cpu(hash);
    //bpf_printk("hash = %u, cpu = %u", hash, cpu);

    return bpf_redirect_map(&BPFWG_RSS_CPU_MAP, cpu, XDP_ABORTED);
}


#endif
