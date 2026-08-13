#ifndef FNV_1A_H
#define FNV_1A_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

/* Standard FNV-1a constants for 32-bit */
#define FNV_PRIME 0x01000193
#define FNV_OFFSET_BASIS 0x811C9DC5

/* 
 * 16-element Nibble Lookup Table for the 802.3 CRC32 polynomial (0xEDB88320).
 * Placed in .rodata, it takes only 64 bytes and avoids verifier branch explosion.
 */
static const __u32 crc32_nibble_table[16] = {
    0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC,
    0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
    0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C,
    0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C
};

struct flow_tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
};

/* Inline FNV-1a hash function */
static __always_inline __u32 hash_tuple(struct flow_tuple *tuple) {
    __u32 hash = FNV_OFFSET_BASIS;
    __u8 *data = (__u8 *)tuple;
    
    #pragma unroll
    for (int i = 0; i < sizeof(*tuple); i++) {
        hash ^= data[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

/* Jenkins One-at-a-Time Hash - Excellent for sequential ports */
static __always_inline __u32 jhash_oat(struct flow_tuple *tuple) {
    __u32 hash = 0;
    __u8 *data = (__u8 *)tuple;
    
    #pragma unroll
    for (int i = 0; i < sizeof(*tuple); i++) {
        hash += data[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    
    return hash;
}

/* 
 * eBPF-safe branchless CRC32 calculation.
 * Processes 4 bits (a nibble) at a time.
 */
static __always_inline __u32 calc_crc32(struct flow_tuple *tuple) {
    __u32 crc = 0xFFFFFFFF;
    __u8 *data = (__u8 *)tuple;
    
    #pragma unroll
    for (int i = 0; i < 12; i++) {
        crc ^= data[i];
        
        /* Process the lower 4 bits */
        crc = (crc >> 4) ^ crc32_nibble_table[crc & 0x0F];
        
        /* Process the upper 4 bits */
        crc = (crc >> 4) ^ crc32_nibble_table[crc & 0x0F];
    }
    
    return ~crc;
}

SEC("xdp")
int fnv_1a(struct xdp_md *xdp)
{
    void *data_end = (void *)(long)xdp->data_end;
    void *data = (void *)(long)xdp->data;
    struct ethhdr *eth = data;
    struct flow_tuple tuple;
    struct iphdr *ip;
    __u32 cpu, hash;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    tuple.src_ip = ip->saddr;
    tuple.dst_ip = ip->daddr;
    tuple.protocol = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        tuple.src_port = tcp->source;
        tuple.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        tuple.src_port = udp->source;
        tuple.dst_port = udp->dest;
    } else {
        return XDP_PASS; // Only hash TCP/UDP
    }

    /* Compute deterministic software hash */
    hash = calc_crc32(&tuple);
    hash ^= (hash >> 16);
    hash ^= (hash >> 8);

    cpu = rss_lookup_cpu(hash);
    //bpf_printk("hash = %u, cpu = %u", hash, cpu);

    return bpf_redirect_map(&BPFWG_RSS_CPU_MAP, cpu, XDP_ABORTED);
}

#endif
