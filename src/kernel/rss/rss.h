#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include "../dsa/dsa.h"

#define BPFWG_RSS_INDIR_MASK (BPFWG_RSS_INDIR_SIZE - 1)

#define check_header(hdr, data, data_end, rc) \
    do { \
        hdr = data; \
        data += sizeof(*hdr); \
        if (data > data_end) \
            return rc; \
    } while (0);

struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __type(key, __u32);
    __type(value, struct bpf_cpumap_val);
    __uint(max_entries, 1);
} BPFWG_RSS_CPU_MAP SEC(".maps");

SEC(BPFWG_RSS_SECTION)
struct bpfwg_rss rss = {
    .cpu_count = 1,
    .indir = { 0 },
};

__always_inline static
__u32 rss_lookup_cpu(__u32 key)
{
    return rss.indir[key & BPFWG_RSS_INDIR_MASK];
}

__always_inline static
__be16 check_l2_header(void **data, void *data_end)
{
    switch (dsa.proto) {
        case DSA_PROTO_NONE:
            struct ethhdr *ethh;
            check_header(ethh, *data, data_end, 0);
            return ethh->h_proto;
        case DSA_PROTO_MTK:
            struct mtkhdr *mtkh;
            check_header(mtkh, *data, data_end, 0);
            return mtkh->h_proto;
        default:
            return 0;
    }
}

#include "round_robin.h"
#include "match_port.h"
#include "tuple_steering.h"
#include "rx_hash.h"
