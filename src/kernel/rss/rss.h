#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>


#define RSS_INDIR_MASK (BPFWG_RSS_INDIR_MAP_SIZE - 1)

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
} BPFWG_RSS_CPU_MAP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, BPFWG_RSS_INDIR_MAP_SIZE);
} BPFWG_RSS_INDIR_MAP SEC(".maps");

SEC(BPFWG_RSS_CPU_COUNT_SECTION)
__u32 cpu_count = 1;

__always_inline static __s32 rss_lookup_cpu(__u32 key)
{
    __u32 *cpu;

    key &= RSS_INDIR_MASK;
    cpu = bpf_map_lookup_elem(&BPFWG_RSS_INDIR_MAP, &key);
    if (cpu)
        return *cpu;

    return -1;
}

#include "round_robin.h"
#include "match_port.h"
#include "tuple_steering.h"
#include "rx_hash.h"
