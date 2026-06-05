#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>

#include <linux/types.h>

#define STRINGIFY(x)                  #x
#define TO_STRING(x)                  STRINGIFY(x)

#define BPFWG_XDP_PROG                xdp_wg
#define BPFWG_XDP_PROG_NAME           TO_STRING(BPFWG_XDP_PROG)

#define BPFWG_XDP_CPUMAP_PROG         xdp_wg_cpumap
#define BPFWG_XDP_CPUMAP_PROG_NAME    TO_STRING(BPFWG_XDP_CPUMAP_PROG)

#define BPFWG_TC_PROG                 tc_wg
#define BPFWG_TC_PROG_NAME            TO_STRING(BPFWG_TC_PROG)

#define BPFWG_RSS_CPU_MAP             rss_cpu_map
#define BPFWG_RSS_CPU_MAP_NAME        TO_STRING(BPFWG_RSS_CPU_MAP)
#define BPFWG_RSS_CPU_MAP_QUEUE_SIZE  16384

#define BPFWG_DSA_MAX_PORTS           7
#define BPFWG_RSS_INDIR_SIZE          (1 << 8)

#define BPFWG_CONFIG_SECTION              ".rodata.config"
#define BPFWG_DSA_SECTION                 ".rodata.dsa"
#define BPFWG_RSS_SECTION                 ".rodata.rss"

enum dsa_proto {
    DSA_PROTO_NONE = 0,
    DSA_PROTO_MTK
};

struct bpfwg_dsa {
    enum dsa_proto proto;
    __u32 switch_ifindex;
    __u32 ifindex_base;
    __u32 port_to_ifindex[BPFWG_DSA_MAX_PORTS];
    __u32 ifindex_to_port[BPFWG_DSA_MAX_PORTS];
};

struct bpfwg_rss {
    __u32 cpu_count;
    __u32 indir[BPFWG_RSS_INDIR_SIZE];
};

struct bpfwg_config {
    bool conntrack;
    bool udp_nocheck;
};

#endif
