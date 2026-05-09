#ifndef COMMON_H
#define COMMON_H

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

#define BPFWG_RSS_INDIR_MAP           rss_indir_map
#define BPFWG_RSS_INDIR_MAP_NAME      TO_STRING(BPFWG_RSS_INDIR_MAP)
#define BPFWG_RSS_INDIR_MAP_SIZE      (1 << 8)

#define BPFWG_CONFIG_SECTION              ".rodata.config"
#define BPFWG_RSS_CPU_COUNT_SECTION       ".rodata.rss.cpu_count"
#define BPFWG_RSS_EXCLUDED_CPUS_SECTION   ".rodata.rss.excluded_cpus"

enum dsa_proto {
    DSA_PROTO_NONE = 0,
    DSA_PROTO_MTK
};

struct bpfwg_config {
    enum dsa_proto dsa_proto;
    bool conntrack;
    bool udp_nocheck;
};

#endif
