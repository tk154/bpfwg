#ifndef CONFIG_H
#define CONFIG_H

SEC(BPFWG_CONFIG_SECTION)
struct bpfwg_config config = {
    .dsa_proto = DSA_PROTO_NONE,
    .conntrack = false,
    .udp_nocheck = false
};

#endif
