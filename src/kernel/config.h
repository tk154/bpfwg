#ifndef CONFIG_H
#define CONFIG_H

SEC(BPFWG_CONFIG_SECTION)
struct bpfwg_config config = {
    .conntrack = false,
    .udp_nocheck = false
};

#endif
