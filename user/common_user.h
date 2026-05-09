#ifndef COMMON_USER_H
#define COMMON_USER_H

#include <stdbool.h>

#include "../common.h"


enum {
    BPFWG_RC_ERR = -1,
    BPFWG_RC_OK  =  0
};

struct bpfwg_cpu_list {
    unsigned int *cpus;
    unsigned int count;
};

enum bpf_hook {
    BPF_HOOK_AUTO        = (1U << 0),
    BPF_HOOK_TC          = (1U << 1),

    BPF_HOOK_XDP_GENERIC = (1U << 2),
    BPF_HOOK_XDP_NATIVE  = (1U << 3),
    BPF_HOOK_XDP_OFFLOAD = (1U << 4),

    BPF_HOOK_XDP         = ( BPF_HOOK_XDP_GENERIC |
                             BPF_HOOK_XDP_NATIVE  |
                             BPF_HOOK_XDP_OFFLOAD )
};


#endif
