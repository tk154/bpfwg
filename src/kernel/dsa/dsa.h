#ifndef DSA_H
#define DSA_H

#include <bpf/bpf_helpers.h>

SEC(BPFWG_DSA_SECTION)
struct bpfwg_dsa dsa = {
    .proto = DSA_PROTO_NONE
};


#include "mtk.h"

__always_inline static
bool parse_dsa_header(struct packet_data *pkt, struct l2_header *l2)
{
    switch (dsa.proto) {
        case DSA_PROTO_MTK:
            return parse_mtk_header(pkt, l2);
        default:
            return false;
    }
}

__always_inline static
__s32 push_dsa_header(void *l2, struct packet_data *pkt, struct bpf_fib_lookup *fib)
{
    switch (dsa.proto) {
        case DSA_PROTO_MTK:
            return push_mtk_header(l2, pkt, fib);
        default:
            return -1;
    }
}

#endif
