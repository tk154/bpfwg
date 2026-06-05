#include <linux/bits.h>
#include <linux/if_ether.h>

#define MTK_HDR_LEN                     4
#define MTK_HDR_XMIT_UNTAGGED           0
#define MTK_HDR_RECV_SOURCE_PORT_MASK   __GENMASK(2, 0)
#define MTK_HDR_XMIT_DP_BIT_MASK        __GENMASK(5, 0)

struct mtkhdr {
    __u8   h_dest[ETH_ALEN];
    __u8   h_source[ETH_ALEN];
    __u8   h_tag[MTK_HDR_LEN];
    __be16 h_proto;
} __attribute__((packed));

__always_inline static
bool parse_mtk_header(struct packet_data *pkt, struct l2_header *l2)
{
    struct mtkhdr *mtkh;
    __u32 dsa_port;

    __parse_eth_header(mtkh, pkt, l2);

    dsa_port = mtkh->h_tag[1] & MTK_HDR_RECV_SOURCE_PORT_MASK;
    if (dsa_port >= BPFWG_DSA_MAX_PORTS)
        return false;

    pkt->ifindex = dsa.port_to_ifindex[dsa_port];

    return true;
}

__always_inline static
__s32 push_mtk_header(struct mtkhdr *mtkh, struct packet_data *pkt, struct bpf_fib_lookup *fib)
{
    __u32 dsa_port, index;

    index = fib->ifindex - dsa.ifindex_base;
    if (index >= BPFWG_DSA_MAX_PORTS)
        return -1;

    dsa_port = dsa.ifindex_to_port[index];

    __push_eth_header(mtkh, pkt, fib);
    mtkh->h_tag[0] = MTK_HDR_XMIT_UNTAGGED;
    mtkh->h_tag[1] = (1 << dsa_port) & MTK_HDR_XMIT_DP_BIT_MASK;
    mtkh->h_tag[2] = 0;
    mtkh->h_tag[3] = 0;

    return dsa.switch_ifindex;
}

__always_inline static
void restore_mtk_header(struct packet_data *pkt, __u16 offset)
{
    memmove(pkt->data + offset, pkt->data, sizeof(struct mtkhdr));
}
