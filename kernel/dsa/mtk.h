#include <linux/bits.h>
#include <linux/if_ether.h>

#define MTK_DSA_SWITCH_IFINDEX  2
#define MTK_DSA_PORTS_OFFSET    4

#define MTK_HDR_LEN		                4
#define MTK_HDR_XMIT_UNTAGGED		    0
#define MTK_HDR_RECV_SOURCE_PORT_MASK	__GENMASK(2, 0)
#define MTK_HDR_XMIT_DP_BIT_MASK	    __GENMASK(5, 0)

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
    __u8 dsa_port;

    __parse_eth_header(mtkh, pkt, l2);
    dsa_port = mtkh->h_tag[1] & MTK_HDR_RECV_SOURCE_PORT_MASK;
    pkt->ifindex = dsa_port + MTK_DSA_PORTS_OFFSET;

    return true;
}

__always_inline static
__u32 push_mtk_header(struct mtkhdr *mtkh, struct packet_data *pkt, struct bpf_fib_lookup *fib)
{
    __u8 dsa_port = fib->ifindex - MTK_DSA_PORTS_OFFSET;

    __push_eth_header(mtkh, pkt, fib);
    mtkh->h_tag[0] = MTK_HDR_XMIT_UNTAGGED;
    mtkh->h_tag[1] = (1 << dsa_port) & MTK_HDR_XMIT_DP_BIT_MASK;
    mtkh->h_tag[2] = 0;
    mtkh->h_tag[3] = 0;

    return MTK_DSA_SWITCH_IFINDEX;
}

__always_inline static
void restore_mtk_header(struct packet_data *pkt, __u16 offset)
{
    memmove(pkt->data + offset, pkt->data, sizeof(struct mtkhdr));
}
