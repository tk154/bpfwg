#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <bpf/bpf_helpers.h>

#include "common_kern.h"


#define CHACHA20POLY1305_AUTHTAG_SIZE 16
#define MESSAGE_PADDING_MULTIPLE 16

#define WG_MESSAGE_MINIMUM_LENGTH \
    (sizeof(struct wg_header) + CHACHA20POLY1305_AUTHTAG_SIZE)

#define WG_DECRYPT_MINIMUM_LEN \
    (WG_MESSAGE_MINIMUM_LENGTH + MESSAGE_PADDING_MULTIPLE)

enum wg_action {
    WG_ACTION_DROP = -1,
    WG_ACTION_PASS = 0,
    WG_ACTION_REDIRECT = 1
};

struct wg_device { };
struct wg_peer { };

struct wg_device *
bpf_xdp_wg_device_get_by_index(struct xdp_md *xdp_ctx, __u32 ifindex) __ksym;
struct wg_device *
bpf_xdp_wg_device_get_by_port(struct xdp_md *xdp_ctx, __u16 port) __ksym;

struct wg_device *
bpf_skb_wg_device_get_by_index(struct __sk_buff *skb_ctx, __u32 ifindex) __ksym;
struct wg_device *
bpf_skb_wg_device_get_by_port(struct __sk_buff *skb_ctx, __u16 port) __ksym;

struct wg_peer *
bpf_wg_peer_hashtable_lookup(struct wg_device *wg, __le32 idx) __ksym;
struct wg_peer *
bpf_wg_peer_allowedips_lookup(struct wg_device *wg, const void *addr,
                              __u32 addr__sz) __ksym;

int bpf_wg_endpoint_tuple_get(struct wg_peer *peer, struct bpf_sock_tuple *tuple,
                              __u32 tuple__sz) __ksym;

int bpf_xdp_wg_encrypt(struct xdp_md *xdp_ctx, __u32 offset, __u32 length,
                       struct wg_peer *peer) __ksym;
int bpf_xdp_wg_decrypt(struct xdp_md *xdp_ctx, __u32 offset, __u32 length,
                       struct wg_peer *peer) __ksym;

int bpf_skb_wg_encrypt(struct __sk_buff *skb_ctx, __u32 offset, __u32 length,
                       struct wg_peer *peer) __ksym;
int bpf_skb_wg_decrypt(struct __sk_buff *skb_ctx, __u32 offset, __u32 length,
                       struct wg_peer *peer) __ksym;

void bpf_wg_device_put(struct wg_device *wg) __ksym;
void bpf_wg_peer_put(struct wg_peer *peer) __ksym;


#include "wg_encrypt.h"
#include "wg_decrypt.h"


#endif
