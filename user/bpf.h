#ifndef BPF_H
#define BPF_H

#include "common_user.h"


// Struct to keep BPF object and program pointers together
struct bpf_handle;

struct bpf_handle* bpf_init(const char* obj_path);
void bpf_destroy(struct bpf_handle *bpf);

int bpf_init_rss(struct bpf_handle *bpf, const char *rss_prog_name,
                 const struct bpfwg_cpu_list *excluded_cpus);
int bpf_set_config(struct bpf_handle *bpf, struct bpfwg_config *cfg);

int bpf_attach_program(struct bpf_handle *bpf, enum bpf_hook hook, char *ifaces[], unsigned int ifaces_count);
void bpf_detach_program(struct bpf_handle *bpf, enum bpf_hook hook, char *ifaces[], unsigned int ifaces_count);

#endif
