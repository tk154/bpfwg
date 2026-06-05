#ifndef BPFWG_DSA_USER_H
#define BPFWG_DSA_USER_H

#include "common_user.h"


struct bpfwg_dsa_attach {
    char **ifaces;
    unsigned int ifaces_count;
};

int bpfwg_dsa_prepare(char *ifaces[], unsigned int ifaces_count, bool required,
                      struct bpfwg_dsa *dsa,
                      struct bpfwg_dsa_attach *attach, bool *enabled);
void bpfwg_dsa_attach_free(struct bpfwg_dsa_attach *attach);

#endif
