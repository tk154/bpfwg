#ifndef ARGS_H
#define ARGS_H

#include "common_user.h"


struct cmd_args {
    char *bpf_obj_path;
    char *rss_prog_name;

    char **ifaces;
    unsigned int ifaces_count;

    enum bpf_hook hook;
    struct bpfwg_config config;
    struct bpfwg_dsa dsa_config;
    struct bpfwg_cpu_list rss_excluded_cpus;
    bool dsa, rss_only;
};

int check_cmd_args(int argc, char *argv[], struct cmd_args *args);
void free_cmd_args(struct cmd_args *args);

#endif
