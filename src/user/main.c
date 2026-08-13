#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "args.h"
#include "bpf.h"
#include "dsa.h"
#include "log.h"


static void empty_signal_handler(int signal) {}

int main(int argc, char *argv[]) {
    struct bpfwg_dsa_attach dsa_attach = {};
    unsigned int attach_ifaces_count;
    int rc, ret = EXIT_FAILURE;
    bool dsa_enabled = false;
    struct bpf_handle *bpf;
    char **attach_ifaces;
    struct cmd_args args;

    rc = check_cmd_args(argc, argv, &args);
    if (rc == BPFWG_RC_OTHER) {
        ret = EXIT_SUCCESS;
        goto out;
    }
    if (rc != BPFWG_RC_OK)
        goto out;

    if (args.dsa && bpfwg_dsa_prepare(args.ifaces, args.ifaces_count, args.dsa,
            &args.dsa_config, &dsa_attach, &dsa_enabled) != BPFWG_RC_OK)
        goto out;

    if (dsa_enabled) {
        attach_ifaces = dsa_attach.ifaces;
        attach_ifaces_count = dsa_attach.ifaces_count;
    }
    else {
        attach_ifaces = args.ifaces;
        attach_ifaces_count = args.ifaces_count;
    }

    bpfwg_info("Init BPF object and setting config ...\n");

    // Load the BPF object (including program and maps) into the kernel
    bpf = bpf_init(args.bpf_obj_path);
    if (!bpf)
        goto out;

    if (dsa_enabled && bpf_set_dsa_config(bpf, &args.dsa_config) != BPFWG_RC_OK)
        goto bpf_destroy;

    if (bpf_set_config(bpf, &args.config) != BPFWG_RC_OK)
        goto bpf_destroy;

    if (args.rss_prog_name) {
        bpfwg_info("Init BPF RSS ...\n");

        if (bpf_init_rss(bpf, args.rss_prog_name, &args.rss_excluded_cpus, args.rss_only) != BPFWG_RC_OK)
            goto bpf_destroy;
    }

    bpfwg_info("Loading BPF program and attaching to network interfaces ...\n");

    // Attach the program to the specified interface names
    if (bpf_attach_program(bpf, args.hook, attach_ifaces, attach_ifaces_count) != BPFWG_RC_OK)
        goto bpf_destroy;

    signal(SIGINT, empty_signal_handler);
    signal(SIGTERM, empty_signal_handler);

    ret = EXIT_SUCCESS;

    bpfwg_info("Successfully loaded BPF program. Press CTRL+C to unload.\n");
    pause();
    bpfwg_info("\nUnloading ...\n");

    bpf_detach_program(bpf, args.hook, attach_ifaces, attach_ifaces_count);
bpf_destroy:
    bpf_destroy(bpf);
out:
    bpfwg_dsa_attach_free(&dsa_attach);
    free_cmd_args(&args);
    return ret;
}
