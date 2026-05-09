#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "args.h"
#include "bpf.h"
#include "log.h"


static void empty_signal_handler(int signal) {}

int main(int argc, char *argv[]) {
    struct bpf_handle *bpf;
    int ret = EXIT_FAILURE;
    int rc;
    struct cmd_args args = { 0 };

    rc = check_cmd_args(argc, argv, &args);
    if (rc == BPFWG_RC_HELP) {
        ret = EXIT_SUCCESS;
        goto out;
    }
    if (rc != BPFWG_RC_OK)
        goto out;

    bpfwg_info("Init BPF object and setting config ...\n");

    // Load the BPF object (including program and maps) into the kernel
    bpf = bpf_init(args.bpf_obj_path);
    if (!bpf)
        goto out;

    if (bpf_set_config(bpf, &args.config) != BPFWG_RC_OK)
        goto bpf_destroy;

    if (args.rss_prog_name) {
        bpfwg_info("Init BPF RSS ...\n");

        if (bpf_init_rss(bpf, args.rss_prog_name, &args.rss_excluded_cpus) != BPFWG_RC_OK)
            goto bpf_destroy;
    }

    bpfwg_info("Loading BPF program and attaching to network interfaces ...\n");

    // Attach the program to the specified interface names
    if (bpf_attach_program(bpf, args.hook, args.ifaces, args.ifaces_count) != BPFWG_RC_OK)
        goto bpf_destroy;

    signal(SIGINT, empty_signal_handler);
    signal(SIGTERM, empty_signal_handler);

    ret = EXIT_SUCCESS;

    bpfwg_info("Successfully loaded BPF program. Press CTRL+C to unload.\n");
    pause();
    bpfwg_info("\nUnloading ...\n");

    bpf_detach_program(bpf, args.hook, args.ifaces, args.ifaces_count);
bpf_destroy:
    bpf_destroy(bpf);
out:
    free_cmd_args(&args);
    return ret;
}
