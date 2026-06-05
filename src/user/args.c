#include "args.h"

#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"


#if BYTE_ORDER == LITTLE_ENDIAN
    #define DEFAULT_BPF_OBJECT_PATH    "./wg_le.o"
#elif BYTE_ORDER == BIG_ENDIAN
    #define DEFAULT_BPF_OBJECT_PATH    "./wg_be.o"
#endif

static void print_usage(const char *prog, FILE *out) {
    fprintf(out, "Usage: %s [options] <hook> <network_interface> [network_interface...]\n\n", prog);
    fprintf(out, "Attach the WireGuard eBPF data path to TC ingress or XDP.\n\n");

    fprintf(out, "Hooks:\n");
    fprintf(out, "  tc                 Attach the TC ingress program.\n");
    fprintf(out, "  xdp                Attach the XDP program with automatic mode selection.\n");
    fprintf(out, "  xdpgeneric         Attach XDP in generic/SKB mode.\n");
    fprintf(out, "  xdpnative          Attach XDP in native/driver mode.\n");
    fprintf(out, "  xdpoffload         Attach XDP in hardware offload mode.\n\n");

    fprintf(out, "Options:\n");
    fprintf(out, "  -?, -h, --help                 Show this help text and exit.\n");
    fprintf(out, "  -c, --conntrack                Require conntrack entries before redirecting packets.\n");
    fprintf(out, "  -d, --dsa                      Require DSA discovery and attach to the conduit.\n");
    fprintf(out, "  -e, --exclude-cpus LIST        Exclude CPUs from RSS targets, e.g. 0,1,4-7.\n");
    fprintf(out, "  -l, --log-level LEVEL          Set log level: error, warning, info, debug, verbose.\n");
    fprintf(out, "                                  Default: info.\n");
    fprintf(out, "  -o, --object PATH              BPF object file to load. Default: %s.\n", DEFAULT_BPF_OBJECT_PATH);
    fprintf(out, "  -r, --rss PROGRAM              Enable XDP cpumap RSS with the selected program.\n");
    fprintf(out, "                                  Common values: round_robin, match_port,\n");
    fprintf(out, "                                  tuple_steering, rx_hash.\n");
    fprintf(out, "  -u, --udp                      Disable IPv4 UDP tunnel checksum calculation.\n\n");

    fprintf(out, "Examples:\n");
    fprintf(out, "  %s tc eth0 -o src/kernel/obj/wg_le.o\n", prog);
    fprintf(out, "  %s xdpnative eth0 eth1 -o src/kernel/obj/wg_le.o -r rx_hash -e 0\n", prog);
    fprintf(out, "  %s xdp lan1 -o src/kernel/obj/wg_le.o --conntrack --udp\n", prog);
}

static bool is_help_arg(const char *arg) {
    return !strcmp(arg, "-?") || !strcmp(arg, "-h") || !strcmp(arg, "--help");
}

static enum bpf_hook parse_hook(char* prog_hook) {
    size_t arg_len;

    if (!strcmp(prog_hook, "tc"))
        return BPF_HOOK_TC;
    if (!strcmp(prog_hook, "xdp"))
        return BPF_HOOK_XDP;

    arg_len = strlen(prog_hook);
    if (arg_len < 4)
        goto unknown_hook;

    if (!strncmp(prog_hook, "xdpgeneric", arg_len))
        return BPF_HOOK_XDP_GENERIC;
    if (!strncmp(prog_hook, "xdpnative",  arg_len))
        return BPF_HOOK_XDP_NATIVE;
    if (!strncmp(prog_hook, "xdpoffload", arg_len))
        return BPF_HOOK_XDP_OFFLOAD;

unknown_hook:
    bpfwg_error("Unknown hook '%s'.\n\n", prog_hook);
    return 0;
}

static bool parse_log_level(char* log_level) {
    size_t arg_len = strlen(log_level);

    if (!strncmp(log_level, "error", arg_len))
        bpfwg_set_log_level(BPFWG_LOG_LEVEL_ERROR);
    else if (!strncmp(log_level, "warning", arg_len))
        bpfwg_set_log_level(BPFWG_LOG_LEVEL_WARN);
    else if (!strncmp(log_level, "info", arg_len))
        bpfwg_set_log_level(BPFWG_LOG_LEVEL_INFO);
    else if (!strncmp(log_level, "debug", arg_len))
        bpfwg_set_log_level(BPFWG_LOG_LEVEL_DEBUG);
    else if (!strncmp(log_level, "verbose", arg_len))
        bpfwg_set_log_level(BPFWG_LOG_LEVEL_VERBOSE);
    else {
        bpfwg_error("Unknown log level '%s'.\n\n", log_level);
        return false;
    }

    return true;
}

static bool cpu_list_contains(const struct bpfwg_cpu_list *cpus, unsigned int cpu) {
    unsigned int i;

    for (i = 0; i < cpus->count; i++)
        if (cpus->cpus[i] == cpu)
            return true;

    return false;
}

static bool cpu_list_add(struct bpfwg_cpu_list *cpus, unsigned int cpu) {
    unsigned int *new_cpus;

    if (cpu_list_contains(cpus, cpu))
        return true;

    new_cpus = (unsigned int *)realloc(cpus->cpus,
        (cpus->count + 1) * sizeof(*cpus->cpus));
    if (!new_cpus) {
        bpfwg_error("Error allocating RSS excluded CPU list: %s (-%d).\n",
            strerror(errno), errno);
        return false;
    }

    cpus->cpus = new_cpus;
    cpus->cpus[cpus->count++] = cpu;

    return true;
}

static bool parse_cpu_id(const char *str, char **end, unsigned int *cpu) {
    unsigned long val;

    errno = 0;
    val = strtoul(str, end, 10);
    if (*end == str || errno || val > UINT_MAX)
        return false;

    *cpu = val;
    return true;
}

static bool parse_cpu_list(const char *str, struct bpfwg_cpu_list *cpus) {
    const char *p = str;
    unsigned int start, end, cpu;
    char *next;

    if (!str || !*str)
        goto invalid;

    while (*p) {
        if (!parse_cpu_id(p, &next, &start))
            goto invalid;

        end = start;
        if (*next == '-') {
            p = next + 1;
            if (!parse_cpu_id(p, &next, &end) || end < start)
                goto invalid;
        }

        for (cpu = start; cpu <= end; cpu++) {
            if (!cpu_list_add(cpus, cpu))
                return false;
            if (cpu == UINT_MAX)
                break;
        }

        if (!*next)
            return true;
        if (*next != ',')
            goto invalid;

        p = next + 1;
        if (!*p)
            goto invalid;
    }

    return true;

invalid:
    bpfwg_error("Invalid CPU list '%s'. Expected e.g. 0,1,4-7.\n\n", str);
    return false;
}

// Checks if the given arguments are valid and determines the BPF hook
static int parse_cmd_args(int argc, char* argv[], struct cmd_args *args) {
    int opt, opt_index;
    int i;

    struct option options[] = {
        { "conntrack",    no_argument,       0, 'c' },
        { "dsa",          no_argument,       0, 'd' },
        { "exclude-cpus", required_argument, 0, 'e' },
        { "help",         no_argument,       0, 'h' },
        { "log-level",    required_argument, 0, 'l' },
        { "object",       required_argument, 0, 'o' },
        { "rss",          required_argument, 0, 'r' },
        { "udp",          no_argument,       0, 'u' },
        { 0,              0,                 0,  0  }
    };

    for (i = 1; i < argc; i++) {
        if (is_help_arg(argv[i])) {
            print_usage(argv[0], stdout);
            return BPFWG_RC_HELP;
        }
    }

    while ((opt = getopt_long(argc, argv, "cde:hl:o:r:u?", options, &opt_index)) != -1) {
        switch (opt) {
            case 'c':
                args->config.conntrack = true;
            break;

            case 'd':
                args->dsa = true;
            break;

            case 'e':
                if (!parse_cpu_list(optarg, &args->rss_excluded_cpus))
                    return BPFWG_RC_ERR;
            break;

            case 'h':
                print_usage(argv[0], stdout);
                return BPFWG_RC_HELP;

            case 'l':
                if (!parse_log_level(optarg))
                    return BPFWG_RC_ERR;
            break;

            case 'o':
                args->bpf_obj_path = optarg;
            break;

            case 'r':
                args->rss_prog_name = optarg;
            break;

            case 'u':
                args->config.udp_nocheck = true;
            break;

            case '?':
                return BPFWG_RC_ERR;
        }
    }

    if (argc - optind < 1) {
        bpfwg_error("Missing hook argument.\n\n");
        return BPFWG_RC_ERR;
    }

    args->hook = parse_hook(argv[optind]);
    if (!args->hook)
        return BPFWG_RC_ERR;

    if (argc - optind < 2) {
        bpfwg_error("Missing network interface(s).\n\n");
        return BPFWG_RC_ERR;
    }

    args->ifaces = &argv[optind + 1];
    args->ifaces_count = argc - optind - 1;

    if (args->rss_excluded_cpus.count && !args->rss_prog_name) {
        bpfwg_error("--exclude-cpus requires --rss.\n\n");
        return BPFWG_RC_ERR;
    }

    return BPFWG_RC_OK;
}

int check_cmd_args(int argc, char* argv[], struct cmd_args *args) {
    int rc;

    args->hook = BPF_HOOK_AUTO;

    args->bpf_obj_path = DEFAULT_BPF_OBJECT_PATH;
    args->rss_prog_name = NULL;
    args->rss_excluded_cpus.cpus = NULL;
    args->rss_excluded_cpus.count = 0;

    args->dsa = false;
    args->config.conntrack = false;
    args->config.udp_nocheck = false;
    memset(&args->dsa_config, 0, sizeof(args->dsa_config));

    rc = parse_cmd_args(argc, argv, args);
    if (rc == BPFWG_RC_ERR)
        print_usage(argv[0], stderr);

    return rc;
}

void free_cmd_args(struct cmd_args *args) {
    free(args->rss_excluded_cpus.cpus);
}
