#include "args.h"

#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"


#if BYTE_ORDER == LITTLE_ENDIAN
    #define DEFAULT_BPF_OBJECT_PATH    "./wg_le.o"
#elif BYTE_ORDER == BIG_ENDIAN
    #define DEFAULT_BPF_OBJECT_PATH    "./wg_be.o"
#endif

static void print_usage(char* prog) {
    bpfwg_error("Usage: %s <hook> [network_interface(s)...] [options]\n\n", prog);

    bpfwg_error("Options:\n");
    bpfwg_error("  -l, --log-level      Log level, can be error, warning, info, debug, verbose (Default: info).\n");
    bpfwg_error("  -e  --exclude-cpus CPU[,CPU-RANGE...]  Exclude CPUs from RSS selection, e.g. 0,1,4-7.\n");

    bpfwg_error("All possible hooks to attach the BPF program are listed below:\n");
    bpfwg_error("  tc            TC hoook\n");
    bpfwg_error("  xdp           XDP hook\n");
    bpfwg_error("  xdpgeneric    Generic/SKB XDP hook\n");
    bpfwg_error("  xdpnative     Native/Driver XDP hook\n");
    bpfwg_error("  xdpoffload    XDP offloaded into hardware\n");
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

static enum dsa_proto parse_dsa_proto(const char *dsa_str) {
    if (!strcmp(dsa_str, "mtk"))
        return DSA_PROTO_MTK;

    bpfwg_error("Unsupported DSA protocol '%s'. \n\n", dsa_str);
    return DSA_PROTO_NONE;
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
static bool parse_cmd_args(int argc, char* argv[], struct cmd_args *args) {
    int opt, opt_index;

    struct option options[] = {
        { "conntrack",    no_argument,       0, 'c' },
        { "dsa",          required_argument, 0, 'd' },
        { "exclude-cpus", required_argument, 0, 'e' },
        { "log-level",    required_argument, 0, 'l' },
        { "object",       required_argument, 0, 'o' },
        { "rss",          required_argument, 0, 'r' },
        { "udp",          no_argument,       0, 'u' },
        { 0,              0,                 0,  0  }
    };

    while ((opt = getopt_long(argc, argv, "cd:e:l:o:r:u", options, &opt_index)) != -1) {
        switch (opt) {
            case 'c':
                args->config.conntrack = true;
            break;

            case 'd':
                args->config.dsa_proto = parse_dsa_proto(optarg);
                if (args->config.dsa_proto == DSA_PROTO_NONE)
                    return false;
            break;

            case 'e':
                if (!parse_cpu_list(optarg, &args->rss_excluded_cpus))
                    return false;
            break;

            case 'l':
                if (!parse_log_level(optarg))
                    return false;
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
                return false;
        }
    }

    // Check if the hook is provided in the command line
    if (argc - optind < 2) {
        bpfwg_error("Missing hook argument.\n\n");
        return false;
    }

    // Check the hook argument
    args->hook = parse_hook(argv[optind]);
    if (!args->hook)
        return false;

    // Check if network interface(s) are provided in the command line
    if (argc - optind < 1) {
        bpfwg_error("Missing network interface(s).\n\n");
        return false;
    }

    args->ifaces = &argv[optind + 1];
    args->ifaces_count = argc - optind - 1;

    if (args->rss_excluded_cpus.count && !args->rss_prog_name) {
        bpfwg_error("--exclude-cpus requires --rss.\n\n");
        return false;
    }

    return true;
}

int check_cmd_args(int argc, char* argv[], struct cmd_args *args) {
    args->hook = BPF_HOOK_AUTO;

    args->bpf_obj_path = DEFAULT_BPF_OBJECT_PATH;
    args->rss_prog_name = NULL;
    args->rss_excluded_cpus.cpus = NULL;
    args->rss_excluded_cpus.count = 0;

    args->config.dsa_proto = DSA_PROTO_NONE;
    args->config.conntrack = false;
    args->config.udp_nocheck = false;

    // Check if the arguments are provided correctly
    if (!parse_cmd_args(argc, argv, args)) {
        print_usage(argv[0]);
        return BPFWG_RC_ERR;
    }

    return BPFWG_RC_OK;
}

void free_cmd_args(struct cmd_args *args) {
    free(args->rss_excluded_cpus.cpus);
}
