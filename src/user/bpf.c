#include "bpf.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/if_link.h>
#include <net/if.h>

#include "log.h"


struct bpf_rss_program {
    struct bpf_object *obj;
    struct bpf_program *prog;
    __u32 ifindex;
    int prog_fd;
    bool attached;
};

struct bpf_tc_link {
    __u32 ifindex;
    struct bpf_link *link;
};

struct bpf_handle {
    /* BPF object/program pointers */
    struct bpf_object *obj;

    struct bpf_rss_program *rss;
    unsigned int rss_count;
    const char *rss_prog_name;
    struct bpfwg_cpu_list excluded_cpus;
    __u32 *allowed_cpus;
    __u32 allowed_cpu_count;

    struct bpfwg_dsa dsa_config;

    const char *obj_path;
    
    /* BPF program file descriptors */
    int xdp_prog_fd;
    int cpumap_prog_fd;
    struct bpf_program *tc_prog;

    struct bpf_tc_link *tc_links;
    unsigned int tc_links_count;

    __u32 cpu_count;
    bool dsa_enabled;
    bool rss_enabled;
    bool rss_only;
    bool rss_prepared;
    bool obj_loaded;
};


static __u32 get_xdp_flag(enum bpf_hook hook) {
    switch (hook) {
        case BPF_HOOK_XDP_GENERIC:
            return XDP_FLAGS_SKB_MODE;
        case BPF_HOOK_XDP_NATIVE:
            return XDP_FLAGS_DRV_MODE;
        case BPF_HOOK_XDP_OFFLOAD:
            return XDP_FLAGS_HW_MODE;
        default:
            return 0;
    }
}

static const char *get_xdp_str(__u32 xdp_flag) {
    switch (xdp_flag) {
        case XDP_FLAGS_HW_MODE:
            return "XDP Offload";
        case XDP_FLAGS_DRV_MODE:
            return "XDP Native";
        case XDP_FLAGS_SKB_MODE:
            return "XDP Generic";
        default:
            return "XDP";
    }
}


static void libbpf_enable_messages(libbpf_print_fn_t fn) {
    libbpf_set_print(fn);
}

static libbpf_print_fn_t libbpf_disable_messages() {
    return libbpf_set_print(NULL);
}

static int bpf_get_program_fd(struct bpf_object *obj, const char *prog_name) {
    struct bpf_program *prog;

    prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        bpfwg_error("Couldn't find BPF program %s\n", prog_name);
        return BPFWG_RC_ERR;
    }

    return bpf_program__fd(prog);
}

static void *bpf_get_section_data(struct bpf_object *obj, const char *sec_name, size_t sec_size_exp) {
    struct bpf_map *section;
    size_t section_size;
    void *section_data;

    // Find the .rodata section
    section = bpf_object__find_map_by_name(obj, sec_name);
    if (!section) {
        bpfwg_error("Error: Couldn't find BPF section %s.\n", sec_name);
        return NULL;
    }

    section_data = bpf_map__initial_value(section, &section_size);
    if (!section_data || sec_size_exp && sec_size_exp != section_size) {
        bpfwg_error("Error: Failed to get data from BPF section %s.\n", sec_name);
        return NULL;
    }

    return section_data;
}

static int bpf_set_dsa_config_obj(struct bpf_object *obj, const struct bpfwg_dsa *cfg) {
    struct bpfwg_dsa *dsa;

    dsa = bpf_get_section_data(obj, BPFWG_DSA_SECTION, sizeof(*dsa));
    if (!dsa)
        return BPFWG_RC_ERR;

    memcpy(dsa, cfg, sizeof(*dsa));
    return BPFWG_RC_OK;
}

static void bpf_object_close(struct bpf_object *obj) {
    if (!obj)
        return;

    // Unpin the maps from /sys/fs/bpf
    bpf_object__unpin_maps(obj, NULL);
    bpf_object__close(obj);
}

static int bpf_set_programs_autoload(struct bpf_object *obj, const char *prog_name_a,
                                     const char *prog_name_b) {
    struct bpf_program *prog;
    const char *prog_name;
    bool autoload;

    bpf_object__for_each_program(prog, obj) {
        prog_name = bpf_program__name(prog);
        autoload = (prog_name_a && !strcmp(prog_name, prog_name_a)) ||
                   (prog_name_b && !strcmp(prog_name, prog_name_b));

        if (bpf_program__set_autoload(prog, autoload) != 0) {
            bpfwg_error("Error setting autoload for BPF program %s: %s (-%d).\n",
                prog_name, strerror(errno), errno);
            return BPFWG_RC_ERR;
        }
    }

    return BPFWG_RC_OK;
}

static int bpf_get_cpu_count(__u32 *cpu_count) {
    int num_cpus;

    num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0) {
        bpfwg_error("Error getting number of CPUs: %s (-%d).\n",
            strerror(-num_cpus), -num_cpus);
        return BPFWG_RC_ERR;
    }

    *cpu_count = num_cpus;
    return BPFWG_RC_OK;
}

static bool bpf_cpu_list_contains(const struct bpfwg_cpu_list *cpus, __u32 cpu) {
    unsigned int i;

    for (i = 0; i < cpus->count; i++)
        if (cpus->cpus[i] == cpu)
            return true;

    return false;
}

static int bpf_copy_cpu_list(struct bpfwg_cpu_list *dst, const struct bpfwg_cpu_list *src) {
    memset(dst, 0, sizeof(*dst));

    if (!src || !src->count)
        return BPFWG_RC_OK;

    dst->cpus = (unsigned int *)malloc(src->count * sizeof(*dst->cpus));
    if (!dst->cpus) {
        bpfwg_error("Error allocating RSS excluded CPU list: %s (-%d).\n",
            strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    memcpy(dst->cpus, src->cpus, src->count * sizeof(*dst->cpus));
    dst->count = src->count;

    return BPFWG_RC_OK;
}

static int bpf_build_allowed_cpus(struct bpf_handle *bpf) {
    __u32 cpu;
    unsigned int i;

    for (i = 0; i < bpf->excluded_cpus.count; i++) {
        if (bpf->excluded_cpus.cpus[i] >= bpf->cpu_count) {
            bpfwg_error("RSS excluded CPU %u is out of range; system has %u possible CPUs.\n",
                bpf->excluded_cpus.cpus[i], bpf->cpu_count);
            return BPFWG_RC_ERR;
        }
    }

    bpf->allowed_cpus = (__u32 *)calloc(bpf->cpu_count, sizeof(*bpf->allowed_cpus));
    if (!bpf->allowed_cpus) {
        bpfwg_error("Error allocating RSS allowed CPU list: %s (-%d).\n",
            strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    for (cpu = 0; cpu < bpf->cpu_count; cpu++) {
        if (!bpf_cpu_list_contains(&bpf->excluded_cpus, cpu))
            bpf->allowed_cpus[bpf->allowed_cpu_count++] = cpu;
    }

    if (!bpf->allowed_cpu_count) {
        bpfwg_error("RSS CPU policy excludes all possible CPUs.\n");
        return BPFWG_RC_ERR;
    }

    return BPFWG_RC_OK;
}

static int bpf_prepare_cpu_map(struct bpf_object *obj, __u32 cpu_count, bool rss_only) {
    struct bpf_map *cpu_map;

    cpu_map = bpf_object__find_map_by_name(obj, BPFWG_RSS_CPU_MAP_NAME);
    if (!cpu_map) {
        bpfwg_error("Error: Couldn't find BPF map %s.\n", BPFWG_RSS_CPU_MAP_NAME);
        return BPFWG_RC_ERR;
    }

    if (rss_only && bpf_map__set_value_size(cpu_map, sizeof(__u32)) != 0) {
        bpfwg_error("Error setting %s value size: %s (-%d).\n",
            BPFWG_RSS_CPU_MAP_NAME, strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    if (bpf_map__set_max_entries(cpu_map, cpu_count) != 0) {
        bpfwg_error("Error setting %s max entries: %s (-%d).\n",
            BPFWG_RSS_CPU_MAP_NAME, strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    return BPFWG_RC_OK;
}

static int bpf_set_rss_config(struct bpf_object *obj, const struct bpf_handle *bpf) {
    struct bpfwg_rss *rss;
    __u32 key;

    if (!bpf->allowed_cpu_count) {
        bpfwg_error("RSS CPU policy has no allowed CPUs.\n");
        return BPFWG_RC_ERR;
    }

    rss = bpf_get_section_data(obj, BPFWG_RSS_SECTION, sizeof(*rss));
    if (!rss)
        return BPFWG_RC_ERR;

    rss->cpu_count = bpf->allowed_cpu_count;
    for (key = 0; key < BPFWG_RSS_INDIR_SIZE; key++)
        rss->indir[key] = bpf->allowed_cpus[key % bpf->allowed_cpu_count];

    return BPFWG_RC_OK;
}

static int bpf_prepare_main_object(struct bpf_handle *bpf) {
    struct bpf_program *cpumap_prog;
    struct bpf_program *tc_prog;

    tc_prog = bpf_object__find_program_by_name(bpf->obj, BPFWG_TC_PROG_NAME);
    if (tc_prog)
        bpf_program__set_expected_attach_type(tc_prog, BPF_TCX_INGRESS);

    if (!bpf->rss_enabled)
        return bpf_set_programs_autoload(bpf->obj, BPFWG_XDP_PROG_NAME,
            BPFWG_TC_PROG_NAME);

    if (!bpf->rss_only) {
        if (bpf_set_programs_autoload(bpf->obj, BPFWG_XDP_CPUMAP_PROG_NAME, NULL)
                != BPFWG_RC_OK)
            return BPFWG_RC_ERR;

        cpumap_prog = bpf_object__find_program_by_name(bpf->obj,
            BPFWG_XDP_CPUMAP_PROG_NAME);
        if (!cpumap_prog) {
            bpfwg_error("Error finding BPF program %s: %s (-%d).\n",
                BPFWG_XDP_CPUMAP_PROG_NAME, strerror(errno), errno);
            return BPFWG_RC_ERR;
        }

        if (bpf_program__set_expected_attach_type(cpumap_prog, BPF_XDP_CPUMAP) != 0) {
            bpfwg_error("Couldn't set expected attach type 'BPF_XDP_CPUMAP' for BPF program %s: %s (-%d).\n",
                BPFWG_XDP_CPUMAP_PROG_NAME, strerror(errno), errno);
            return BPFWG_RC_ERR;
        }
    }
    else if (bpf_set_programs_autoload(bpf->obj, NULL, NULL) != BPFWG_RC_OK)
        return BPFWG_RC_ERR;

    if (bpf_prepare_cpu_map(bpf->obj, bpf->cpu_count, bpf->rss_only) != BPFWG_RC_OK)
        return BPFWG_RC_ERR;

    return bpf_set_rss_config(bpf->obj, bpf);
}

static int bpf_populate_cpu_map(struct bpf_handle *bpf) {
    struct bpf_cpumap_val cpu_map_val;
    int cpu_map_fd;
    __u32 cpu_id;
    unsigned int i;

    cpu_map_fd = bpf_object__find_map_fd_by_name(bpf->obj, BPFWG_RSS_CPU_MAP_NAME);
    if (cpu_map_fd < 0) {
        bpfwg_error("Error: Couldn't find BPF map %s.\n", BPFWG_RSS_CPU_MAP_NAME);
        return BPFWG_RC_ERR;
    }

    memset(&cpu_map_val, 0, sizeof(cpu_map_val));
    cpu_map_val.bpf_prog.fd = !bpf->rss_only ? bpf->cpumap_prog_fd : 0;
    cpu_map_val.qsize = BPFWG_RSS_CPU_MAP_QUEUE_SIZE;

    for (i = 0; i < bpf->allowed_cpu_count; i++) {
        cpu_id = bpf->allowed_cpus[i];

        if (bpf_map_update_elem(cpu_map_fd, &cpu_id, &cpu_map_val, BPF_ANY) != 0) {
            bpfwg_error("Error updating CPU map entry: %s (-%d).\n",
                strerror(errno), errno);
            return BPFWG_RC_ERR;
        }
    }

    return BPFWG_RC_OK;
}

static int bpf_reuse_map(struct bpf_handle *bpf, struct bpf_object *obj, const char *map_name) {
    struct bpf_map *main_map;
    struct bpf_map *rss_map;

    main_map = bpf_object__find_map_by_name(bpf->obj, map_name);
    rss_map = bpf_object__find_map_by_name(obj, map_name);
    if (!main_map || !rss_map) {
        bpfwg_error("Error: Couldn't find BPF map %s.\n", map_name);
        return BPFWG_RC_ERR;
    }

    if (bpf_map__reuse_fd(rss_map, bpf_map__fd(main_map)) != 0) {
        bpfwg_error("Error reusing BPF map %s: %s (-%d).\n",
            map_name, strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    return BPFWG_RC_OK;
}

static int bpf_load_rss_objects(struct bpf_handle *bpf) {
    unsigned int i;

    for (i = 0; i < bpf->rss_count; i++) {
        if (bpf_reuse_map(bpf, bpf->rss[i].obj, BPFWG_RSS_CPU_MAP_NAME) != BPFWG_RC_OK)
            return BPFWG_RC_ERR;

        if (bpf_object__load(bpf->rss[i].obj) != 0) {
            bpfwg_error_ifindex("Error loading device-bound RSS program for ",
                bpf->rss[i].ifindex, errno);
            return BPFWG_RC_ERR;
        }

        bpf->rss[i].prog_fd = bpf_program__fd(bpf->rss[i].prog);
        if (bpf->rss[i].prog_fd < 0) {
            bpfwg_error_ifindex("Error getting device-bound RSS program fd for ",
                bpf->rss[i].ifindex, errno);
            return BPFWG_RC_ERR;
        }
    }

    return BPFWG_RC_OK;
}

static int bpf_load_object(struct bpf_handle *bpf) {
    if (bpf_prepare_main_object(bpf) != BPFWG_RC_OK)
        return BPFWG_RC_ERR;

    // Try to load the BPF object into the kernel, return on error
    if (bpf_object__load(bpf->obj) != 0) {
        bpfwg_error("Error loading BPF program into kernel: %s (-%d).\n",
            strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    bpf->obj_loaded = true;

    if (bpf->rss_enabled) {
        if (!bpf->rss_only) {
            bpf->cpumap_prog_fd = bpf_get_program_fd(bpf->obj,
                BPFWG_XDP_CPUMAP_PROG_NAME);

            if (bpf->cpumap_prog_fd < 0)
                return BPFWG_RC_ERR;
        }

        if (bpf_populate_cpu_map(bpf) != BPFWG_RC_OK)
            return BPFWG_RC_ERR;

        return bpf_load_rss_objects(bpf);
    }

    bpf->xdp_prog_fd = bpf_get_program_fd(bpf->obj, BPFWG_XDP_PROG_NAME);
    bpf->tc_prog = bpf_object__find_program_by_name(bpf->obj, BPFWG_TC_PROG_NAME);

    if (bpf->xdp_prog_fd < 0 && !bpf->tc_prog) {
        bpfwg_error("XDP and TC program not found inside the BPF object file.\n");
        return BPFWG_RC_ERR;
    }

    return BPFWG_RC_OK;
}


static int bpf_attach_xdp_fd(__u32 ifindex, int prog_fd, enum bpf_hook hook) {
    const char *xdp_str;
    __u32 xdp_flag;

    xdp_flag = get_xdp_flag(hook);
    xdp_str = get_xdp_str(xdp_flag);

    // Attach the program to the XDP hook
    if (bpf_xdp_attach(ifindex, prog_fd, xdp_flag, NULL) != 0) {
        bpfwg_error_ifindex("Error attaching %s program to ", ifindex, errno, xdp_str);
        return BPFWG_RC_ERR;
    }

    bpfwg_debug_ifindex("  Attached %s hook to ", ifindex, 0, xdp_str);
    return BPFWG_RC_OK;
}

static int bpf_attach_xdp_program(struct bpf_handle *bpf, __u32 ifindex, enum bpf_hook hook) {
    return bpf_attach_xdp_fd(ifindex, bpf->xdp_prog_fd, hook);
}

static void bpf_detach_xdp_program(struct bpf_handle *bpf, __u32 ifindex, enum bpf_hook hook) {
    // Detach the program from the XDP hook
    bpf_xdp_detach(ifindex, get_xdp_flag(hook), NULL);
}

static int bpf_attach_tc_program(struct bpf_handle *bpf, __u32 ifindex) {
    struct bpf_tc_link *new_links;
    struct bpf_link *link;

    // Attach the program to the TCX hook
    link = bpf_program__attach_tcx(bpf->tc_prog, ifindex, NULL);
    if (!link) {
        bpfwg_error_ifindex("Error attaching TCX program to ",
            ifindex, errno);
        return BPFWG_RC_ERR;
    }

    new_links = (struct bpf_tc_link *)realloc(bpf->tc_links, (bpf->tc_links_count + 1) * sizeof(*new_links));
    if (!new_links) {
        bpfwg_error("Error allocating memory for TCX link: %s (-%d).\n", strerror(errno), errno);
        bpf_link__destroy(link);
        return BPFWG_RC_ERR;
    }

    bpf->tc_links = new_links;
    bpf->tc_links[bpf->tc_links_count].ifindex = ifindex;
    bpf->tc_links[bpf->tc_links_count].link = link;
    bpf->tc_links_count++;

    bpfwg_debug_ifindex("  Attached TCX hook to ", ifindex, 0);

    return BPFWG_RC_OK;
}

static void bpf_detach_tc_program(struct bpf_handle *bpf, __u32 ifindex) {
    unsigned int i;

    // Detach the TCX program
    for (i = 0; i < bpf->tc_links_count; i++) {
        if (bpf->tc_links[i].ifindex == ifindex) {
            bpf_link__destroy(bpf->tc_links[i].link);

            bpf->tc_links_count--;
            if (i < bpf->tc_links_count)
                bpf->tc_links[i] = bpf->tc_links[bpf->tc_links_count];
            break;
        }
    }
}


static int bpf_ifindex_attach_program(struct bpf_handle *bpf, __u32 ifindex, enum bpf_hook hook) {
    if (hook & BPF_HOOK_XDP) {
        if (bpf->xdp_prog_fd < 0) {
            bpfwg_error("XDP program not found inside the BPF object file.\n");
            return BPFWG_RC_ERR;
        }

        return bpf_attach_xdp_program(bpf, ifindex, hook);
    }

    if (!bpf->tc_prog) {
        bpfwg_error("TC program not found inside the BPF object file.\n");
        return BPFWG_RC_ERR;
    }

    return bpf_attach_tc_program(bpf, ifindex);
}

static void bpf_ifindex_detach_program(struct bpf_handle* bpf, __u32 ifindex, enum bpf_hook hook) {
    if (hook & BPF_HOOK_XDP) {
        bpf_detach_xdp_program(bpf, ifindex, hook);
        return;
    }

    bpf_detach_tc_program(bpf, ifindex);
}

static int bpf_ifname_attach_program(struct bpf_handle* bpf, char* ifname, enum bpf_hook hook) {
    __u32 ifindex;

    // Get the interface index from the interface name
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        bpfwg_error("Error finding network interface %s: %s (-%d).\n",
            ifname, strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    return bpf_ifindex_attach_program(bpf, ifindex, hook);
}

static int bpf_ifname_detach_program(struct bpf_handle* bpf, char* ifname, enum bpf_hook hook) {
    __u32 ifindex;

    // Get the interface index from the interface name
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        bpfwg_error("Error finding network interface %s: %s (-%d).\n",
            ifname, strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    bpf_ifindex_detach_program(bpf, ifindex, hook);
    return BPFWG_RC_OK;
}

static void bpf_close_rss(struct bpf_handle *bpf) {
    unsigned int i;

    for (i = 0; i < bpf->rss_count; i++)
        bpf_object_close(bpf->rss[i].obj);

    free(bpf->rss);
    bpf->rss = NULL;
    bpf->rss_count = 0;
    bpf->rss_prepared = false;
}

static int bpf_ifindex_prepare_rss(struct bpf_handle *bpf, struct bpf_rss_program *rss,
                                   __u32 ifindex) {
    struct bpf_program *prog;

    memset(rss, 0, sizeof(*rss));
    rss->ifindex = ifindex;
    rss->prog_fd = -1;

    // Try to open the BPF object file, return on error
    rss->obj = bpf_object__open_file(bpf->obj_path, NULL);
    if (!rss->obj) {
        bpfwg_error("Error opening BPF object file %s: %s (-%d).\n",
            bpf->obj_path, strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    if (bpf->dsa_enabled &&
            bpf_set_dsa_config_obj(rss->obj, &bpf->dsa_config) != BPFWG_RC_OK)
        return BPFWG_RC_ERR;

    if (bpf_set_programs_autoload(rss->obj, bpf->rss_prog_name, NULL) != BPFWG_RC_OK)
        return BPFWG_RC_ERR;

    prog = bpf_object__find_program_by_name(rss->obj, bpf->rss_prog_name);
    if (!prog) {
        bpfwg_error("Error finding RSS program %s: %s (-%d).\n",
            bpf->rss_prog_name, strerror(errno), errno);
        return BPFWG_RC_ERR;
    }
    rss->prog = prog;

    bpf_program__set_ifindex(prog, ifindex);
    if (bpf_program__set_flags(prog, BPF_F_XDP_DEV_BOUND_ONLY) != 0) {
        bpfwg_error("Error setting device-bound flag for RSS program %s: %s (-%d).\n",
            bpf->rss_prog_name, strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    if (bpf_prepare_cpu_map(rss->obj, bpf->cpu_count, bpf->rss_only) != BPFWG_RC_OK)
        return BPFWG_RC_ERR;

    if (bpf_set_rss_config(rss->obj, bpf) != BPFWG_RC_OK)
        return BPFWG_RC_ERR;

    return BPFWG_RC_OK;
}

static int bpf_ifname_prepare_rss(struct bpf_handle* bpf, struct bpf_rss_program *rss,
                                  char* ifname) {
    __u32 ifindex;

    // Get the interface index from the interface name
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        bpfwg_error("Error finding network interface %s: %s (-%d).\n",
            ifname, strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    return bpf_ifindex_prepare_rss(bpf, rss, ifindex);
}

static int bpf_prepare_rss(struct bpf_handle *bpf, char *ifaces[], unsigned int ifaces_count) {
    unsigned int i;

    if (bpf->obj_loaded) {
        bpfwg_error("RSS programs must be prepared before loading the BPF object.\n");
        return BPFWG_RC_ERR;
    }

    if (bpf_get_cpu_count(&bpf->cpu_count) != BPFWG_RC_OK)
        return BPFWG_RC_ERR;

    if (bpf_build_allowed_cpus(bpf) != BPFWG_RC_OK)
        return BPFWG_RC_ERR;

    bpf->rss = (struct bpf_rss_program *)calloc(ifaces_count, sizeof(*bpf->rss));
    if (!bpf->rss) {
        bpfwg_error("Error allocating BPF RSS handle: %s (-%d).\n",
            strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    for (i = 0; i < ifaces_count; i++) {
        if (bpf_ifname_prepare_rss(bpf, &bpf->rss[i], ifaces[i]) != BPFWG_RC_OK) {
            bpf->rss_count = i + 1;
            bpf_close_rss(bpf);
            return BPFWG_RC_ERR;
        }
    }

    bpf->rss_count = ifaces_count;
    bpf->rss_prepared = true;

    return BPFWG_RC_OK;
}

static int bpf_validate_rss_hook(enum bpf_hook hook) {
    if (!(hook & BPF_HOOK_XDP)) {
        bpfwg_error("RSS programs require an XDP hook.\n");
        return BPFWG_RC_ERR;
    }

    if (hook == BPF_HOOK_XDP_GENERIC) {
        bpfwg_error("RSS metadata kfuncs require device-backed XDP; use xdp or xdpnative.\n");
        return BPFWG_RC_ERR;
    }

    return BPFWG_RC_OK;
}

static int bpf_attach_rss_programs(struct bpf_handle *bpf, enum bpf_hook hook) {
    unsigned int i;
    int rc;

    for (i = 0; i < bpf->rss_count; i++) {
        rc = bpf_attach_xdp_fd(bpf->rss[i].ifindex, bpf->rss[i].prog_fd, hook);
        if (rc != BPFWG_RC_OK) {
            while (i-- > 0) {
                bpf_detach_xdp_program(bpf, bpf->rss[i].ifindex, hook);
                bpf->rss[i].attached = false;
            }

            return rc;
        }

        bpf->rss[i].attached = true;
    }

    return BPFWG_RC_OK;
}

static void bpf_detach_rss_programs(struct bpf_handle *bpf, enum bpf_hook hook) {
    unsigned int i;

    for (i = 0; i < bpf->rss_count; i++) {
        if (!bpf->rss[i].attached)
            continue;

        bpf_detach_xdp_program(bpf, bpf->rss[i].ifindex, hook);
        bpf->rss[i].attached = false;
    }
}


int bpf_attach_program(struct bpf_handle *bpf, enum bpf_hook hook, char *ifaces[], unsigned int ifaces_count) {
    int i, rc;

    if (bpf->rss_enabled) {
        if (bpf_validate_rss_hook(hook) != BPFWG_RC_OK)
            return BPFWG_RC_ERR;

        if (!bpf->rss_prepared &&
                bpf_prepare_rss(bpf, ifaces, ifaces_count) != BPFWG_RC_OK)
            return BPFWG_RC_ERR;
    }

    if (!bpf->obj_loaded && bpf_load_object(bpf) != BPFWG_RC_OK)
        return BPFWG_RC_ERR;

    if (bpf->rss_enabled)
        return bpf_attach_rss_programs(bpf, hook);

    for (i = 0; i < ifaces_count; i++) {
        rc = bpf_ifname_attach_program(bpf, ifaces[i], hook);

        if (rc != 0) {
            // If an error occured while attaching to one interface, detach all the already attached programs
            while (--i >= 0)
                bpf_ifname_detach_program(bpf, ifaces[i], hook);

            return rc;
        }
    }

    return BPFWG_RC_OK;
}

void bpf_detach_program(struct bpf_handle *bpf, enum bpf_hook hook, char *ifaces[], unsigned int ifaces_count) {
    int i;

    if (bpf->rss_enabled) {
        bpf_detach_rss_programs(bpf, hook);
        return;
    }

    for (i = 0; i < ifaces_count; i++)
        bpf_ifname_detach_program(bpf, ifaces[i], hook);
}

int bpf_init_rss(struct bpf_handle *bpf, const char *rss_prog_name,
                 const struct bpfwg_cpu_list *excluded_cpus, bool rss_only) {
    if (bpf->obj_loaded) {
        bpfwg_error("RSS mode must be enabled before loading the BPF object.\n");
        return BPFWG_RC_ERR;
    }

    if (!bpf_object__find_program_by_name(bpf->obj, rss_prog_name)) {
        bpfwg_error("Error finding RSS program %s: %s (-%d).\n",
            rss_prog_name, strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    if (bpf_copy_cpu_list(&bpf->excluded_cpus, excluded_cpus) != BPFWG_RC_OK)
        return BPFWG_RC_ERR;

    bpf->rss_enabled = true;
    bpf->rss_only = rss_only;
    bpf->rss_prog_name = rss_prog_name;

    return BPFWG_RC_OK;
}

int bpf_set_config(struct bpf_handle *bpf, struct bpfwg_config *cfg) {
    struct bpfwg_config *config;

    config = bpf_get_section_data(bpf->obj, BPFWG_CONFIG_SECTION, sizeof(*config));
    if (!config)
        return BPFWG_RC_ERR;

    memcpy(config, cfg, sizeof(*config));
    return BPFWG_RC_OK;
}

int bpf_set_dsa_config(struct bpf_handle *bpf, const struct bpfwg_dsa *cfg) {
    if (bpf->obj_loaded) {
        bpfwg_error("DSA config must be set before loading the BPF object.\n");
        return BPFWG_RC_ERR;
    }

    memcpy(&bpf->dsa_config, cfg, sizeof(bpf->dsa_config));
    bpf->dsa_enabled = true;

    return bpf_set_dsa_config_obj(bpf->obj, cfg);
}

struct bpf_handle* bpf_init(const char *obj_path) {
    struct bpf_handle *bpf;

    bpf = (struct bpf_handle *)malloc(sizeof(*bpf));
    if (!bpf) {
        bpfwg_error("Error allocating BPF handle: %s (-%d).\n",
            strerror(errno), errno);
        goto error;
    }

    bpf->obj_path = obj_path;
    bpf->obj_loaded = false;

    bpf->rss = NULL;
    bpf->rss_count = 0;
    bpf->rss_prog_name = NULL;
    bpf->excluded_cpus.cpus = NULL;
    bpf->excluded_cpus.count = 0;
    bpf->allowed_cpus = NULL;
    bpf->allowed_cpu_count = 0;
    memset(&bpf->dsa_config, 0, sizeof(bpf->dsa_config));
    bpf->dsa_enabled = false;
    bpf->rss_enabled = false;
    bpf->rss_prepared = false;

    bpf->xdp_prog_fd = -1;
    bpf->cpumap_prog_fd = -1;
    bpf->tc_prog = NULL;
    bpf->tc_links = NULL;
    bpf->tc_links_count = 0;
    bpf->cpu_count = 0;

    // Try to open the BPF object file, return on error
    bpf->obj = bpf_object__open_file(obj_path, NULL);
    if (!bpf->obj) {
        bpfwg_error("Error opening BPF object file %s: %s (-%d).\n",
            obj_path, strerror(errno), errno);
        goto free_bpf;
    }

    return bpf;

free_bpf:
    free(bpf);
error:
    return NULL;
}

void bpf_destroy(struct bpf_handle* bpf) {
    bpf_close_rss(bpf);
    bpf_object_close(bpf->obj);
    free(bpf->excluded_cpus.cpus);
    free(bpf->allowed_cpus);
    free(bpf->tc_links);

    free(bpf);
}
