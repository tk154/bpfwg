#include "dsa.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <libmnl/libmnl.h>
#include <net/if.h>

#include "log.h"


struct dsa_link {
    __u32 ifindex;
    __u32 link_ifindex;
    __u32 port;
    bool is_dsa;
    bool has_port;
    char ifname[IF_NAMESIZE];
};

struct dsa_links {
    struct dsa_link *links;
    unsigned int count;
};

struct attr_tb {
    const struct nlattr **attr;
    unsigned int max_type;
};

#define DECLARE_ATTR_TB(name, max) \
    const struct nlattr *name[(max) + 1] = {}; \
    struct attr_tb name ## _tb = { name, (max) }

static int attr_parse_cb(const struct nlattr *attr, void *data) {
    struct attr_tb *tb = data;
    unsigned int type = mnl_attr_get_type(attr);

    if (type <= tb->max_type)
        tb->attr[type] = attr;

    return MNL_CB_OK;
}

static int parse_nested_attr(const struct nlattr *attr, struct attr_tb *tb) {
    return mnl_attr_parse_nested(attr, attr_parse_cb, tb);
}

static int parse_attr(const struct nlmsghdr *nlh, unsigned int offset,
                      struct attr_tb *tb) {
    return mnl_attr_parse(nlh, offset, attr_parse_cb, tb);
}

static char *dup_string(const char *str) {
    size_t len = strlen(str) + 1;
    char *dup = malloc(len);

    if (!dup)
        return NULL;

    memcpy(dup, str, len);
    return dup;
}

static bool parse_phys_port_name(const char *name, __u32 *port) {
    const char *num = name;
    unsigned long val;
    char *end;

    while (*num && (*num < '0' || *num > '9'))
        num++;

    if (!*num)
        return false;

    errno = 0;
    val = strtoul(num, &end, 10);
    if (end == num || errno || val > UINT_MAX)
        return false;

    *port = val;
    return true;
}

static int dsa_links_add(struct dsa_links *links, const struct dsa_link *link) {
    struct dsa_link *new_links;

    new_links = realloc(links->links, (links->count + 1) * sizeof(*links->links));
    if (!new_links) {
        bpfwg_error("Error allocating DSA link list: %s (-%d).\n",
            strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    links->links = new_links;
    links->links[links->count++] = *link;
    return BPFWG_RC_OK;
}

static struct dsa_link *dsa_find_link(struct dsa_links *links, __u32 ifindex) {
    unsigned int i;

    for (i = 0; i < links->count; i++)
        if (links->links[i].ifindex == ifindex)
            return &links->links[i];

    return NULL;
}

static bool dsa_has_ports_on_conduit(struct dsa_links *links, __u32 ifindex) {
    unsigned int i;

    for (i = 0; i < links->count; i++)
        if (links->links[i].is_dsa && links->links[i].link_ifindex == ifindex)
            return true;

    return false;
}

static int dsa_link_cb(const struct nlmsghdr *nlh, void *data) {
    DECLARE_ATTR_TB(ifla, IFLA_MAX);
    DECLARE_ATTR_TB(ifla_info, IFLA_INFO_MAX);
    struct dsa_links *links = data;
    struct ifinfomsg *ifi;
    struct dsa_link link = {};
    const char *kind;
    const char *port_name;

    if (nlh->nlmsg_type != RTM_NEWLINK)
        return MNL_CB_OK;

    ifi = mnl_nlmsg_get_payload(nlh);
    link.ifindex = ifi->ifi_index;

    parse_attr(nlh, sizeof(*ifi), &ifla_tb);

    if (ifla[IFLA_IFNAME])
        snprintf(link.ifname, sizeof(link.ifname), "%s",
            mnl_attr_get_str(ifla[IFLA_IFNAME]));
    else
        snprintf(link.ifname, sizeof(link.ifname), "%u", link.ifindex);

    if (ifla[IFLA_LINK])
        link.link_ifindex = mnl_attr_get_u32(ifla[IFLA_LINK]);

    if (ifla[IFLA_LINKINFO]) {
        parse_nested_attr(ifla[IFLA_LINKINFO], &ifla_info_tb);
        if (ifla_info[IFLA_INFO_KIND]) {
            kind = mnl_attr_get_str(ifla_info[IFLA_INFO_KIND]);
            link.is_dsa = strcmp(kind, "dsa") == 0;
        }
    }

    if (link.is_dsa && ifla[IFLA_PHYS_PORT_NAME]) {
        port_name = mnl_attr_get_str(ifla[IFLA_PHYS_PORT_NAME]);
        link.has_port = parse_phys_port_name(port_name, &link.port);
    }

    return dsa_links_add(links, &link) == BPFWG_RC_OK ? MNL_CB_OK : MNL_CB_ERROR;
}

static int dsa_dump_links(struct dsa_links *links) {
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct mnl_socket *nl;
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifi;
    unsigned int portid;
    unsigned int seq = 1;
    ssize_t nbytes;
    int rc = BPFWG_RC_ERR;
    int cb_rc;

    nl = mnl_socket_open(NETLINK_ROUTE);
    if (!nl) {
        bpfwg_error("Error opening netlink socket: %s (-%d).\n",
            strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) != 0) {
        bpfwg_error("Error binding netlink socket: %s (-%d).\n",
            strerror(errno), errno);
        goto close;
    }

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq;
    ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        bpfwg_error("Error sending netlink link dump request: %s (-%d).\n",
            strerror(errno), errno);
        goto close;
    }

    portid = mnl_socket_get_portid(nl);
    while ((nbytes = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
        cb_rc = mnl_cb_run(buf, nbytes, seq, portid, dsa_link_cb, links);
        if (cb_rc == MNL_CB_ERROR) {
            bpfwg_error("Error parsing netlink link dump: %s (-%d).\n",
                strerror(errno), errno);
            goto close;
        }
        if (cb_rc == MNL_CB_STOP)
            break;
    }

    if (nbytes < 0) {
        bpfwg_error("Error receiving netlink link dump: %s (-%d).\n",
            strerror(errno), errno);
        goto close;
    }

    rc = BPFWG_RC_OK;

close:
    mnl_socket_close(nl);
    return rc;
}

static int dsa_read_tag_proto(__u32 switch_ifindex, char *tag_proto, size_t len) {
    char ifname[IF_NAMESIZE];
    char tag_path[128];
    FILE *tag_file;

    if (!if_indextoname(switch_ifindex, ifname)) {
        bpfwg_error_ifindex("Error resolving DSA conduit name for ",
            switch_ifindex, errno);
        return BPFWG_RC_ERR;
    }

    snprintf(tag_path, sizeof(tag_path), "/sys/class/net/%s/dsa/tagging", ifname);
    tag_file = fopen(tag_path, "r");
    if (!tag_file) {
        bpfwg_error("Error opening '%s': %s (-%d).\n",
            tag_path, strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    if (!fgets(tag_proto, len, tag_file)) {
        bpfwg_error("Error reading '%s': %s (-%d).\n",
            tag_path, strerror(errno), errno);
        fclose(tag_file);
        return BPFWG_RC_ERR;
    }

    tag_proto[strcspn(tag_proto, "\n")] = '\0';
    fclose(tag_file);
    return BPFWG_RC_OK;
}

static int dsa_set_proto(struct bpfwg_dsa *dsa, __u32 switch_ifindex) {
    char tag_proto[64];

    if (dsa_read_tag_proto(switch_ifindex, tag_proto, sizeof(tag_proto))
            != BPFWG_RC_OK)
        return BPFWG_RC_ERR;

    if (!strcmp(tag_proto, "mtk")) {
        dsa->proto = DSA_PROTO_MTK;
        return BPFWG_RC_OK;
    }

    bpfwg_error("Unsupported DSA tag protocol '%s'.\n", tag_proto);
    return BPFWG_RC_ERR;
}

static int dsa_resolve_conduit(struct dsa_links *links, char *ifaces[],
                               unsigned int ifaces_count, bool required,
                               __u32 *switch_ifindex, bool *enabled) {
    struct dsa_link *link;
    __u32 ifindex, candidate;
    bool has_non_dsa = false;
    unsigned int i;

    *enabled = false;

    for (i = 0; i < ifaces_count; i++) {
        ifindex = if_nametoindex(ifaces[i]);
        if (!ifindex) {
            bpfwg_error("Error finding network interface %s: %s (-%d).\n",
                ifaces[i], strerror(errno), errno);
            return BPFWG_RC_ERR;
        }

        link = dsa_find_link(links, ifindex);
        if (!link) {
            bpfwg_error("Couldn't find netlink information for %s.\n", ifaces[i]);
            return BPFWG_RC_ERR;
        }

        if (link->is_dsa) {
            if (!link->link_ifindex) {
                bpfwg_error("DSA interface %s has no conduit link.\n", ifaces[i]);
                return BPFWG_RC_ERR;
            }
            candidate = link->link_ifindex;
        }
        else if (dsa_has_ports_on_conduit(links, ifindex)) {
            candidate = ifindex;
        }
        else {
            has_non_dsa = true;
            continue;
        }

        if (has_non_dsa) {
            bpfwg_error("DSA and non-DSA attach targets cannot be mixed.\n");
            return BPFWG_RC_ERR;
        }

        if (*switch_ifindex && *switch_ifindex != candidate) {
            bpfwg_error("Only one DSA conduit is supported per run.\n");
            return BPFWG_RC_ERR;
        }

        *switch_ifindex = candidate;
        *enabled = true;
    }

    if (*enabled && has_non_dsa) {
        bpfwg_error("DSA and non-DSA attach targets cannot be mixed.\n");
        return BPFWG_RC_ERR;
    }

    if (!*enabled && required) {
        bpfwg_error("No DSA user port or conduit found in attach targets.\n");
        return BPFWG_RC_ERR;
    }

    return BPFWG_RC_OK;
}

static int dsa_build_port_config(struct dsa_links *links, __u32 switch_ifindex,
                                 struct bpfwg_dsa *dsa,
                                 unsigned int *port_count) {
    bool port_seen[BPFWG_DSA_MAX_PORTS] = {};
    struct dsa_link *link;
    __u32 min_ifindex = UINT_MAX;
    __u32 max_ifindex = 0;
    __u32 ifindex;
    __u32 port;
    __u32 index;
    unsigned int i;

    *port_count = 0;

    for (i = 0; i < links->count; i++) {
        link = &links->links[i];
        if (!link->is_dsa || link->link_ifindex != switch_ifindex)
            continue;

        if (!link->has_port) {
            bpfwg_error("DSA interface %s has no usable physical port name.\n",
                link->ifname);
            return BPFWG_RC_ERR;
        }

        if (link->port >= BPFWG_DSA_MAX_PORTS) {
            bpfwg_error("DSA interface %s reports MTK port %u, max supported is %u.\n",
                link->ifname, link->port, BPFWG_DSA_MAX_PORTS - 1);
            return BPFWG_RC_ERR;
        }

        if (port_seen[link->port]) {
            bpfwg_error("Duplicate DSA MTK port %u.\n", link->port);
            return BPFWG_RC_ERR;
        }

        port_seen[link->port] = true;
        dsa->port_to_ifindex[link->port] = link->ifindex;
        (*port_count)++;

        if (link->ifindex < min_ifindex)
            min_ifindex = link->ifindex;
        if (link->ifindex > max_ifindex)
            max_ifindex = link->ifindex;
    }

    if (!*port_count) {
        bpfwg_error("Couldn't find DSA ports for conduit ifindex %u.\n",
            switch_ifindex);
        return BPFWG_RC_ERR;
    }

    if (max_ifindex - min_ifindex >= BPFWG_DSA_MAX_PORTS) {
        bpfwg_error("DSA port ifindexes %u..%u do not fit in the MTK direct lookup table.\n",
            min_ifindex, max_ifindex);
        return BPFWG_RC_ERR;
    }

    dsa->ifindex_base = min_ifindex;

    for (port = 0; port < BPFWG_DSA_MAX_PORTS; port++) {
        ifindex = dsa->port_to_ifindex[port];
        if (!ifindex)
            continue;

        index = ifindex - dsa->ifindex_base;
        dsa->ifindex_to_port[index] = port;
    }

    return BPFWG_RC_OK;
}

static int dsa_build_attach(__u32 switch_ifindex, struct bpfwg_dsa_attach *attach) {
    char ifname[IF_NAMESIZE];

    if (!if_indextoname(switch_ifindex, ifname)) {
        bpfwg_error_ifindex("Error resolving DSA conduit name for ",
            switch_ifindex, errno);
        return BPFWG_RC_ERR;
    }

    attach->ifaces = calloc(1, sizeof(*attach->ifaces));
    if (!attach->ifaces) {
        bpfwg_error("Error allocating DSA attach target: %s (-%d).\n",
            strerror(errno), errno);
        return BPFWG_RC_ERR;
    }

    attach->ifaces[0] = dup_string(ifname);
    if (!attach->ifaces[0]) {
        bpfwg_error("Error allocating DSA attach interface name: %s (-%d).\n",
            strerror(errno), errno);
        free(attach->ifaces);
        attach->ifaces = NULL;
        return BPFWG_RC_ERR;
    }

    attach->ifaces_count = 1;
    return BPFWG_RC_OK;
}

int bpfwg_dsa_prepare(char *ifaces[], unsigned int ifaces_count, bool required,
                      struct bpfwg_dsa *dsa,
                      struct bpfwg_dsa_attach *attach, bool *enabled) {
    struct dsa_links links = {};
    unsigned int port_count = 0;
    __u32 switch_ifindex = 0;
    int rc;

    memset(dsa, 0, sizeof(*dsa));
    memset(attach, 0, sizeof(*attach));
    *enabled = false;

    rc = dsa_dump_links(&links);
    if (rc != BPFWG_RC_OK)
        goto out;

    rc = dsa_resolve_conduit(&links, ifaces, ifaces_count, required,
        &switch_ifindex, enabled);
    if (rc != BPFWG_RC_OK || !*enabled)
        goto out;

    dsa->switch_ifindex = switch_ifindex;

    rc = dsa_set_proto(dsa, switch_ifindex);
    if (rc != BPFWG_RC_OK)
        goto out;

    rc = dsa_build_port_config(&links, switch_ifindex, dsa, &port_count);
    if (rc != BPFWG_RC_OK)
        goto out;

    rc = dsa_build_attach(switch_ifindex, attach);
    if (rc != BPFWG_RC_OK)
        goto out;

    bpfwg_info("DSA: attaching to conduit %s with %u discovered ports.\n",
        attach->ifaces[0], port_count);

out:
    free(links.links);
    return rc;
}

void bpfwg_dsa_attach_free(struct bpfwg_dsa_attach *attach) {
    unsigned int i;

    if (!attach || !attach->ifaces)
        return;

    for (i = 0; i < attach->ifaces_count; i++)
        free(attach->ifaces[i]);

    free(attach->ifaces);
    attach->ifaces = NULL;
    attach->ifaces_count = 0;
}
