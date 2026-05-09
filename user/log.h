#ifndef LOG_H
#define LOG_H

#include "common_user.h"


enum bpfwg_log_level {
    BPFWG_LOG_LEVEL_ERROR,
    BPFWG_LOG_LEVEL_WARN,
    BPFWG_LOG_LEVEL_INFO,
    BPFWG_LOG_LEVEL_DEBUG,
    BPFWG_LOG_LEVEL_VERBOSE
};


#define BPFWG_DEFAULT_LOG_LEVEL BPFWG_LOG_LEVEL_INFO

#define bpfwg_error(format, ...)   bpfwg_log(BPFWG_LOG_LEVEL_ERROR,   format, ##__VA_ARGS__)
#define bpfwg_warn(format, ...)    bpfwg_log(BPFWG_LOG_LEVEL_WARN,    format, ##__VA_ARGS__)
#define bpfwg_info(format, ...)    bpfwg_log(BPFWG_LOG_LEVEL_INFO,    format, ##__VA_ARGS__)
#define bpfwg_debug(format, ...)   bpfwg_log(BPFWG_LOG_LEVEL_DEBUG,   format, ##__VA_ARGS__)
#define bpfwg_verbose(format, ...) bpfwg_log(BPFWG_LOG_LEVEL_VERBOSE, format, ##__VA_ARGS__)

#define bpfwg_errno(prefix, error, ...) bpfwg_log_errno(BPFWG_LOG_LEVEL_ERROR, error, prefix, ##__VA_ARGS__)

#define bpfwg_error_ifindex(prefix, ifindex, error, ...)   bpfwg_log_ifindex(BPFWG_LOG_LEVEL_ERROR,   ifindex, error, prefix, ##__VA_ARGS__)
#define bpfwg_warn_ifindex(prefix, ifindex, error, ...)    bpfwg_log_ifindex(BPFWG_LOG_LEVEL_WARN,    ifindex, error, prefix, ##__VA_ARGS__)
#define bpfwg_debug_ifindex(prefix, ifindex, error, ...)   bpfwg_log_ifindex(BPFWG_LOG_LEVEL_DEBUG,   ifindex, error, prefix, ##__VA_ARGS__)
#define bpfwg_verbose_ifindex(prefix, ifindex, error, ...) bpfwg_log_ifindex(BPFWG_LOG_LEVEL_VERBOSE, ifindex, error, prefix, ##__VA_ARGS__)

#define bpfwg_error_ip(prefix, ip, family, error, ...) bpfwg_log_ip(BPFWG_LOG_LEVEL_ERROR, ip, family, error, prefix, ##__VA_ARGS__)
#define bpfwg_warn_ip(prefix, ip, family, error, ...)  bpfwg_log_ip(BPFWG_LOG_LEVEL_WARN,  ip, family, error, prefix, ##__VA_ARGS__)
#define bpfwg_debug_ip(prefix, ip, family, error, ...) bpfwg_log_ip(BPFWG_LOG_LEVEL_DEBUG, ip, family, error, prefix, ##__VA_ARGS__)

#define bpfwg_warn_ip_on_ifindex(prefix, ip, family, ifindex, error, ...)  bpfwg_log_ip_on_ifindex(BPFWG_LOG_LEVEL_WARN, ip, family, ifindex, error, prefix, ##__VA_ARGS__)
#define bpfwg_debug_ip_on_ifindex(prefix, ip, family, ifindex, error, ...) bpfwg_log_ip_on_ifindex(BPFWG_LOG_LEVEL_DEBUG, ip, family, ifindex, error, prefix, ##__VA_ARGS__)

#define bpfwg_debug_key(prefix, f_key, ...)             bpfwg_log_key(BPFWG_LOG_LEVEL_DEBUG, f_key, prefix, ##__VA_ARGS__)
#define bpfwg_debug_action(prefix, action, ...)         bpfwg_log_action(BPFWG_LOG_LEVEL_DEBUG, action, prefix, ##__VA_ARGS__)
#define bpfwg_verbose_nat(prefix, n_entry, family, ...) bpfwg_log_nat(BPFWG_LOG_LEVEL_VERBOSE, n_entry, family, prefix, ##__VA_ARGS__)
#define bpfwg_verbose_next_hop(prefix, next_h, ...)     bpfwg_log_next_hop(BPFWG_LOG_LEVEL_VERBOSE, next_h, prefix, ##__VA_ARGS__)
#define bpfwg_verbose_route_type(prefix, rtm_type, ...) bpfwg_log_route_type(BPFWG_LOG_LEVEL_VERBOSE, rtm_type, prefix, ##__VA_ARGS__)
#define bpfwg_debug_rule(prefix, target, name, ...)     bpfwg_log_rule(BPFWG_LOG_LEVEL_DEBUG, prefix, target, name, prefix, ##__VA_ARGS__)


enum bpfwg_log_level bpfwg_get_log_level();
void bpfwg_set_log_level(enum bpfwg_log_level level);

void bpfwg_log(enum bpfwg_log_level level, const char* format, ...);
void bpfwg_log_errno(enum bpfwg_log_level level, int error, const char *prefix, ...);
void bpfwg_log_ifindex(enum bpfwg_log_level level, unsigned int ifindex, int error, const char *prefix, ...);


#endif
