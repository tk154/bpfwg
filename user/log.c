#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <net/if.h>


static enum bpfwg_log_level log_level = BPFWG_DEFAULT_LOG_LEVEL;

#define LOG_HEAD(level, format)                                      \
    if (log_level < level) return;                                   \
    FILE *log_file = level >= BPFWG_LOG_LEVEL_INFO ? stdout : stderr; \
    do {                                                             \
        va_list args;                                                \
        va_start(args, format);                                      \
        vfprintf(log_file, format, args);                            \
        va_end(args);                                                \
    } while (0);                            

#define LOG_ERROR(error) \
    if (error) fprintf(log_file, ": %s (-%d).\n", strerror(error), error);   \
    else fputc('\n', log_file);


enum bpfwg_log_level bpfwg_get_log_level() {
    return log_level;
}

void bpfwg_set_log_level(enum bpfwg_log_level level) {
    log_level = level;
}

void bpfwg_log(unsigned int level, const char* format, ...) {
    LOG_HEAD(level, format)
}

void bpfwg_log_errno(enum bpfwg_log_level level, int error, const char *prefix, ...) {
    LOG_HEAD(level, prefix)
    fprintf(log_file, ": %s (-%d).\n", strerror(error), error); 
}

void bpfwg_log_ifindex(enum bpfwg_log_level level, unsigned int ifindex, int error, const char *prefix, ...) {
    LOG_HEAD(level, prefix)

    char ifname[IF_NAMESIZE] = "?";
    if_indextoname(ifindex, ifname);
    fputs(ifname, log_file);

    LOG_ERROR(error)
}
