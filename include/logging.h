// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2014 IBM Corp. */

#ifndef __LOGGING_H
#define __LOGGING_H

#include <types.h>

#define REG		"%016llx"

/* Console logging
 * Update console_get_level() if you add here
 */
#define PR_EMERG        0
#define PR_ALERT        1
#define PR_CRIT         2
#define PR_ERR          3
#define PR_WARNING      4
#define PR_NOTICE       5
#define PR_PRINTF       PR_NOTICE
#define PR_INFO         6
#define PR_DEBUG        7
#define PR_TRACE        8
#define PR_INSANE       9

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

void _prlog(int log_level, const char* fmt, ...) __attribute__((format (printf, 2, 3)));
#define prlog(l, f, ...) do { _prlog(l, pr_fmt(f), ##__VA_ARGS__); } while(0)
/*
 * Prepend just one character 'E' for error messages, 'D' for debug
 * messages, "N" for notice messages.  This will conserve the
 * ultravisor log space, without compromising information.
 */
#define pr_error(fmt...) do { prlog(PR_ERR, "E: "fmt); } while(0)
#define pr_debug(fmt...) do { prlog(PR_DEBUG, "D: "fmt); } while(0)
#define pr_info(fmt...) do { prlog(PR_INFO, fmt); } while(0)
#define pr_notice(fmt...) do { prlog(PR_NOTICE, "N: "fmt); } while(0)
#define pr_warn(fmt...) do { prlog(PR_WARNING, "W: "fmt); } while(0)
#define prlog_once(arg, ...)                    \
({                                              \
        static bool __prlog_once = false;       \
        if (!__prlog_once) {                    \
                __prlog_once = true;            \
                prlog(arg, ##__VA_ARGS__);      \
        }                                       \
})
#define pr_error_once(fmt...) do { prlog_once(PR_ERR, "E: "fmt); } while(0)
#define pr_debug_once(fmt...) do { prlog_once(PR_DEBUG, "D: "fmt); } while(0)
#define pr_info_once(fmt...) do { prlog_once(PR_INFO, fmt); } while(0)
#define pr_notice_once(fmt...) do { prlog_once(PR_NOTICE, "N: "fmt); } while(0)
#define pr_warn_once(fmt...) do { prlog_once(PR_WARNING, "W: "fmt); } while(0)

struct debug_descriptor {
        u8      eye_catcher[8]; /* "OPALdbug" */
#define DEBUG_DESC_VERSION      1
        u32     version;
        u8      console_log_levels;     /* high 4 bits in memory,
                                         * low 4 bits driver (e.g. uart). */
        u8      state_flags; /* various state flags - OPAL_BOOT_COMPLETE etc */
        u16     reserved2;
        u32     reserved[2];

        /* Memory console */
        u64     memcons_phys;
        u32     memcons_tce;
        u32     memcons_obuf_tce;
        u32     memcons_ibuf_tce;

        /* Traces */
        u64     trace_mask;
        u32     num_traces;
#define DEBUG_DESC_MAX_TRACES   256
        u64     trace_phys[DEBUG_DESC_MAX_TRACES];
        u32     trace_size[DEBUG_DESC_MAX_TRACES];
        u32     trace_tce[DEBUG_DESC_MAX_TRACES];
};
extern struct debug_descriptor debug_descriptor;

#ifdef DEBUG_NUMA
#define pr_numa_debug(f, ...) do { prlog(PR_DEBUG, f, ##__VA_ARGS__); } while(0)
#else
#define pr_numa_debug(f, ...) do {} while(0)
#endif

#endif /* __LOGGING_H */
