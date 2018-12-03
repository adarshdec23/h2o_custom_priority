#ifndef h2o__http2_schedmode_h
#define h2o__http2_schedmode_h

typedef enum en_sched_mode_t {
    /**
     * In this (default) scheduling mode, H2O will adhere to the HTTP/2
     * prioritization directives as specified by the user agent.
     */
    SCHED_MODE_FLAG_H2_PRIO_AWARE = 0,
    /**
     * In this scheduling mode (which can be set via the
     * <tt>--sched fcfs</tt> command-line argument), H2O will neglect any
     * HTTP/2 prioritization directives specified by the user agent and
     * instead will serve incoming HTTP requests in a
     * First-Come-First-Served fashion.
     */
    SCHED_MODE_FLAG_FCFS,
    /**
     * In this scheduling mode (which can be set via the
     * <tt>--sched rr</tt> command-line argument), H2O will neglect any
     * HTTP/2 prioritization directives specified by the user agent and
     * instead will serve incoming HTTP requests in a completely fair 
     * Round-Robin fashion (i.e., all outstanding HTTP requests will 
     * be allocated equal portions of server-side network bandwidth).
     */
    SCHED_MODE_FLAG_RR,
} sched_mode_t;

/**
 * The employed scheduling mode.
 */
extern sched_mode_t H2O_SCHEDULING_MODE;

/* inline definitions */

static inline size_t SCHED_MODE_H2_PRIO_AWARE(void)
{
    return (H2O_SCHEDULING_MODE == SCHED_MODE_FLAG_H2_PRIO_AWARE ? 1 : 0);
}

static inline size_t SCHED_MODE_H2_PRIO_UNAWARE(void)
{
    return (SCHED_MODE_H2_PRIO_AWARE() ? 0 : 1);
}

#endif

