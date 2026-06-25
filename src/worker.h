/* ============================================================
 * SPIFast - worker.h
 * ------------------------------------------------------------
 * Module Dispatcher + Worker.
 * ============================================================ */

#ifndef SPIFAST_WORKER_H
#define SPIFAST_WORKER_H

#include <rte_ring.h>
#include "acl.h"          /* filter_groups, num_groups, MAX_RULES, MAX_GROUPS */

/* ------------------------------------------------------------
 * Hang so cau hinh
 * ------------------------------------------------------------ */
#define NUM_WORKERS    4
#define RING_SIZE      1024
#define HASH_SEED      0
#define RX_BURST_SIZE  32

/* ------------------------------------------------------------
 * Stats per-Worker
 * ------------------------------------------------------------ */
typedef struct {
	volatile uint64_t hit_count[MAX_RULES];
	volatile uint64_t group_hit_count[MAX_GROUPS];
	volatile uint64_t default_drop_count;
	volatile uint64_t total_classified;
} worker_stats_t;

/* ------------------------------------------------------------
 * Dispatcher stats
 * ------------------------------------------------------------ */
typedef struct {
	volatile uint64_t total_rx_pkts;
	volatile uint64_t total_rx_bytes;
	volatile uint64_t ring_drop_count;
	volatile uint64_t non_ipv4_count;
} dispatcher_stats_t;

/* ------------------------------------------------------------
 * Externs
 * ------------------------------------------------------------ */
extern struct rte_ring    *worker_rings[NUM_WORKERS];
extern worker_stats_t      worker_stats[NUM_WORKERS];
extern dispatcher_stats_t  disp_stats;

/* ------------------------------------------------------------
 * API
 * ------------------------------------------------------------ */
int  worker_rings_init(void);
int  dispatcher_run(void *arg);
int  worker_main(void *arg);
void print_final_stats(void);

#endif /* SPIFAST_WORKER_H */
