/* ============================================================
 * SPIFast - worker.h
 * ------------------------------------------------------------
 * Module Dispatcher + Worker:
 *   - Dispatcher (Master lcore 0): rx_burst, parse 5-tuple,
 *     software hash (rte_jhash), phan tai qua rte_ring.
 *   - Worker (lcore 1-4): dequeue, rte_acl_classify, tra
 *     action_map, thuc thi action, cap nhat stats local.
 *
 * Stats per-Worker (chong data race) duoc export qua
 * worker_stats[] de Master collect va in.
 * ============================================================ */

#ifndef SPIFAST_WORKER_H
#define SPIFAST_WORKER_H

#include <stdint.h>
#include <rte_ring.h>
#include <rte_acl.h>
#include <rte_ether.h>

#include "parser.h"       /* five_tuple_t, action_map_t, MAX_RULES */

/* ------------------------------------------------------------
 * Hang so cau hinh (dong bo voi MASTER_SPEC muc 4.1 / 4.4 / 4.5)
 * ------------------------------------------------------------ */
#define NUM_WORKERS  4
#define RING_SIZE    1024
#define HASH_SEED    0       /* Co dinh, khong sinh ngau nhien (spec 4.5) */
#define RX_BURST_SIZE 32

/* ------------------------------------------------------------
 * Stats per-Worker (chong data race, KHONG share global counter)
 * Master chi READ cac struct nay; Worker chi WRITE cua minh.
 * Voi PCAP vdev (single-run, sequential), volatile la du —
 * khong can rte_atomic voi lock-free ring + lcore-pinned model.
 * ------------------------------------------------------------ */
typedef struct {
	volatile uint64_t hit_count[MAX_RULES];  /* index = userdata-1 */
	volatile uint64_t default_drop_count;
	volatile uint64_t total_classified;
} worker_stats_t;

/* Mang stats toan cuc: worker_stats[worker_id], worker_id = 0..3 */
extern worker_stats_t worker_stats[NUM_WORKERS];

/* ------------------------------------------------------------
 * Dispatcher stats (Master lcore 0)
 * ------------------------------------------------------------ */
typedef struct {
	volatile uint64_t total_rx_pkts;
	volatile uint64_t total_rx_bytes;
	volatile uint64_t ring_drop_count;
	volatile uint64_t non_ipv4_count;
} dispatcher_stats_t;

extern dispatcher_stats_t disp_stats;

/* ------------------------------------------------------------
 * Global extern: rte_ring va ACL context
 * ------------------------------------------------------------ */
extern struct rte_ring *worker_rings[NUM_WORKERS];
extern struct rte_acl_ctx *acl_ctx;

/* ------------------------------------------------------------
 * API
 * ------------------------------------------------------------ */

/**
 * worker_rings_init() - Tao NUM_WORKERS rte_ring (SPSC).
 * Goi tu main() TRUOC khi launch Worker lcore.
 * @return 0 thanh cong, -1 loi.
 */
int worker_rings_init(void);

/**
 * worker_main() - Ham chay tren moi Worker lcore (1-4).
 * @param arg  worker_id (0..3), cast tu (void*)(uintptr_t)i.
 * @return 0 khi ket thuc.
 */
int worker_main(void *arg);

/**
 * dispatcher_run() - Ham chay tren Master lcore (lcore 0).
 * Vong lap vo han: rx_burst -> parse 5-tuple -> hash -> enqueue ring.
 * Thoat khi PCAP doc het (rx_burst tra ve 0 lien tiep).
 */
void dispatcher_run(void);

/**
 * print_final_stats() - In thong ke cuoi cung sau khi tat ca
 * Worker da ket thuc. Goi tu main() sau rte_eal_mp_wait_lcore().
 */
void print_final_stats(void);

#endif /* SPIFAST_WORKER_H */
