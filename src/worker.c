/* ============================================================
 * SPIFast - worker.c
 * ------------------------------------------------------------
 * Dispatcher (Master lcore 0) va Worker (lcore 1-4).
 * ============================================================ */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_cycles.h>

#include "worker.h"
#include "header_parser.h"
#include "acl.h"

/* ============================================================
 * GLOBAL DEFINITIONS
 * ============================================================ */
struct rte_ring    *worker_rings[NUM_WORKERS];
worker_stats_t      worker_stats[NUM_WORKERS];
dispatcher_stats_t  disp_stats;

/* Force-quit flag — set boi SIGINT handler */
static volatile int force_quit = 0;

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
		force_quit = 1;
}

/* ============================================================
 * worker_rings_init()
 * ============================================================ */
int
worker_rings_init(void)
{
	char ring_name[32];
	unsigned i;

	memset(worker_stats, 0, sizeof(worker_stats));
	memset(&disp_stats, 0, sizeof(disp_stats));

	for (i = 0; i < NUM_WORKERS; i++) {
		snprintf(ring_name, sizeof(ring_name),
			"spifast_ring_%u", i);

		worker_rings[i] = rte_ring_create(
			ring_name,
			RING_SIZE,
			rte_socket_id(),
			RING_F_SP_ENQ | RING_F_SC_DEQ
		);

		if (worker_rings[i] == NULL) {
			fprintf(stderr,
				"[WORKER] Loi: khong the tao ring '%s': %s\n",
				ring_name, rte_strerror(rte_errno));
			return -1;
		}

		printf("[WORKER] Ring '%s' (size=%u, SPSC)\n",
			ring_name, RING_SIZE);
	}

	return 0;
}

/* ============================================================
 * dispatcher_run() — Master lcore 0
 * ============================================================ */
int
dispatcher_run(void *arg __rte_unused)
{
	struct rte_mbuf *mbufs[RX_BURST_SIZE];
	uint16_t nb_rx;
	uint16_t i;

	/* Dang ky SIGINT handler */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	printf("[DISPATCHER] Bat dau rx_burst tren lcore %u\n",
		rte_lcore_id());

	uint64_t tsc_hz       = rte_get_timer_hz();
	uint64_t last_tsc     = rte_get_timer_cycles();
	uint64_t last_rx_pkts = 0;
	uint64_t last_rx_bytes = 0;

	while (!force_quit) {
		nb_rx = rte_eth_rx_burst(0, 0, mbufs, RX_BURST_SIZE);

		if (nb_rx == 0)
			continue;

		/* Cap nhat stats tong Rx */
		disp_stats.total_rx_pkts += nb_rx;
		for (i = 0; i < nb_rx; i++)
			disp_stats.total_rx_bytes +=
				rte_pktmbuf_pkt_len(mbufs[i]);

		/* Xu ly tung mbuf */
		for (i = 0; i < nb_rx; i++) {
			five_tuple_t tuple;
			uint32_t hash_val;
			uint32_t ring_idx;
			int ret;

			/* Parse 5-tuple */
			if (parse_packet_5tuple(mbufs[i], &tuple) < 0) {
				disp_stats.non_ipv4_count++;
				rte_pktmbuf_free(mbufs[i]);
				continue;
			}

			/* Software hash */
			hash_val = rte_jhash(&tuple, sizeof(five_tuple_t),
					     HASH_SEED);
			ring_idx = hash_val % NUM_WORKERS;

			/* Enqueue */
			ret = rte_ring_enqueue(worker_rings[ring_idx],
					       mbufs[i]);
			if (ret != 0) {
				disp_stats.ring_drop_count++;
				rte_pktmbuf_free(mbufs[i]);
			}
		}

		/* --- Stats định kỳ 1 giây --- */
		uint64_t now = rte_get_timer_cycles();
		if (now - last_tsc >= tsc_hz) {
			double delta_s = (double)(now - last_tsc) / (double)tsc_hz;

			uint64_t pkts_interval  = disp_stats.total_rx_pkts  - last_rx_pkts;
			uint64_t bytes_interval = disp_stats.total_rx_bytes - last_rx_bytes;

			/* Throughput và Flow Rate */
			uint64_t mbps = (uint64_t)((double)(bytes_interval * 8)
							/ 1000000.0 / delta_s);
			uint64_t pps  = (uint64_t)((double)pkts_interval / delta_s);

			/* Collect worker stats (snapshot — đọc volatile trực tiếp) */
			uint64_t snap_group[MAX_GROUPS];
			uint64_t snap_default = 0;
			uint64_t snap_classified = 0;
			uint32_t g;
			unsigned w;

			memset(snap_group, 0, sizeof(snap_group));
			for (w = 0; w < NUM_WORKERS; w++) {
				snap_default    += worker_stats[w].default_drop_count;
				snap_classified += worker_stats[w].total_classified;
				for (g = 0; g < num_groups; g++)
					snap_group[g] += worker_stats[w].group_hit_count[g];
			}

			/* Missing Rate */
			uint64_t accounted = snap_classified
							   + disp_stats.non_ipv4_count
							   + disp_stats.ring_drop_count;
			uint64_t missing = (disp_stats.total_rx_pkts > accounted)
							 ? (disp_stats.total_rx_pkts - accounted) : 0;
			uint64_t missing_pct = (disp_stats.total_rx_pkts > 0)
								 ? (missing * 100 / disp_stats.total_rx_pkts)
								 : 0;

			/* Drop Rate (ring full) */
			uint64_t drop_pct = (pkts_interval > 0)
							  ? (disp_stats.ring_drop_count * 100
								 / disp_stats.total_rx_pkts)
							  : 0;

			/* In ra console theo format MASTER_SPEC mục 4.6 */
			printf("\n================= SPI RUNTIME STATS (1s) =================\n");
			printf("Throughput: %lu Mbps | Flow Rate: %lu pps\n", mbps, pps);
			printf("Missing Rate: %lu%% | Packet Drop Rate (Ring full): %lu%%\n",
				   missing_pct, drop_pct);
			printf("----------------------------------------------------------\n");
			for (g = 0; g < num_groups; g++) {
				printf("[Group: %-24s] Hit: %lu pkts | Action: %s\n",
					   filter_groups[g].group_name,
					   snap_group[g],
					   filter_groups[g].action == ACTION_FORWARD
						   ? "FORWARD" : "DROP");
			}
			printf("[Default/Unmatched]              "
				   "Hit: %lu pkts | Action: DROP\n", snap_default);
			printf("==========================================================\n");

			/* Cập nhật baseline cho interval tiếp theo */
			last_tsc      = now;
			last_rx_pkts  = disp_stats.total_rx_pkts;
			last_rx_bytes = disp_stats.total_rx_bytes;
		}
		/* --- Kết thúc stats --- */
	}

	printf("[DISPATCHER] Thoat. Rx: %lu pkts, %lu bytes\n",
		(unsigned long)disp_stats.total_rx_pkts,
		(unsigned long)disp_stats.total_rx_bytes);

	/* Gui NULL sentinel cho moi Worker */
	for (i = 0; i < NUM_WORKERS; i++) {
		while (rte_ring_enqueue(worker_rings[i], NULL) != 0)
			;
	}

	return 0;
}

/* ============================================================
 * worker_main() — Worker lcore 1-4
 * ============================================================ */
int
worker_main(void *arg)
{
	uint32_t worker_id = (uint32_t)(uintptr_t)arg;
	worker_stats_t *stats = &worker_stats[worker_id];
	void *obj;

	printf("[WORKER %u] Bat dau tren lcore %u\n",
		worker_id, rte_lcore_id());

	for (;;) {
		if (rte_ring_dequeue(worker_rings[worker_id], &obj) != 0)
			continue;

		/* NULL sentinel = thoat */
		struct rte_mbuf *mbuf = (struct rte_mbuf *)obj;
		if (mbuf == NULL)
			break;

		/* Parse 5-tuple (NBO tu packet, khong convert) */
		five_tuple_t tuple;
		memset(&tuple, 0, sizeof(tuple));
		if (parse_packet_5tuple(mbuf, &tuple) < 0) {
			rte_pktmbuf_free(mbuf);
			continue;
		}

		/* Classify tuan tu theo precedence */
		const uint8_t *data = (const uint8_t *)&tuple;
		int matched = 0;
		uint32_t g;

		for (g = 0; g < num_groups; g++) {
			uint32_t result = 0;

			if (filter_groups[g].acl_ctx == NULL)
				continue;

			rte_acl_classify(filter_groups[g].acl_ctx,
					 &data, &result, 1, 1);

			if (result != 0) {
				uint32_t global_idx =
					filter_groups[g].global_rule_offset
					+ result - 1;
				stats->hit_count[global_idx]++;
				stats->group_hit_count[g]++;
				stats->total_classified++;
				matched = 1;
				break;
			}
		}

		if (!matched) {
			stats->default_drop_count++;
			stats->total_classified++;
		}

		rte_pktmbuf_free(mbuf);
	}

	printf("[WORKER %u] Ket thuc. Classified: %lu, Default drop: %lu\n",
		worker_id,
		(unsigned long)stats->total_classified,
		(unsigned long)stats->default_drop_count);

	return 0;
}

/* ============================================================
 * print_final_stats()
 * ============================================================ */
void
print_final_stats(void)
{
	uint64_t total_group_hits[MAX_GROUPS];
	uint64_t total_default_drop = 0;
	uint64_t total_classified = 0;
	unsigned i;
	uint32_t g;

	memset(total_group_hits, 0, sizeof(total_group_hits));

	/* Collect tu tat ca Worker */
	for (i = 0; i < NUM_WORKERS; i++) {
		const worker_stats_t *ws = &worker_stats[i];
		total_default_drop += ws->default_drop_count;
		total_classified   += ws->total_classified;

		for (g = 0; g < num_groups; g++)
			total_group_hits[g] += ws->group_hit_count[g];
	}

	/* In header */
	printf("\n================= SPI FINAL STATS =================\n");
	printf("Rx Total: %lu pkts | %lu bytes\n",
		(unsigned long)disp_stats.total_rx_pkts,
		(unsigned long)disp_stats.total_rx_bytes);
	printf("Non-IPv4 (skipped): %lu pkts\n",
		(unsigned long)disp_stats.non_ipv4_count);
	printf("Ring drop (full): %lu pkts\n",
		(unsigned long)disp_stats.ring_drop_count);
	printf("Total classified: %lu pkts\n",
		(unsigned long)total_classified);
	printf("----------------------------------------------------------\n");

	/* Per-group */
	for (g = 0; g < num_groups; g++) {
		printf("[Group: %-24s] Hit: %lu pkts | Action: %s\n",
			filter_groups[g].group_name,
			(unsigned long)total_group_hits[g],
			filter_groups[g].action == ACTION_FORWARD ?
				"FORWARD" : "DROP");
	}

	printf("[Default/Unmatched]              Hit: %lu pkts | Action: DROP\n",
		(unsigned long)total_default_drop);
	printf("==========================================================\n\n");

	/* Verify Missing Rate */
	uint64_t total_accounted = total_classified
				   + disp_stats.non_ipv4_count
				   + disp_stats.ring_drop_count;
	if (total_accounted == disp_stats.total_rx_pkts) {
		printf("[VERIFY] Missing Rate: 0%% (OK)\n");
	} else {
		printf("[VERIFY] WARNING: Missing Rate != 0%% — "
			"Accounted=%lu, Rx=%lu, Delta=%ld\n",
			(unsigned long)total_accounted,
			(unsigned long)disp_stats.total_rx_pkts,
			(long)(disp_stats.total_rx_pkts - total_accounted));
	}
}
