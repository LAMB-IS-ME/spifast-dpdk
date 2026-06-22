/* ============================================================
 * SPIFast - worker.c
 * ------------------------------------------------------------
 * Hien thuc Dispatcher (Master lcore 0) va Worker (lcore 1-4).
 *
 * Dispatcher:
 *   rx_burst -> parse_packet_5tuple -> rte_jhash -> enqueue ring
 *
 * Worker:
 *   dequeue ring -> rte_acl_classify -> tra action_map -> action
 *
 * Stats per-Worker chong data race: moi Worker chi ghi vao
 * worker_stats[worker_id] cua minh, Master chi doc de in.
 * ============================================================ */

#include "worker.h"
#include "header_parser.h"
#include "parser.h"
#include "acl.h"

#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include <rte_ring.h>
#include <rte_jhash.h>
#include <rte_acl.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_ether.h>

/* ============================================================
 * GLOBAL DEFINITIONS
 * ============================================================ */
struct rte_ring    *worker_rings[NUM_WORKERS];
worker_stats_t      worker_stats[NUM_WORKERS];
dispatcher_stats_t  disp_stats;

/* acl_ctx duoc khai bao extern trong worker.h,
 * dinh nghia that su o main.c (global) */

/* ============================================================
 * worker_rings_init()
 * ------------------------------------------------------------
 * Tao NUM_WORKERS rte_ring SPSC (Single-Producer Single-Consumer)
 * de Dispatcher (lcore 0) enqueue, Worker (lcore 1-4) dequeue.
 *
 * SPSC toi uu nhat cho mo hinh 1 producer / 1 consumer:
 *   - Dispatcher la producer duy nhat ghi vao ring[i]
 *   - Worker[i] la consumer duy nhat doc tu ring[i]
 * ============================================================ */
int
worker_rings_init(void)
{
	char ring_name[32];
	unsigned i;

	memset(worker_stats, 0, sizeof(worker_stats));
	memset(&disp_stats, 0, sizeof(disp_stats));

	for (i = 0; i < NUM_WORKERS; i++) {
		snprintf(ring_name, sizeof(ring_name), "worker_ring_%u", i);

		worker_rings[i] = rte_ring_create(
			ring_name,
			RING_SIZE,
			rte_socket_id(),
			RING_F_SP_ENQ | RING_F_SC_DEQ  /* SPSC */
		);

		if (worker_rings[i] == NULL) {
			fprintf(stderr,
				"[WORKER] Loi: Khong the tao ring '%s': %s\n",
				ring_name, rte_strerror(rte_errno));
			return -1;
		}

		printf("[WORKER] Da tao ring '%s' (size=%u, SPSC)\n",
			ring_name, RING_SIZE);
	}

	return 0;
}

/* ============================================================
 * dispatcher_run() — Master lcore 0
 * ------------------------------------------------------------
 * Vong lap:
 *   1. rte_eth_rx_burst() nhan toi da 32 mbuf
 *   2. Cap nhat stats tong Rx
 *   3. Voi moi mbuf:
 *      - parse_packet_5tuple() -> skip neu khong phai IPv4
 *      - rte_jhash() tren five_tuple_t -> ring_index
 *      - rte_ring_enqueue() -> ring_drop_count neu that bai
 *   4. Thoat khi PCAP doc het (rx_burst tra ve 0 lien tiep)
 *
 * LUU Y ve dieu kien thoat:
 *   PCAP PMD doc het file thi rx_burst tra ve 0. Dung bo dem
 *   0-burst lien tiep (MAX_EMPTY_POLLS) de phan biet voi
 *   truong hop tam nghi (burst ranh gioi). Gia tri 512 la du
 *   lon de dam bao PCAP da that su het data.
 * ============================================================ */
#define MAX_EMPTY_POLLS  512

void
dispatcher_run(void)
{
	struct rte_mbuf *mbufs[RX_BURST_SIZE];
	uint16_t nb_rx;
	uint16_t i;
	uint32_t empty_polls = 0;

	printf("[DISPATCHER] Bat dau rx_burst tren lcore %u\n",
		rte_lcore_id());

	for (;;) {
		nb_rx = rte_eth_rx_burst(0, 0, mbufs, RX_BURST_SIZE);

		if (nb_rx == 0) {
			empty_polls++;
			if (empty_polls >= MAX_EMPTY_POLLS)
				break;    /* PCAP da doc het */
			continue;
		}

		empty_polls = 0;

		/* Cap nhat stats tong Rx */
		disp_stats.total_rx_pkts += nb_rx;
		for (i = 0; i < nb_rx; i++)
			disp_stats.total_rx_bytes += rte_pktmbuf_pkt_len(mbufs[i]);

		/* Xu ly tung mbuf */
		for (i = 0; i < nb_rx; i++) {
			five_tuple_t tuple;
			uint32_t hash_val;
			uint32_t ring_idx;
			int ret;

			/* Parse 5-tuple */
			if (parse_packet_5tuple(mbufs[i], &tuple) < 0) {
				/* Khong phai IPv4: skip, free mbuf */
				disp_stats.non_ipv4_count++;
				rte_pktmbuf_free(mbufs[i]);
				continue;
			}

			/* Software hash (spec 4.5: rte_jhash, HASH_SEED co dinh) */
			hash_val = rte_jhash(&tuple, sizeof(five_tuple_t),
					     HASH_SEED);
			ring_idx = hash_val % NUM_WORKERS;

			/* Enqueue vao ring cua Worker tuong ung */
			ret = rte_ring_enqueue(worker_rings[ring_idx], mbufs[i]);
			if (ret != 0) {
				/* Ring day: tang ring_drop_count, free mbuf */
				disp_stats.ring_drop_count++;
				rte_pktmbuf_free(mbufs[i]);
			}
		}
	}

	printf("[DISPATCHER] PCAP doc het. Tong Rx: %lu pkts, %lu bytes\n",
		(unsigned long)disp_stats.total_rx_pkts,
		(unsigned long)disp_stats.total_rx_bytes);

	/* Gui tin hieu "het data" cho Worker bang cach enqueue NULL
	 * vao moi ring. Worker thay NULL thi thoat vong lap. */
	for (i = 0; i < NUM_WORKERS; i++) {
		/* Busy-wait cho den khi enqueue thanh cong (ring co the day) */
		while (rte_ring_enqueue(worker_rings[i], NULL) != 0)
			;  /* spin */
	}
}

/* ============================================================
 * worker_main() — Worker lcore 1-4
 * ------------------------------------------------------------
 * Vong lap:
 *   1. rte_ring_dequeue() lay mbuf
 *   2. Chuan bi input cho rte_acl_classify():
 *      - data[1] tro toi L3 header (sau Ethernet header)
 *      - rte_acl_classify(acl_ctx, data, results, 1, 1)
 *   3. Tra action_map[userdata] -> action
 *   4. Thuc thi action (FORWARD/DROP) — trong ca 2 truong hop
 *      deu free mbuf vi khong co TX port that.
 *   5. Thoat khi nhan duoc NULL sentinel tu Dispatcher.
 *
 * VE ACL INPUT FORMAT:
 *   rte_acl_classify() nhan mang const uint8_t* tro toi du lieu
 *   bat dau tu vi tri ma field definitions (ipv4_field_defs)
 *   dung offsetof() tro toi. Trong truong hop nay, field defs
 *   dung offsetof(five_tuple_t, ...) nen data phai tro toi
 *   mot vung nho co layout giong five_tuple_t.
 *
 *   Tuy nhien, vi five_tuple_t duoc gan field-by-field tu
 *   packet (da byte-swap sang host order), ta KHONG THE chi
 *   vao raw packet L3 header truc tiep — vi ACL field defs
 *   offset doi hoi layout cua five_tuple_t, khong phai IPv4 hdr.
 *
 *   => Phai parse truoc thanh five_tuple_t, roi tro data vao do.
 * ============================================================ */
int
worker_main(void *arg)
{
	uint32_t worker_id = (uint32_t)(uintptr_t)arg;
	worker_stats_t *stats = &worker_stats[worker_id];
	struct rte_mbuf *mbuf;
	void *dequeued;

	printf("[WORKER %u] Bat dau tren lcore %u\n",
		worker_id, rte_lcore_id());

	for (;;) {
		/* Dequeue 1 mbuf tu ring */
		if (rte_ring_dequeue(worker_rings[worker_id], &dequeued) != 0)
			continue;

		/* NULL sentinel = Dispatcher bao het data */
		if (dequeued == NULL)
			break;

		mbuf = (struct rte_mbuf *)dequeued;

		/* ------------------------------------------------
		 * Parse 5-tuple de tao input cho ACL classify
		 * ------------------------------------------------ */
		five_tuple_t tuple;
		memset(&tuple, 0, sizeof(tuple));   /* THEM DONG NAY — zero padding */
		if (parse_packet_5tuple(mbuf, &tuple) < 0) {
			rte_pktmbuf_free(mbuf);
			continue;
		}

		// printf("[DEBUG] tuple: proto=%u src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u\n",
		// 	tuple.protocol,
		// 	(tuple.src_ip>>24)&0xFF, (tuple.src_ip>>16)&0xFF,
		// 	(tuple.src_ip>>8)&0xFF,  tuple.src_ip&0xFF,
		// 	tuple.src_port,
		// 	(tuple.dst_ip>>24)&0xFF, (tuple.dst_ip>>16)&0xFF,
		// 	(tuple.dst_ip>>8)&0xFF,  tuple.dst_ip&0xFF,
		// 	tuple.dst_port);

		/* ------------------------------------------------
		 * ACL classify
		 * data[0] tro toi five_tuple_t (layout khop field defs)
		 * ------------------------------------------------ */
		const uint8_t *data[1] = { (const uint8_t *)&tuple };
		uint32_t results[1] = { 0 };

		rte_acl_classify(acl_ctx, data, results, 1, 1);

		uint32_t userdata = results[0];
		stats->total_classified++;

		/* ------------------------------------------------
		 * Xu ly ket qua classify
		 * ------------------------------------------------ */
		if (userdata == 0) {
			/* No match — Zero-Trust: DROP */
			stats->default_drop_count++;
			rte_pktmbuf_free(mbuf);
			continue;
		}

		/* userdata bat dau tu 1, action_map index tu 0
		 * => action_map[userdata - 1] */
		uint32_t map_idx = userdata - 1;
		stats->hit_count[map_idx]++;

		/* Ca FORWARD lan DROP deu free mbuf (khong co TX port that).
		 * Chi khac nhau o counter — action_map[].action cho biet
		 * FORWARD hay DROP de thong ke. */
		rte_pktmbuf_free(mbuf);
	}

	printf("[WORKER %u] Ket thuc. Classified: %lu, Default drop: %lu\n",
		worker_id,
		(unsigned long)stats->total_classified,
		(unsigned long)stats->default_drop_count);

	return 0;
}

/* ============================================================
 * print_final_stats() — In thong ke cuoi cung
 * ------------------------------------------------------------
 * Goi tu main() sau khi tat ca Worker da ket thuc
 * (rte_eal_mp_wait_lcore()). Collect stats tu tat ca Worker
 * va in theo format gan giong MASTER_SPEC muc 4.6.
 * ============================================================ */
void
print_final_stats(void)
{
	uint64_t total_hits[MAX_RULES];
	uint64_t total_default_drop = 0;
	uint64_t total_classified = 0;
	unsigned i;
	int r;

	memset(total_hits, 0, sizeof(total_hits));

	/* Collect tu tat ca Worker */
	for (i = 0; i < NUM_WORKERS; i++) {
		const worker_stats_t *ws = &worker_stats[i];
		total_default_drop += ws->default_drop_count;
		total_classified   += ws->total_classified;

		for (r = 0; r < num_rules; r++)
			total_hits[r] += ws->hit_count[r];
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

	/* In per-rule/group stats */
	for (r = 0; r < num_rules; r++) {
		if (total_hits[r] > 0) {
			printf("[Group: %-24s] Hit: %lu pkts | Action: %s\n",
				action_map[r].group_name,
				(unsigned long)total_hits[r],
				action_map[r].action == ACTION_FORWARD ?
					"FORWARD" : "DROP");
		}
	}

	printf("[Default/Unmatched]              Hit: %lu pkts | Action: DROP\n",
		(unsigned long)total_default_drop);
	printf("==========================================================\n\n");

	/* Kiem tra Missing Rate (spec: 0% tuyet doi) */
	uint64_t total_accounted = total_classified + disp_stats.non_ipv4_count
				   + disp_stats.ring_drop_count;
	if (total_accounted == disp_stats.total_rx_pkts) {
		printf("[VERIFY] Missing Rate: 0%% (OK) — Tong match + drop "
			"= tong Rx\n");
	} else {
		printf("[VERIFY] WARNING: Missing Rate != 0%% — "
			"Accounted=%lu, Rx=%lu, Delta=%ld\n",
			(unsigned long)total_accounted,
			(unsigned long)disp_stats.total_rx_pkts,
			(long)(disp_stats.total_rx_pkts - total_accounted));
	}
}
