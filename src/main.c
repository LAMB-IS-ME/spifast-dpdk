/* ============================================================
 * SPIFast - main.c
 * ------------------------------------------------------------
 *   - EAL init (rte_eal_init)
 *   - Tao Mempool chuan (8192 mbufs, cache 256)
 *   - Kiem tra so luong port mang (vdev net_pcap0)
 *   - Khoi chay lcore (Master + Worker) - PLACEHOLDER, chua co logic
 *     Parser/ACL/Dispatcher/Worker that su (se lam o cac buoc sau).
 *
 * KHONG tu y sinh them logic Parser / ACL / Header-parse / Hash /
 * Statistics trong file nay - theo dung "QUY TAC TUONG TAC" cua
 * master spec (something.md).
 * ============================================================ */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_log.h>

#include "parser.h"
#include "acl.h"

/* ------------------------------------------------------------
 * Hang so cau hinh (dong bo voi something.md muc 4.1 / 4.4)
 * ------------------------------------------------------------ */
#define NUM_WORKERS         4
#define MBUF_POOL_NAME      "SPIFAST_MBUF_POOL"
#define NUM_MBUFS           8192
#define MBUF_CACHE_SIZE     256
#define MBUF_DATA_SIZE      RTE_MBUF_DEFAULT_BUF_SIZE

static struct rte_mempool *spifast_pktmbuf_pool = NULL;

/* ------------------------------------------------------------
 * Ham khoi tao Mempool chuan
 * ------------------------------------------------------------ */
static struct rte_mempool *
spifast_mempool_init(void)
{
	struct rte_mempool *pool;

	pool = rte_pktmbuf_pool_create(
		MBUF_POOL_NAME,
		NUM_MBUFS,
		MBUF_CACHE_SIZE,
		0,                  /* private data size */
		MBUF_DATA_SIZE,
		rte_socket_id()
	);

	if (pool == NULL) {
		rte_exit(EXIT_FAILURE,
			"Khong the tao mbuf pool: %s\n",
			rte_strerror(rte_errno));
	}

	printf("[INIT] Mempool '%s' da tao thanh cong: %u mbufs, cache=%u\n",
		MBUF_POOL_NAME, NUM_MBUFS, MBUF_CACHE_SIZE);

	return pool;
}

/* ------------------------------------------------------------
 * Kiem tra port mang kha dung (vdev net_pcap0)
 * ------------------------------------------------------------ */
static uint16_t
spifast_check_ports(void)
{
	uint16_t nb_ports = rte_eth_dev_count_avail();

	if (nb_ports == 0) {
		rte_exit(EXIT_FAILURE,
			"Khong tim thay port mang nao. "
			"Kiem tra lai tham so --vdev=\"net_pcap0,rx_pcap=...\"\n");
	}

	printf("[INIT] Tim thay %u port mang (vdev PCAP PMD)\n", nb_ports);

	return nb_ports;
}

/* ------------------------------------------------------------
 * Lcore worker function - PLACEHOLDER
 * Master (lcore_id == rte_get_main_lcore()) se lam Dispatcher.
 * Worker (lcore_id khac) se lam Worker.
 * Logic that su (rx_burst/hash/ring/acl_classify/...) se duoc
 * them vao cac buoc tiep theo, KHONG sinh truoc o day.
 * ------------------------------------------------------------ */
static int
spifast_lcore_main(__rte_unused void *arg)
{
	unsigned lcore_id = rte_lcore_id();

	if (lcore_id == rte_get_main_lcore()) {
		printf("[LCORE %u] Master (Rx/Dispatcher) - cho logic o buoc sau\n",
			lcore_id);
	} else {
		printf("[LCORE %u] Worker - cho logic o buoc sau\n", lcore_id);
	}

	/* TODO (cac buoc sau): vong lap rx_burst / ring_dequeue thuc te */

	return 0;
}

int
main(int argc, char **argv)
{
	int ret;
	unsigned lcore_id;

	/* ------------------------------------------------------------
	 * 1. EAL init - parse cac tham so --lcores, --vdev, -n ...
	 * ------------------------------------------------------------ */
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Loi khoi tao EAL\n");
	}
	argc -= ret;
	argv += ret;

	printf("[INIT] EAL khoi tao thanh cong. So lcore kha dung: %u\n",
		rte_lcore_count());

	if (rte_lcore_count() < NUM_WORKERS + 1) {
		rte_exit(EXIT_FAILURE,
			"Can it nhat %d lcore (1 Master + %d Worker), hien co %u\n",
			NUM_WORKERS + 1, NUM_WORKERS, rte_lcore_count());
	}

	/* ------------------------------------------------------------
	 * 2. Tao Mempool
	 * ------------------------------------------------------------ */
	spifast_pktmbuf_pool = spifast_mempool_init();

	/* ------------------------------------------------------------
	 * 3. Kiem tra vdev PCAP PMD da duoc nap chua
	 * ------------------------------------------------------------ */
	spifast_check_ports();

	/* TODO (buoc sau): rte_eth_dev_configure / rx_queue_setup / dev_start
	 * cho port vdev net_pcap0. Chua lam o buoc khung nay. */

	/* ------------------------------------------------------------
	 * 3b. Load CSV: Policy truoc, Rule sau (spec muc 4.2)
	 * ------------------------------------------------------------ */
	if (load_policy("SPI_policy.csv") < 0) {
		rte_exit(EXIT_FAILURE, "Khong the load SPI_policy.csv\n");
	}
	if (load_rules("SPI_rule.csv") < 0) {
		rte_exit(EXIT_FAILURE, "Khong the load SPI_rule.csv\n");
	}

	/* ------------------------------------------------------------
	 * 3c. Khoi tao DPDK ACL context + add rules + build trie
	 * (MASTER_SPEC.md muc 4.3)
	 * ------------------------------------------------------------ */
	struct rte_acl_ctx *acl_ctx = NULL;

	if (acl_init(&acl_ctx) < 0) {
		rte_exit(EXIT_FAILURE, "Khong the tao ACL context\n");
	}
	if (acl_add_rules_from_parsed(acl_ctx) < 0) {
		rte_exit(EXIT_FAILURE, "Khong the add/build ACL rules\n");
	}
	/* TODO (buoc sau): Setup 2 rings (RX, FLOW) cho moi worker: 
	 *   - Mbuf->RX -> RX ring
	 *   - Worker lay mbuf tu RX ring, classif via acl_classify, 
	 *     gui vao FLOW ring */

	/* ------------------------------------------------------------
	 * 4. Khoi chay lcore - Master + Worker (placeholder)
	 * ------------------------------------------------------------ */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_remote_launch(spifast_lcore_main, NULL, lcore_id);
	}

	/* Master lcore chay truc tiep tai day */
	spifast_lcore_main(NULL);

	/* Cho tat ca worker lcore ket thuc */
	rte_eal_mp_wait_lcore();

	/* ------------------------------------------------------------
	 * 5. Don dep
	 * ------------------------------------------------------------ */
	rte_eal_cleanup();

	return 0;
}
