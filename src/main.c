/* ============================================================
 * SPIFast - main.c
 * ------------------------------------------------------------
 *   - EAL init (rte_eal_init)
 *   - Tao Mempool chuan (8192 mbufs, cache 256)
 *   - Kiem tra va setup port mang (vdev net_pcap0)
 *   - Load CSV (Policy truoc, Rule sau)
 *   - Khoi tao ACL context + build trie
 *   - Tao rte_ring cho Worker
 *   - Launch Worker lcore 1-4 (worker_main)
 *   - Chay Dispatcher tren Master lcore 0 (dispatcher_run)
 *   - In thong ke cuoi cung (print_final_stats)
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
#include "worker.h"

/* ------------------------------------------------------------
 * Hang so cau hinh (dong bo voi MASTER_SPEC muc 4.1 / 4.4)
 * NUM_WORKERS da define trong worker.h
 * ------------------------------------------------------------ */
#define MBUF_POOL_NAME      "SPIFAST_MBUF_POOL"
#define NUM_MBUFS           8192
#define MBUF_CACHE_SIZE     256
#define MBUF_DATA_SIZE      RTE_MBUF_DEFAULT_BUF_SIZE

static struct rte_mempool *spifast_pktmbuf_pool = NULL;

/* ACL context toan cuc — read-only sau khi build xong (thread-safe)
 * Dinh nghia that su o day, extern trong worker.h */
struct rte_acl_ctx *acl_ctx = NULL;

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
 * Setup port vdev net_pcap0: configure, rx_queue_setup, dev_start
 * ------------------------------------------------------------ */
#define NUM_RX_DESC  128

static void
spifast_port_setup(uint16_t port_id)
{
	struct rte_eth_conf port_conf;
	int ret;

	memset(&port_conf, 0, sizeof(port_conf));

	/* Configure port voi 1 RX queue, 0 TX queue (khong can TX) */
	ret = rte_eth_dev_configure(port_id, 1, 0, &port_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"Loi rte_eth_dev_configure(port=%u): %s\n",
			port_id, rte_strerror(-ret));
	}

	/* Setup RX queue 0 */
	ret = rte_eth_rx_queue_setup(port_id, 0, NUM_RX_DESC,
		rte_eth_dev_socket_id(port_id), NULL, spifast_pktmbuf_pool);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"Loi rte_eth_rx_queue_setup(port=%u): %s\n",
			port_id, rte_strerror(-ret));
	}

	/* Start port */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"Loi rte_eth_dev_start(port=%u): %s\n",
			port_id, rte_strerror(-ret));
	}

	printf("[INIT] Port %u da setup va start thanh cong\n", port_id);
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

	/* ------------------------------------------------------------
	 * 3a. Setup port vdev net_pcap0
	 * ------------------------------------------------------------ */
	spifast_port_setup(0);

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
	if (acl_init(&acl_ctx) < 0) {
		rte_exit(EXIT_FAILURE, "Khong the tao ACL context\n");
	}
	if (acl_add_rules_from_parsed(acl_ctx) < 0) {
		rte_exit(EXIT_FAILURE, "Khong the add/build ACL rules\n");
	}

	/* ------------------------------------------------------------
	 * 3d. Tao rte_ring cho Worker (SPSC)
	 * ------------------------------------------------------------ */
	if (worker_rings_init() < 0) {
		rte_exit(EXIT_FAILURE, "Khong the tao worker rings\n");
	}

	/* ------------------------------------------------------------
	 * 4. Launch Worker lcore 1-4, chay Dispatcher tren Master
	 * ------------------------------------------------------------ */
	unsigned worker_idx = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (worker_idx >= NUM_WORKERS)
			break;
		rte_eal_remote_launch(worker_main,
			(void *)(uintptr_t)worker_idx, lcore_id);
		printf("[INIT] Worker %u launched tren lcore %u\n",
			worker_idx, lcore_id);
		worker_idx++;
	}

	/* Master lcore (lcore 0) chay Dispatcher */
	dispatcher_run();

	/* Cho tat ca Worker lcore ket thuc */
	rte_eal_mp_wait_lcore();

	/* In thong ke cuoi cung */
	print_final_stats();

	/* ------------------------------------------------------------
	 * 5. Don dep
	 * ------------------------------------------------------------ */
	rte_eal_cleanup();

	return 0;
}
