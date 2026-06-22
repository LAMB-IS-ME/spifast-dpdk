/* ============================================================
 * SPIFast - header_parser.c
 * ------------------------------------------------------------
 * Hien thuc parse_packet_5tuple(): trich xuat 5-Tuple tu mbuf
 * bang Zero-copy (cast con tro), gan field-by-field vao
 * five_tuple_t (co padding sau protocol nen KHONG memcpy raw).
 *
 * Protocol khac TCP/UDP: port = 0, van return 0 (de ACL tu
 * quyet dinh action, KHONG drop tai day).
 * ============================================================ */

#include "header_parser.h"

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <netinet/in.h>   /* IPPROTO_TCP, IPPROTO_UDP */

int
parse_packet_5tuple(struct rte_mbuf *mbuf, five_tuple_t *out)
{
	/* ----------------------------------------------------------
	 * L2: Ethernet header (Zero-copy cast tu dau mbuf data)
	 * ---------------------------------------------------------- */
	struct rte_ether_hdr *eth;
	eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

	/* Chi xu ly IPv4 — cac loai khac (IPv6, ARP, ...) skip */
	if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
		return -1;

	/* ----------------------------------------------------------
	 * L3: IPv4 header (ngay sau Ethernet header)
	 * ---------------------------------------------------------- */
	struct rte_ipv4_hdr *ip;
	ip = (struct rte_ipv4_hdr *)((uint8_t *)eth + sizeof(struct rte_ether_hdr));

	/* Gan field-by-field (KHONG memcpy raw vi five_tuple_t co
	 * padding 3 bytes sau protocol).
	 *
	 * LUU Y BYTE ORDER: DPDK ACL (rte_acl_classify) expect input
	 * data co multi-byte fields o NETWORK BYTE ORDER. Trie builder
	 * da tu convert rule values (host-order) sang NBO byte patterns
	 * khi build trie. Do do, ta KHONG convert IP/port tu NBO sang
	 * host-order — giu nguyen NBO tu packet headers.
	 */
	out->protocol = ip->next_proto_id;
	out->src_ip   = ip->src_addr;    /* NBO — KHONG rte_be_to_cpu_32 */
	out->dst_ip   = ip->dst_addr;    /* NBO — KHONG rte_be_to_cpu_32 */

	/* ----------------------------------------------------------
	 * L4: TCP hoac UDP header (ngay sau IPv4 header)
	 * Dung ip->ihl de tinh offset chinh xac (IHL co the > 5)
	 * ---------------------------------------------------------- */
	uint8_t *l4_ptr = (uint8_t *)ip + (ip->version_ihl & 0x0F) * 4;

	if (out->protocol == IPPROTO_TCP) {
		struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_ptr;
		out->src_port = tcp->src_port;  /* NBO — KHONG rte_be_to_cpu_16 */
		out->dst_port = tcp->dst_port;  /* NBO — KHONG rte_be_to_cpu_16 */
	} else if (out->protocol == IPPROTO_UDP) {
		struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_ptr;
		out->src_port = udp->src_port;  /* NBO — KHONG rte_be_to_cpu_16 */
		out->dst_port = udp->dst_port;  /* NBO — KHONG rte_be_to_cpu_16 */
	} else {
		/* Protocol khac TCP/UDP: port = 0, van return 0
		 * De ACL tu quyet dinh action (KHONG drop o day) */
		out->src_port = 0;
		out->dst_port = 0;
	}

	return 0;
}
