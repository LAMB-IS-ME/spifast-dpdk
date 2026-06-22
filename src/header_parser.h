/* ============================================================
 * SPIFast - header_parser.h
 * ------------------------------------------------------------
 * Module Header Parser: trich xuat 5-Tuple tu raw packet mbuf
 * (Ethernet -> IPv4 -> TCP/UDP) theo phuong phap Zero-copy
 * (ep kieu con tro, KHONG memcpy).
 *
 * KHONG chua logic ACL, CSV Parser, Dispatcher hay bat ky
 * phan nao khac ngoai pham vi Header Parse.
 * ============================================================ */

#ifndef SPIFAST_HEADER_PARSER_H
#define SPIFAST_HEADER_PARSER_H

#include "parser.h"
#include <rte_mbuf.h>

/**
 * parse_packet_5tuple() - Trich xuat 5-Tuple tu mot mbuf packet.
 *
 * Parse L2 (Ethernet), L3 (IPv4), L4 (TCP/UDP) header bang
 * phuong phap Zero-copy (cast con tro truc tiep tren mbuf data).
 * Gan field-by-field vao `out` (KHONG dung memcpy raw vi
 * five_tuple_t co padding sau `protocol`).
 *
 * @param mbuf  Con tro mbuf chua packet nhan tu rte_eth_rx_burst().
 * @param out   [out] Con tro five_tuple_t se duoc dien 5 field.
 * @return 0 thanh cong, -1 neu packet khong phai IPv4 (skip).
 */
int parse_packet_5tuple(struct rte_mbuf *mbuf, five_tuple_t *out);

#endif /* SPIFAST_HEADER_PARSER_H */
