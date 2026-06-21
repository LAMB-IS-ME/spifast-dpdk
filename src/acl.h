/* ============================================================
 * SPIFast - acl.h
 * ------------------------------------------------------------
 * Module ACL: Khoi tao DPDK ACL context, convert parsed_rules[]
 * thanh rte_acl_rule va build trie de san sang cho classify.
 *
 * KHONG chua logic classify (Worker), Header Parse, hay
 * Dispatcher — cac buoc do lam rieng sau.
 * ============================================================ */

#ifndef SPIFAST_ACL_H
#define SPIFAST_ACL_H

#include <rte_acl.h>

/**
 * acl_init() - Tao va cau hinh mot DPDK ACL context moi.
 *
 * Thuc hien 3 buoc:
 *   1. rte_acl_create()             -> tao context rong
 *   2. rte_acl_add_rules()          -> add tat ca parsed_rules[]
 *   3. rte_acl_build()              -> build trie noi bo
 *
 * Tra ve con tro ctx qua tham so output de main.c tu quyet dinh
 * xu ly loi (khong rte_exit() truc tiep trong module).
 *
 * @param ctx_out  [out] Con tro toi rte_acl_ctx* da khoi tao xong.
 * @return 0 thanh cong, -1 loi (thong bao in ra stderr).
 */
int acl_init(struct rte_acl_ctx **ctx_out);

/**
 * acl_add_rules_from_parsed() - Convert parsed_rules[] thanh
 * rte_acl_rule va add vao ACL context, sau do build trie.
 *
 * YEU CAU: load_policy() va load_rules() phai da duoc goi thanh
 * cong truoc khi goi ham nay.
 *
 * @param ctx  ACL context da duoc tao boi acl_init() (hoac
 *             rte_acl_create() truc tiep).
 * @return 0 thanh cong, -1 loi.
 */
int acl_add_rules_from_parsed(struct rte_acl_ctx *ctx);

#endif /* SPIFAST_ACL_H */
