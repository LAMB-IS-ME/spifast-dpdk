/* ============================================================
 * SPIFast - acl.h
 * ------------------------------------------------------------
 * Module ACL: kien truc multi-context — moi filter-group co
 * 1 rte_acl_ctx rieng biet. Classify tuan tu theo precedence
 * tang dan (so nho = uu tien cao, classify truoc).
 *
 * Theo MASTER_SPEC.md muc 4.1, 4.3.
 * ============================================================ */

#ifndef SPIFAST_ACL_H
#define SPIFAST_ACL_H

#include <rte_acl.h>
#include "parser.h"

/* ------------------------------------------------------------
 * Anh xa 1 rule toan cuc -> group chua no.
 * ------------------------------------------------------------ */
typedef struct {
	uint32_t group_id;
	char     group_name[64];
	uint32_t action;
} rule_action_map_t;

/* ------------------------------------------------------------
 * Thong tin moi filter-group.
 * ------------------------------------------------------------ */
typedef struct {
	uint32_t            group_id;
	char                group_name[64];
	uint32_t            action;
	uint32_t            precedence;
	struct rte_acl_ctx *acl_ctx;
	uint32_t            num_rules;
	uint32_t            global_rule_offset;
} filter_group_t;

/* ------------------------------------------------------------
 * Externs
 * ------------------------------------------------------------ */
extern filter_group_t    filter_groups[MAX_GROUPS];
extern uint32_t          num_groups;
extern rule_action_map_t rule_action_map[MAX_RULES];
extern uint32_t          num_rules_total;

/* ------------------------------------------------------------
 * API
 * ------------------------------------------------------------ */
int  acl_build_all(void);
void acl_free_all(void);

#endif /* SPIFAST_ACL_H */
