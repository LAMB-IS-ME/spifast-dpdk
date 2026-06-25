/* ============================================================
 * SPIFast - acl.c
 * ------------------------------------------------------------
 * Module ACL: kien truc multi-context.
 * acl_build_all() populate filter_groups[] tu policy_table[],
 * sort theo precedence, tao ctx rieng + add rules + build trie
 * cho tung group.
 *
 * Theo MASTER_SPEC.md muc 4.1, 4.3.
 * ============================================================ */

#include <stdio.h>
#include <string.h>

#include <rte_acl.h>
#include <rte_errno.h>
#include <rte_lcore.h>

#include "acl.h"

/* ============================================================
 * GLOBAL DEFINITIONS (extern trong acl.h)
 * ============================================================ */
filter_group_t    filter_groups[MAX_GROUPS];
uint32_t          num_groups = 0;
rule_action_map_t rule_action_map[MAX_RULES];
uint32_t          num_rules_total = 0;

/* ============================================================
 * SO FIELD TRONG MOI ACL RULE (IPv4 5-tuple)
 * ============================================================ */
#define NUM_FIELDS_IPV4 5

/* ============================================================
 * FIELD DEFINITIONS
 * ------------------------------------------------------------
 * Layout bat buoc khop voi five_tuple_t (NBO, sizeof=16):
 *   protocol @ offset 0   (1 byte + 3 padding)
 *   src_ip   @ offset 4   (4 bytes)
 *   dst_ip   @ offset 8   (4 bytes)
 *   src_port @ offset 12  (2 bytes)  input_index=3
 *   dst_port @ offset 14  (2 bytes)  input_index=3
 * ============================================================ */
static const struct rte_acl_field_def ipv4_field_defs[NUM_FIELDS_IPV4] = {
	/* [0] protocol */
	{
		.type        = RTE_ACL_FIELD_TYPE_BITMASK,
		.size        = sizeof(uint8_t),
		.field_index = 0,
		.input_index = 0,
		.offset      = 0,
	},
	/* [1] src_ip */
	{
		.type        = RTE_ACL_FIELD_TYPE_MASK,
		.size        = sizeof(uint32_t),
		.field_index = 1,
		.input_index = 1,
		.offset      = 4,
	},
	/* [2] dst_ip */
	{
		.type        = RTE_ACL_FIELD_TYPE_MASK,
		.size        = sizeof(uint32_t),
		.field_index = 2,
		.input_index = 2,
		.offset      = 8,
	},
	/* [3] src_port — input_index=3, chung khoi 4 byte voi dst_port */
	{
		.type        = RTE_ACL_FIELD_TYPE_RANGE,
		.size        = sizeof(uint16_t),
		.field_index = 3,
		.input_index = 3,
		.offset      = 12,
	},
	/* [4] dst_port — input_index=3 (giong src_port) */
	{
		.type        = RTE_ACL_FIELD_TYPE_RANGE,
		.size        = sizeof(uint16_t),
		.field_index = 4,
		.input_index = 3,
		.offset      = 14,
	},
};

/* ============================================================
 * DEFINE KIEU ACL RULE VOI 5 FIELD
 * ============================================================ */
RTE_ACL_RULE_DEF(acl_ipv4_rule, NUM_FIELDS_IPV4);

/* ============================================================
 * mask_to_depth() — convert subnet mask -> prefix depth
 * Vi du: 0xFFFFC000 (/18) -> 18
 * ============================================================ */
static inline uint32_t
mask_to_depth(uint32_t mask)
{
	if (mask == 0)
		return 0;
	return (uint32_t)__builtin_popcount(mask);
}

/* ============================================================
 * acl_build_all()
 * ============================================================ */
int
acl_build_all(void)
{
	int i, j;
	uint32_t g;

	if (num_rules <= 0) {
		fprintf(stderr, "[ACL] Loi: num_rules=%d, chua load rules?\n",
			num_rules);
		return -1;
	}
	if (num_policies <= 0) {
		fprintf(stderr, "[ACL] Loi: num_policies=%d, chua load policy?\n",
			num_policies);
		return -1;
	}

	/* --------------------------------------------------------
	 * Buoc 1: Populate filter_groups[] tu policy_table[]
	 * -------------------------------------------------------- */
	num_groups = (uint32_t)num_policies;
	for (i = 0; i < num_policies; i++) {
		filter_group_t *fg = &filter_groups[i];
		memset(fg, 0, sizeof(*fg));
		fg->group_id = (uint32_t)i;
		memcpy(fg->group_name, policy_table[i].group_name,
			sizeof(fg->group_name));
		fg->group_name[sizeof(fg->group_name) - 1] = '\0';
		fg->action     = policy_table[i].action;
		fg->precedence = policy_table[i].precedence;
		fg->acl_ctx    = NULL;
		fg->num_rules  = 0;
		fg->global_rule_offset = 0;
	}

	/* --------------------------------------------------------
	 * Buoc 2: Sort filter_groups[] tang dan theo precedence
	 * (insertion sort — num_groups nho, <= 256)
	 * -------------------------------------------------------- */
	for (i = 1; i < (int)num_groups; i++) {
		filter_group_t tmp = filter_groups[i];
		j = i - 1;
		while (j >= 0 && filter_groups[j].precedence > tmp.precedence) {
			filter_groups[j + 1] = filter_groups[j];
			j--;
		}
		filter_groups[j + 1] = tmp;
	}

	/* --------------------------------------------------------
	 * Buoc 3: Re-assign group_id = index sau sort
	 * -------------------------------------------------------- */
	for (i = 0; i < (int)num_groups; i++)
		filter_groups[i].group_id = (uint32_t)i;

	/* --------------------------------------------------------
	 * Buoc 4: Dem num_rules cho moi group
	 * -------------------------------------------------------- */
	for (i = 0; i < num_rules; i++) {
		for (j = 0; j < (int)num_groups; j++) {
			if (strcmp(parsed_rules[i].group_name,
				  filter_groups[j].group_name) == 0) {
				filter_groups[j].num_rules++;
				break;
			}
		}
	}

	/* --------------------------------------------------------
	 * Buoc 5: Tinh global_rule_offset cho moi group
	 * -------------------------------------------------------- */
	{
		uint32_t offset = 0;
		for (i = 0; i < (int)num_groups; i++) {
			filter_groups[i].global_rule_offset = offset;
			offset += filter_groups[i].num_rules;
		}
		num_rules_total = offset;
	}

	/* --------------------------------------------------------
	 * Buoc 6: Populate rule_action_map[]
	 * -------------------------------------------------------- */
	for (i = 0; i < (int)num_groups; i++) {
		uint32_t idx = filter_groups[i].global_rule_offset;
		for (j = 0; j < num_rules; j++) {
			if (strcmp(parsed_rules[j].group_name,
				  filter_groups[i].group_name) == 0) {
				rule_action_map[idx].group_id = (uint32_t)i;
				memcpy(rule_action_map[idx].group_name,
					filter_groups[i].group_name,
					sizeof(rule_action_map[idx].group_name));
				rule_action_map[idx].group_name[
					sizeof(rule_action_map[idx].group_name) - 1] = '\0';
				rule_action_map[idx].action = filter_groups[i].action;
				idx++;
			}
		}
	}

	printf("[ACL_BUILD] %u groups, %u total rules\n",
		num_groups, num_rules_total);
	for (i = 0; i < (int)num_groups; i++) {
		printf("  Group[%d]: %-30s prec=%-5u action=%-7s "
			"rules=%-3u offset=%u\n",
			i, filter_groups[i].group_name,
			filter_groups[i].precedence,
			filter_groups[i].action == ACTION_FORWARD
				? "FORWARD" : "DROP",
			filter_groups[i].num_rules,
			filter_groups[i].global_rule_offset);
	}

	/* --------------------------------------------------------
	 * Buoc 7: Tao ACL context rieng cho moi group
	 * -------------------------------------------------------- */
	for (g = 0; g < num_groups; g++) {
		filter_group_t *fg = &filter_groups[g];
		struct rte_acl_param acl_param;
		struct rte_acl_config acl_cfg;
		char ctx_name[64];
		uint32_t local_idx;
		int ret;

		if (fg->num_rules == 0) {
			fg->acl_ctx = NULL;
			continue;
		}

		/* a. Tao ten ctx unique */
		snprintf(ctx_name, sizeof(ctx_name),
			"spifast_acl_%s", fg->group_name);

		/* b. rte_acl_create */
		memset(&acl_param, 0, sizeof(acl_param));
		acl_param.name         = ctx_name;
		acl_param.socket_id    = rte_socket_id();
		acl_param.rule_size    = RTE_ACL_RULE_SZ(NUM_FIELDS_IPV4);
		acl_param.max_rule_num = fg->num_rules + 1;

		/* c. Tao ctx */
		fg->acl_ctx = rte_acl_create(&acl_param);
		if (fg->acl_ctx == NULL) {
			fprintf(stderr,
				"[ACL] Loi: rte_acl_create('%s'): %s\n",
				ctx_name, rte_strerror(rte_errno));
			return -1;
		}

		/* d. Add rules thuoc group g */
		local_idx = 0;
		for (j = 0; j < num_rules; j++) {
			struct acl_ipv4_rule ar;
			const parsed_rule_t *pr = &parsed_rules[j];

			if (strcmp(pr->group_name, fg->group_name) != 0)
				continue;

			memset(&ar, 0, sizeof(ar));

			ar.data.userdata      = local_idx + 1;
			ar.data.category_mask = 1;
			ar.data.priority      = (int32_t)fg->precedence;

			ar.field[0].value.u8      = pr->protocol;
			ar.field[0].mask_range.u8 = pr->protocol_mask;

			ar.field[1].value.u32      = pr->src_ip;
			ar.field[1].mask_range.u32 = mask_to_depth(pr->src_mask);

			ar.field[2].value.u32      = pr->dst_ip;
			ar.field[2].mask_range.u32 = mask_to_depth(pr->dst_mask);

			ar.field[3].value.u16      = pr->src_port_low;
			ar.field[3].mask_range.u16 = pr->src_port_high;

			ar.field[4].value.u16      = pr->dst_port_low;
			ar.field[4].mask_range.u16 = pr->dst_port_high;

			ret = rte_acl_add_rules(fg->acl_ctx,
				(const struct rte_acl_rule *)&ar, 1);
			if (ret != 0) {
				fprintf(stderr,
					"[ACL] Loi: rte_acl_add_rules "
					"group '%s' rule %u: %s\n",
					fg->group_name, local_idx,
					rte_strerror(-ret));
				return -1;
			}

			local_idx++;
		}

		/* e. Build trie */
		memset(&acl_cfg, 0, sizeof(acl_cfg));
		acl_cfg.num_categories = 1;
		acl_cfg.num_fields     = NUM_FIELDS_IPV4;
		acl_cfg.max_size       = 0;
		memcpy(acl_cfg.defs, ipv4_field_defs,
			sizeof(ipv4_field_defs));

		ret = rte_acl_build(fg->acl_ctx, &acl_cfg);
		if (ret != 0) {
			fprintf(stderr,
				"[ACL] Loi: rte_acl_build group '%s': %s\n",
				fg->group_name, rte_strerror(-ret));
			return -1;
		}

		/* f. Log */
		printf("[ACL_BUILD] Group '%s' (precedence=%u): "
			"%u rules, ctx=%p\n",
			fg->group_name, fg->precedence,
			fg->num_rules, (void *)fg->acl_ctx);
	}

	printf("[ACL_BUILD] Tat ca %u groups da build thanh cong\n",
		num_groups);
	return 0;
}

/* ============================================================
 * acl_free_all()
 * ============================================================ */
void
acl_free_all(void)
{
	uint32_t g;

	for (g = 0; g < num_groups; g++) {
		if (filter_groups[g].acl_ctx != NULL) {
			rte_acl_free(filter_groups[g].acl_ctx);
			filter_groups[g].acl_ctx = NULL;
		}
	}
}
