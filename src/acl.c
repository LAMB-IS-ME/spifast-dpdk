/* ============================================================
 * SPIFast - acl.c
 * ------------------------------------------------------------
 * Module ACL: Khoi tao DPDK ACL context (rte_acl_create),
 * convert parsed_rules[] thanh rte_acl_rule, add rules, build
 * trie de san sang cho rte_acl_classify() (Worker goi sau).
 *
 * KHONG chua logic classify, Header Parse, Dispatcher.
 * Theo MASTER_SPEC.md muc 4.3.
 * ============================================================ */

#include <stdio.h>
#include <string.h>
#include <stddef.h>       /* offsetof */

#include <rte_acl.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_byteorder.h>

#include "parser.h"
#include "acl.h"

/* ============================================================
 * SO FIELD TRONG MOI ACL RULE (IPv4 5-tuple)
 * ============================================================ */
#define NUM_FIELDS_IPV4  5

/* ============================================================
 * FIELD DEFINITIONS
 * ------------------------------------------------------------
 * Bam sat chuan IPv4 5-tuple cua examples/l3fwd-acl (DPDK).
 * Thu tu field:
 *   [0] protocol  (BITMASK, 1 byte)
 *   [1] src_ip    (MASK,    4 bytes)
 *   [2] dst_ip    (MASK,    4 bytes)
 *   [3] src_port  (RANGE,   2 bytes)
 *   [4] dst_port  (RANGE,   2 bytes)
 *
 * VE input_index:
 * - Vong lap noi bo cua DPDK ACL xu ly 4 byte moi lan (tru byte
 *   dau tien duoc xu ly rieng khi setup).
 * - input_index nhom cac field thanh cac khoi 4 byte lien tiep.
 * - protocol (1 byte) -> input_index=0 (byte dau tien, setup)
 * - src_ip   (4 byte) -> input_index=1
 * - dst_ip   (4 byte) -> input_index=2
 * - src_port (2 byte) + dst_port (2 byte) cung nam trong 1 khoi
 *   4 byte -> CA HAI deu co input_index=3.
 *   Day la dac diem cua DPDK ACL trie builder: no gom 2 port
 *   16-bit vao chung 1 "input field" 32-bit khi xay trie, nen
 *   chung PHAI co cung input_index.
 * ============================================================ */
static const struct rte_acl_field_def ipv4_field_defs[NUM_FIELDS_IPV4] = {
	/* Field 0: protocol */
	{
		.type        = RTE_ACL_FIELD_TYPE_BITMASK,
		.size        = sizeof(uint8_t),
		.field_index = 0,
		.input_index = 0,
		.offset      = offsetof(five_tuple_t, protocol),
	},
	/* Field 1: src_ip */
	{
		.type        = RTE_ACL_FIELD_TYPE_MASK,
		.size        = sizeof(uint32_t),
		.field_index = 1,
		.input_index = 1,
		.offset      = offsetof(five_tuple_t, src_ip),
	},
	/* Field 2: dst_ip */
	{
		.type        = RTE_ACL_FIELD_TYPE_MASK,
		.size        = sizeof(uint32_t),
		.field_index = 2,
		.input_index = 2,
		.offset      = offsetof(five_tuple_t, dst_ip),
	},
	/* Field 3: src_port
	 * input_index = 3, cung khoi 4 byte voi dst_port (xem giai
	 * thich ve input_index o tren). */
	{
		.type        = RTE_ACL_FIELD_TYPE_RANGE,
		.size        = sizeof(uint16_t),
		.field_index = 3,
		.input_index = 3,
		.offset      = offsetof(five_tuple_t, src_port),
	},
	/* Field 4: dst_port
	 * input_index = 3 (GIONG src_port) vi DPDK ACL gom 2 port
	 * 16-bit vao chung 1 input 32-bit khi build trie. */
	{
		.type        = RTE_ACL_FIELD_TYPE_RANGE,
		.size        = sizeof(uint16_t),
		.field_index = 4,
		.input_index = 3,
		.offset      = offsetof(five_tuple_t, dst_port),
	},
};

/* ============================================================
 * DEFINE KIEU ACL RULE VOI 5 FIELD
 * Macro RTE_ACL_RULE_DEF tao struct co:
 *   struct rte_acl_rule_data data;
 *   struct rte_acl_field field[5];
 * ============================================================ */
RTE_ACL_RULE_DEF(acl_ipv4_rule, NUM_FIELDS_IPV4);

/* ============================================================
 * HAM TIEN ICH: mask_to_depth()
 * ------------------------------------------------------------
 * Convert subnet mask dang bitmask (vd 0xFFFFC000) sang "depth"
 * (so bit lien tiep tu MSB, vd 18).
 *
 * DPDK ACL dung "depth" cho field type RTE_ACL_FIELD_TYPE_MASK,
 * KHONG dung bitmask truc tiep. Vi du:
 *   IP 31.13.64.0/18 -> mask_range.u32 = 18 (khong phai 0xFFFFC000)
 *
 * Tham khao: rte_acl.h dong 81:
 *   "mask -> 1.2.3.4/32 value=0x1020304, mask_range=32"
 * ============================================================ */
static inline uint32_t
mask_to_depth(uint32_t mask)
{
	if (mask == 0)
		return 0;

	/* __builtin_popcount dem so bit 1 trong mask.
	 * Vi subnet mask hop le la cac bit 1 lien tiep tu MSB,
	 * nen popcount = so bit prefix (depth). */
	return (uint32_t)__builtin_popcount(mask);
}

/* ============================================================
 * acl_init()
 * ------------------------------------------------------------
 * Tao DPDK ACL context rong, san sang de add rules.
 *
 * Chon kieu tra ve int + ctx qua con tro output vi:
 *   - Nhat quan voi phong cach error handling cua DPDK (return
 *     negative on error).
 *   - Cho phep main.c kiem tra return code va tu quyet dinh
 *     cach xu ly loi (rte_exit hoac retry), khong ep module
 *     phai tu exit.
 *   - Tranh tra ve NULL ma khong co thong tin loi cu the.
 * ============================================================ */
int
acl_init(struct rte_acl_ctx **ctx_out)
{
	struct rte_acl_param acl_param;
	struct rte_acl_ctx *ctx;

	if (ctx_out == NULL) {
		fprintf(stderr, "[ACL] Loi: ctx_out la NULL\n");
		return -1;
	}

	*ctx_out = NULL;

	memset(&acl_param, 0, sizeof(acl_param));
	acl_param.name         = "spifast_acl_ctx";
	acl_param.socket_id    = rte_socket_id();
	acl_param.rule_size    = RTE_ACL_RULE_SZ(NUM_FIELDS_IPV4);
	acl_param.max_rule_num = MAX_RULES;

	ctx = rte_acl_create(&acl_param);
	if (ctx == NULL) {
		fprintf(stderr,
			"[ACL] Loi: rte_acl_create() that bai: %s\n",
			rte_strerror(rte_errno));
		return -1;
	}

	printf("[ACL] Da tao ACL context '%s' (socket=%d, max_rules=%u)\n",
		acl_param.name, acl_param.socket_id, acl_param.max_rule_num);

	*ctx_out = ctx;
	return 0;
}

/* ============================================================
 * acl_add_rules_from_parsed()
 * ------------------------------------------------------------
 * Duyet parsed_rules[0..num_rules-1], convert tung rule sang
 * struct acl_ipv4_rule, gom vao mang roi goi rte_acl_add_rules()
 * MOT LAN duy nhat (toi uu, giam overhead goi API nhieu lan).
 * Sau do goi rte_acl_build() voi field defs da dinh nghia.
 * ============================================================ */
int
acl_add_rules_from_parsed(struct rte_acl_ctx *ctx)
{
	struct acl_ipv4_rule rules[MAX_RULES];
	struct rte_acl_config acl_build_cfg;
	int ret;
	int i;

	if (ctx == NULL) {
		fprintf(stderr, "[ACL] Loi: ACL context la NULL\n");
		return -1;
	}

	if (num_rules <= 0) {
		fprintf(stderr, "[ACL] Loi: Khong co rule nao de add "
			"(num_rules=%d). Da goi load_rules() chua?\n",
			num_rules);
		return -1;
	}

	if (num_rules > MAX_RULES - 1) {
		fprintf(stderr, "[ACL] Loi: num_rules=%d vuot qua MAX_RULES-1=%d\n",
			num_rules, MAX_RULES - 1);
		return -1;
	}

	/* --------------------------------------------------------
	 * BUOC 1: Convert parsed_rules[] -> acl_ipv4_rule[]
	 * -------------------------------------------------------- */
	memset(rules, 0, sizeof(rules));

	for (i = 0; i < num_rules; i++) {
		const parsed_rule_t *pr = &parsed_rules[i];
		struct acl_ipv4_rule *ar = &rules[i];

		/* --- Rule metadata --- */
		ar->data.userdata      = pr->userdata;
		ar->data.category_mask = 1;  /* 1 category duy nhat */
		ar->data.priority      = (int32_t)pr->precedence;

		/* --- Field 0: protocol (BITMASK) ---
		 * 1 byte, khong co van de byte order */
		ar->field[0].value.u8      = pr->protocol;
		ar->field[0].mask_range.u8 = pr->protocol_mask;

		/* --- Field 1: src_ip (MASK) ---
		 * Rule values o HOST byte order. DPDK ACL trie builder
		 * tu dong convert sang NBO internally khi build trie.
		 * mask_range = depth (so bit prefix) — giu nguyen. */
		ar->field[1].value.u32      = pr->src_ip;
		ar->field[1].mask_range.u32 = mask_to_depth(pr->src_mask);

		/* --- Field 2: dst_ip (MASK) --- */
		ar->field[2].value.u32      = pr->dst_ip;
		ar->field[2].mask_range.u32 = mask_to_depth(pr->dst_mask);

		/* --- Field 3: src_port (RANGE) ---
		 * Rule values o HOST byte order.
		 * DPDK ACL trie builder tu convert sang NBO internally. */
		ar->field[3].value.u16      = pr->src_port_low;
		ar->field[3].mask_range.u16 = pr->src_port_high;

		/* --- Field 4: dst_port (RANGE) --- */
		ar->field[4].value.u16      = pr->dst_port_low;
		ar->field[4].mask_range.u16 = pr->dst_port_high;
	}

	/* --------------------------------------------------------
	 * BUOC 2: Add tat ca rules vao ACL context (1 lan duy nhat)
	 * -------------------------------------------------------- */
	ret = rte_acl_add_rules(ctx,
		(const struct rte_acl_rule *)rules,
		(uint32_t)num_rules);
	if (ret != 0) {
		fprintf(stderr,
			"[ACL] Loi: rte_acl_add_rules() that bai (ret=%d): %s\n",
			ret, rte_strerror(-ret));
		return -1;
	}

	printf("[ACL] Da add %d rule vao ACL context\n", num_rules);

	/* --------------------------------------------------------
	 * BUOC 3: Build trie noi bo tu cac rule da add
	 * -------------------------------------------------------- */
	memset(&acl_build_cfg, 0, sizeof(acl_build_cfg));
	acl_build_cfg.num_categories = 1;  /* 1 category duy nhat */
	acl_build_cfg.num_fields     = NUM_FIELDS_IPV4;
	acl_build_cfg.max_size       = 0;  /* 0 = DPDK tu chon kich thuoc toi uu */

	/* Copy field definitions vao config */
	memcpy(acl_build_cfg.defs, ipv4_field_defs, sizeof(ipv4_field_defs));

	ret = rte_acl_build(ctx, &acl_build_cfg);
	if (ret != 0) {
		fprintf(stderr,
			"[ACL] Loi: rte_acl_build() that bai (ret=%d): %s\n",
			ret, rte_strerror(-ret));
		return -1;
	}

	printf("[ACL] Build ACL trie thanh cong (%d rules, %d fields)\n",
		num_rules, NUM_FIELDS_IPV4);

	/* Dump ACL context de debug (in ra console) */
	rte_acl_dump(ctx);

	/* --------------------------------------------------------
	 * [ACL_TEST] Inline classify test — xac dinh byte order
	 * --------------------------------------------------------
	 * Test voi CA HAI byte order (host-order va network-byte-order)
	 * de xac dinh root cause cua bug "always userdata=0".
	 * -------------------------------------------------------- */
	{
		five_tuple_t tHO;   /* Host-Order */
		five_tuple_t tNBO;  /* Network-Byte-Order */
		const uint8_t *data_ho[1];
		const uint8_t *data_nbo[1];
		uint32_t res_ho[1], res_nbo[1];

		printf("\n[ACL_TEST] === Inline classify test (sau build) ===\n");

		/* --- Test 1: TCP dst_port=80 (expect Rule 10, userdata=10) --- */
		memset(&tHO, 0, sizeof(tHO));
		tHO.protocol = 6;         /* TCP */
		tHO.src_ip   = 0x0A000001; /* 10.0.0.1 host-order */
		tHO.dst_ip   = 0x68141798; /* 104.20.23.152 host-order */
		tHO.src_port = 12345;     /* host-order */
		tHO.dst_port = 80;        /* host-order */

		memset(&tNBO, 0, sizeof(tNBO));
		tNBO.protocol = 6;
		tNBO.src_ip   = rte_cpu_to_be_32(0x0A000001);
		tNBO.dst_ip   = rte_cpu_to_be_32(0x68141798);
		tNBO.src_port = rte_cpu_to_be_16(12345);
		tNBO.dst_port = rte_cpu_to_be_16(80);

		data_ho[0] = (const uint8_t *)&tHO;
		data_nbo[0] = (const uint8_t *)&tNBO;
		res_ho[0] = 0; res_nbo[0] = 0;

		rte_acl_classify(ctx, data_ho, res_ho, 1, 1);
		rte_acl_classify(ctx, data_nbo, res_nbo, 1, 1);

		printf("[ACL_TEST] Test 1 (TCP dport=80):  HO_userdata=%u  NBO_userdata=%u  (expect=10)\n",
			res_ho[0], res_nbo[0]);

		/* --- Test 2: UDP dst_port=53 (expect Rule 12, userdata=12) --- */
		memset(&tHO, 0, sizeof(tHO));
		tHO.protocol = 17;
		tHO.src_ip   = 0x0A000001;
		tHO.dst_ip   = 0x08080808; /* 8.8.8.8 */
		tHO.src_port = 55555;
		tHO.dst_port = 53;

		memset(&tNBO, 0, sizeof(tNBO));
		tNBO.protocol = 17;
		tNBO.src_ip   = rte_cpu_to_be_32(0x0A000001);
		tNBO.dst_ip   = rte_cpu_to_be_32(0x08080808);
		tNBO.src_port = rte_cpu_to_be_16(55555);
		tNBO.dst_port = rte_cpu_to_be_16(53);

		data_ho[0] = (const uint8_t *)&tHO;
		data_nbo[0] = (const uint8_t *)&tNBO;
		res_ho[0] = 0; res_nbo[0] = 0;

		rte_acl_classify(ctx, data_ho, res_ho, 1, 1);
		rte_acl_classify(ctx, data_nbo, res_nbo, 1, 1);

		printf("[ACL_TEST] Test 2 (UDP dport=53):  HO_userdata=%u  NBO_userdata=%u  (expect=12)\n",
			res_ho[0], res_nbo[0]);

		/* --- Test 3: TCP dst_port=443 (expect Rule 11, userdata=11) --- */
		memset(&tHO, 0, sizeof(tHO));
		tHO.protocol = 6;
		tHO.src_ip   = 0x0A000002;
		tHO.dst_ip   = 0xC0A80001; /* 192.168.0.1 */
		tHO.src_port = 40000;
		tHO.dst_port = 443;

		memset(&tNBO, 0, sizeof(tNBO));
		tNBO.protocol = 6;
		tNBO.src_ip   = rte_cpu_to_be_32(0x0A000002);
		tNBO.dst_ip   = rte_cpu_to_be_32(0xC0A80001);
		tNBO.src_port = rte_cpu_to_be_16(40000);
		tNBO.dst_port = rte_cpu_to_be_16(443);

		data_ho[0] = (const uint8_t *)&tHO;
		data_nbo[0] = (const uint8_t *)&tNBO;
		res_ho[0] = 0; res_nbo[0] = 0;

		rte_acl_classify(ctx, data_ho, res_ho, 1, 1);
		rte_acl_classify(ctx, data_nbo, res_nbo, 1, 1);

		printf("[ACL_TEST] Test 3 (TCP dport=443): HO_userdata=%u  NBO_userdata=%u  (expect=11)\n",
			res_ho[0], res_nbo[0]);

		printf("[ACL_TEST] === Ket luan: Neu NBO match va HO khong -> "
			"ACL expect NBO data ===\n\n");
	}

	return 0;
}
