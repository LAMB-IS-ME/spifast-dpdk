/* ============================================================
 * SPIFast - parser.h
 * ------------------------------------------------------------
 * Module Parser: khai bao cac cau truc du lieu va ham de
 * load file SPI_policy.csv va SPI_rule.csv theo dung thu tu
 * quy dinh trong MASTER_SPEC.md muc 4.2.
 *
 * KHONG chua logic ACL, Header Parse, Dispatcher hay bat ky
 * phan nao khac ngoai pham vi Parser.
 * ============================================================ */

#ifndef SPIFAST_PARSER_H
#define SPIFAST_PARSER_H

#include <stdint.h>

/* ------------------------------------------------------------
 * Hang so gioi han (dong bo voi MASTER_SPEC muc 4.1)
 * ------------------------------------------------------------ */
#define MAX_RULES   1024
#define MAX_GROUPS  256

/* ------------------------------------------------------------
 * Action constants
 * ------------------------------------------------------------ */
#define ACTION_DROP     0
#define ACTION_FORWARD  1

/* ------------------------------------------------------------
 * Cau truc 5-Tuple dung lam input layout cho DPDK ACL
 * (dong bo voi MASTER_SPEC muc 4.1)
 *
 * THU TU cac field PHAI khop voi rte_acl_field_def[]:
 *   protocol -> src_ip -> dst_ip -> src_port -> dst_port
 * De dam bao offsetof() trong ACL field defs la chinh xac.
 * ------------------------------------------------------------ */
typedef struct {
	uint8_t  protocol;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
} five_tuple_t;

/* ------------------------------------------------------------
 * Cau truc anh xa Policy: group_name -> {precedence, action}
 * Load tu SPI_policy.csv
 * ------------------------------------------------------------ */
typedef struct {
	char     group_name[64];
	uint32_t precedence;
	uint32_t action;        /* ACTION_FORWARD hoac ACTION_DROP */
} policy_entry_t;

/* Bang policy toan cuc */
extern policy_entry_t policy_table[MAX_GROUPS];
extern int            num_policies;

/* ------------------------------------------------------------
 * Cau truc anh xa Userdata -> {group_name, action}
 * Dung de tra cuu sau khi rte_acl_classify() tra ve userdata
 * (dong bo voi MASTER_SPEC muc 4.1 va 4.3)
 * ------------------------------------------------------------ */
typedef struct {
	char     group_name[64];
	uint32_t action;        /* ACTION_FORWARD hoac ACTION_DROP */
} action_map_t;

/* Mang toan cuc: action_map[userdata] -> {group_name, action}
 * userdata = so_thu_tu_dong_CSV + 1  (userdata=0 danh cho "no match")
 * Index 0 khong su dung cho rule that. */
extern action_map_t action_map[MAX_RULES];

/* ------------------------------------------------------------
 * Cau truc luu tru Rule da parse (5-tuple + metadata)
 * De module ACL su dung khi add rules sau nay
 * ------------------------------------------------------------ */
typedef struct {
	/* Destination IP + mask */
	uint32_t dst_ip;
	uint32_t dst_mask;      /* VD: 0xFFFFC000 cho /18 */

	/* Source IP + mask */
	uint32_t src_ip;
	uint32_t src_mask;

	/* Port ranges */
	uint16_t dst_port_low;
	uint16_t dst_port_high;
	uint16_t src_port_low;
	uint16_t src_port_high;

	/* Protocol: IPPROTO_TCP(6), IPPROTO_UDP(17), 0=any */
	uint8_t  protocol;
	uint8_t  protocol_mask; /* 0xFF neu co protocol cu the, 0x00 neu wildcard */

	/* Metadata tu Policy */
	uint32_t precedence;
	uint32_t userdata;      /* = so_thu_tu_dong + 1 */

	/* Ten group de tham chieu */
	char     group_name[64];
} parsed_rule_t;

/* Mang toan cuc chua tat ca rule da parse */
extern parsed_rule_t parsed_rules[MAX_RULES];
extern int           num_rules;

/* ------------------------------------------------------------
 * API chinh cua module Parser
 * PHAI goi load_policy() TRUOC load_rules() (theo spec)
 * ------------------------------------------------------------ */

/**
 * Load file SPI_policy.csv, build bang policy_table[].
 * @param filepath  Duong dan toi file SPI_policy.csv
 * @return So policy da load thanh cong, hoac -1 neu loi.
 */
int load_policy(const char *filepath);

/**
 * Load file SPI_rule.csv, parse 10 cot va build:
 *   - parsed_rules[] (mang rule da parse)
 *   - action_map[]   (anh xa userdata -> group_name + action)
 *
 * YEU CAU: load_policy() phai duoc goi truoc ham nay.
 *
 * @param filepath  Duong dan toi file SPI_rule.csv
 * @return So rule da load thanh cong, hoac -1 neu loi.
 */
int load_rules(const char *filepath);

#endif /* SPIFAST_PARSER_H */
