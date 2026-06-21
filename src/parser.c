/* ============================================================
 * SPIFast - parser.c
 * ------------------------------------------------------------
 * Module Parser: doc va parse 2 file CSV cau hinh:
 *   1. SPI_policy.csv  -> bang anh xa group -> {precedence, action}
 *   2. SPI_rule.csv    -> mang parsed_rules[] va action_map[]
 *
 * Thu tu load BAT BUOC: Policy truoc, Rule sau.
 * (Theo MASTER_SPEC.md muc 4.2)
 *
 * KHONG chua logic ACL, Header Parse, Dispatcher hay bat ky
 * phan nao khac ngoai pham vi Parser.
 * ============================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>     /* inet_pton, htonl */
#include <netinet/in.h>    /* IPPROTO_TCP, IPPROTO_UDP */

#include <rte_log.h>
#include <rte_common.h>

#include "parser.h"

/* ------------------------------------------------------------
 * Dinh nghia cac bien toan cuc (extern trong parser.h)
 * ------------------------------------------------------------ */
policy_entry_t policy_table[MAX_GROUPS];
int            num_policies = 0;

action_map_t   action_map[MAX_RULES];
int            num_rules = 0;

parsed_rule_t  parsed_rules[MAX_RULES];

/* ------------------------------------------------------------
 * Kich thuoc buffer doc dong CSV
 * ------------------------------------------------------------ */
#define LINE_BUF_SIZE 2048

/* ============================================================
 * HAM TIEN ICH NỘI BỘ (static)
 * ============================================================ */

/**
 * trim() - Xoa khoang trang / tab / newline o dau va cuoi chuoi.
 * Thao tac in-place, tra ve con tro toi vi tri dau tien khong phai
 * whitespace. Cuoi chuoi duoc cat bang '\0'.
 */
static char *
trim(char *str)
{
	char *end;

	if (str == NULL)
		return NULL;

	/* Bo khoang trang dau */
	while (isspace((unsigned char)*str))
		str++;

	/* Chuoi rong sau khi trim */
	if (*str == '\0')
		return str;

	/* Bo khoang trang cuoi */
	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char)*end))
		end--;
	*(end + 1) = '\0';

	return str;
}

/**
 * is_wildcard() - Kiem tra xem gia tri cot co phai wildcard khong.
 * Wildcard = "NA", "N/A", "any", hoac chuoi rong.
 * So sanh case-insensitive.
 */
static int
is_wildcard(const char *val)
{
	if (val == NULL || *val == '\0')
		return 1;
	if (strcasecmp(val, "NA") == 0)
		return 1;
	if (strcasecmp(val, "N/A") == 0)
		return 1;
	if (strcasecmp(val, "any") == 0)
		return 1;
	return 0;
}

/**
 * parse_ip_prefix() - Parse mot IP dang CIDR (vd "31.13.64.0/18")
 * hoac IP don (vd "69.220.144.5" -> /32).
 *
 * @param str       Chuoi IP CIDR hoac IP don
 * @param out_ip    [out] Dia chi IP dang host-byte-order
 * @param out_mask  [out] Subnet mask dang host-byte-order
 * @return 0 thanh cong, -1 loi
 */
static int
parse_ip_prefix(const char *str, uint32_t *out_ip, uint32_t *out_mask)
{
	char buf[64];
	char *slash;
	int prefix_len;
	struct in_addr addr;

	if (str == NULL || *str == '\0')
		return -1;

	snprintf(buf, sizeof(buf), "%s", str);

	slash = strchr(buf, '/');
	if (slash != NULL) {
		*slash = '\0';
		prefix_len = atoi(slash + 1);
		if (prefix_len < 0 || prefix_len > 32)
			return -1;
	} else {
		/* IP don, xem nhu /32 */
		prefix_len = 32;
	}

	if (inet_pton(AF_INET, buf, &addr) != 1)
		return -1;

	/* inet_pton tra ve network-byte-order, chuyen sang host-byte-order */
	*out_ip = ntohl(addr.s_addr);

	/* Tao subnet mask tu prefix_len */
	if (prefix_len == 0)
		*out_mask = 0;
	else
		*out_mask = 0xFFFFFFFFU << (32 - prefix_len);

	return 0;
}

/**
 * parse_port_range() - Parse mot port don (vd "80" -> 80-80)
 * hoac range (vd "80-443" -> 80-443).
 *
 * @param str       Chuoi port
 * @param out_low   [out] Port thap
 * @param out_high  [out] Port cao
 * @return 0 thanh cong, -1 loi
 */
static int
parse_port_range(const char *str, uint16_t *out_low, uint16_t *out_high)
{
	char buf[64];
	char *dash;
	long low, high;

	if (str == NULL || *str == '\0')
		return -1;

	snprintf(buf, sizeof(buf), "%s", str);

	dash = strchr(buf, '-');
	if (dash != NULL) {
		*dash = '\0';
		low  = strtol(buf, NULL, 10);
		high = strtol(dash + 1, NULL, 10);
	} else {
		/* Port don: range la port-port */
		low = strtol(buf, NULL, 10);
		high = low;
	}

	if (low < 0 || low > 65535 || high < 0 || high > 65535 || low > high)
		return -1;

	*out_low  = (uint16_t)low;
	*out_high = (uint16_t)high;

	return 0;
}

/**
 * parse_protocol() - Parse protocol tu chuoi hoac so.
 * Nhan: "tcp", "udp", "6", "17", wildcard.
 *
 * @param str        Chuoi protocol
 * @param out_proto  [out] IPPROTO_TCP(6), IPPROTO_UDP(17), 0 (any)
 * @param out_mask   [out] 0xFF neu co protocol, 0x00 neu wildcard
 * @return 0 thanh cong, -1 loi
 */
static int
parse_protocol(const char *str, uint8_t *out_proto, uint8_t *out_mask)
{
	if (is_wildcard(str)) {
		*out_proto = 0;
		*out_mask  = 0x00;
		return 0;
	}

	if (strcasecmp(str, "tcp") == 0) {
		*out_proto = IPPROTO_TCP;
		*out_mask  = 0xFF;
		return 0;
	}

	if (strcasecmp(str, "udp") == 0) {
		*out_proto = IPPROTO_UDP;
		*out_mask  = 0xFF;
		return 0;
	}

	/* Thu parse dang so */
	{
		long val = strtol(str, NULL, 10);
		if (val == IPPROTO_TCP || val == IPPROTO_UDP) {
			*out_proto = (uint8_t)val;
			*out_mask  = 0xFF;
			return 0;
		}
	}

	return -1;
}

/**
 * lookup_policy() - Tim policy theo group_name trong policy_table[].
 * @return Con tro toi policy_entry_t, hoac NULL neu khong tim thay.
 */
static const policy_entry_t *
lookup_policy(const char *group_name)
{
	int i;

	for (i = 0; i < num_policies; i++) {
		if (strcmp(policy_table[i].group_name, group_name) == 0)
			return &policy_table[i];
	}
	return NULL;
}

/* ============================================================
 * LOAD POLICY: doc SPI_policy.csv
 * Format: No,l34-filter-group,Precedence,Action
 * ============================================================ */
int
load_policy(const char *filepath)
{
	FILE *fp;
	char line[LINE_BUF_SIZE];
	int  line_no = 0;

	fp = fopen(filepath, "r");
	if (fp == NULL) {
		fprintf(stderr, "[PARSER] Loi: Khong the mo file policy '%s'\n",
			filepath);
		return -1;
	}

	num_policies = 0;

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *cols[4];
		char *token;
		int   col_idx = 0;
		char *saveptr = NULL;
		char *trimmed;

		line_no++;

		/* Bo dong header (dong 1) */
		if (line_no == 1)
			continue;

		/* Bo dong rong */
		trimmed = trim(line);
		if (*trimmed == '\0')
			continue;

		/* Tach 4 cot: No, l34-filter-group, Precedence, Action */
		token = strtok_r(trimmed, ",", &saveptr);
		while (token != NULL && col_idx < 4) {
			cols[col_idx] = trim(token);
			col_idx++;
			token = strtok_r(NULL, ",", &saveptr);
		}

		if (col_idx < 4) {
			fprintf(stderr,
				"[PARSER] Canh bao: Dong %d trong '%s' khong du 4 cot, bo qua\n",
				line_no, filepath);
			continue;
		}

		/* Kiem tra gioi han */
		if (num_policies >= MAX_GROUPS) {
			fprintf(stderr,
				"[PARSER] Loi: Vuot qua gioi han MAX_GROUPS=%d tai dong %d\n",
				MAX_GROUPS, line_no);
			fclose(fp);
			return -1;
		}

		/* cols[0] = No (bo qua)
		 * cols[1] = l34-filter-group
		 * cols[2] = Precedence
		 * cols[3] = Action */

		policy_entry_t *entry = &policy_table[num_policies];

		snprintf(entry->group_name, sizeof(entry->group_name),
			"%s", cols[1]);
		entry->precedence = (uint32_t)strtoul(cols[2], NULL, 10);

		if (strcasecmp(cols[3], "FORWARD") == 0) {
			entry->action = ACTION_FORWARD;
		} else if (strcasecmp(cols[3], "DROP") == 0) {
			entry->action = ACTION_DROP;
		} else {
			fprintf(stderr,
				"[PARSER] Loi: Action khong hop le '%s' tai dong %d "
				"trong '%s' (chi chap nhan FORWARD hoac DROP)\n",
				cols[3], line_no, filepath);
			fclose(fp);
			return -1;
		}

		num_policies++;
	}

	fclose(fp);

	printf("[PARSER] Da load %d policy tu '%s'\n", num_policies, filepath);

	/* In chi tiet de debug */
	for (int i = 0; i < num_policies; i++) {
		printf("  Policy[%d]: group=%-30s precedence=%-5u action=%s\n",
			i,
			policy_table[i].group_name,
			policy_table[i].precedence,
			policy_table[i].action == ACTION_FORWARD ? "FORWARD" : "DROP");
	}

	return num_policies;
}

/* ============================================================
 * LOAD RULES: doc SPI_rule.csv
 * Format 10 cot:
 *   no., l34-filter, l34-filter-group, network-prefix,
 *   network-address, network-port, protocol,
 *   src-ip, src-prefix, src-port
 *
 * Quy tac:
 *   - Wildcard: NA, N/A, any, rong -> 0.0.0.0/0, port 0:65535
 *   - IP dich: uu tien network-prefix, fallback network-address
 *   - IP nguon: uu tien src-ip, fallback src-prefix
 *   - Port don -> range (vd 80 -> 80-80)
 *   - Protocol: tcp/udp/6/17/wildcard
 *   - userdata = (thu tu dong CSV) + 1  (userdata=0 = "no match")
 *   - group_name PHAI ton tai trong policy_table[], neu khong -> fatal
 * ============================================================ */
int
load_rules(const char *filepath)
{
	FILE *fp;
	char line[LINE_BUF_SIZE];
	int  line_no = 0;

	/* Kiem tra policy da duoc load chua */
	if (num_policies <= 0) {
		fprintf(stderr,
			"[PARSER] Loi: Chua load policy! Phai goi load_policy() truoc load_rules().\n");
		return -1;
	}

	fp = fopen(filepath, "r");
	if (fp == NULL) {
		fprintf(stderr, "[PARSER] Loi: Khong the mo file rule '%s'\n",
			filepath);
		return -1;
	}

	num_rules = 0;

	/* Khoi tao action_map[0] - danh rieng cho "no match" (Zero-Trust) */
	memset(&action_map[0], 0, sizeof(action_map[0]));
	snprintf(action_map[0].group_name, sizeof(action_map[0].group_name),
		"Default/Unmatched");
	action_map[0].action = ACTION_DROP;

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *cols[10];
		char *token;
		int   col_idx = 0;
		char *saveptr = NULL;
		char *trimmed;

		line_no++;

		/* Bo dong header (dong 1) */
		if (line_no == 1)
			continue;

		/* Bo dong rong */
		trimmed = trim(line);
		if (*trimmed == '\0')
			continue;

		/* Tach 10 cot */
		token = strtok_r(trimmed, ",", &saveptr);
		while (token != NULL && col_idx < 10) {
			cols[col_idx] = trim(token);
			col_idx++;
			token = strtok_r(NULL, ",", &saveptr);
		}

		/* Canh bao neu thieu cot */
		if (col_idx < 10) {
			fprintf(stderr,
				"[PARSER] Canh bao: Dong %d trong '%s' chi co %d/10 cot, "
				"cac cot con lai duoc coi la wildcard\n",
				line_no, filepath, col_idx);
		}

		/* Neu thieu cot, pad bang chuoi rong (= wildcard) */
		while (col_idx < 10) {
			cols[col_idx] = "";
			col_idx++;
		}

		/* Kiem tra gioi han */
		if (num_rules >= MAX_RULES - 1) {
			/* MAX_RULES - 1 vi action_map[0] da danh cho "no match" */
			fprintf(stderr,
				"[PARSER] Loi: Vuot qua gioi han MAX_RULES=%d tai dong %d\n",
				MAX_RULES, line_no);
			fclose(fp);
			return -1;
		}

		parsed_rule_t *rule = &parsed_rules[num_rules];
		memset(rule, 0, sizeof(*rule));

		/* ----------------------------------------------------------
		 * cols[0] = no.           (bo qua, dung line_no lam tham chieu)
		 * cols[1] = l34-filter    (bo qua, chi de doc)
		 * cols[2] = l34-filter-group
		 * cols[3] = network-prefix
		 * cols[4] = network-address
		 * cols[5] = network-port  (dst port)
		 * cols[6] = protocol
		 * cols[7] = src-ip
		 * cols[8] = src-prefix
		 * cols[9] = src-port
		 * ---------------------------------------------------------- */

		/* --- Group name & Policy lookup --- */
		const char *group = cols[2];

		snprintf(rule->group_name, sizeof(rule->group_name), "%s", group);

		const policy_entry_t *pol = lookup_policy(group);
		if (pol == NULL) {
			fprintf(stderr,
				"[PARSER] LOI NGHIEM TRONG: Dong %d - group_name '%s' "
				"KHONG ton tai trong SPI_policy.csv!\n"
				"  -> Kiem tra lai file policy hoac rule.\n",
				line_no, group);
			fclose(fp);
			/* Fatal exit theo yeu cau spec - khong am tham bo qua */
			rte_exit(EXIT_FAILURE,
				"Parser: group '%s' (dong %d) khong co trong policy. "
				"Dung chuong trinh.\n", group, line_no);
			return -1; /* Khong bao gio chay toi day, rte_exit() da exit */
		}

		rule->precedence = pol->precedence;

		/* --- Destination IP --- */
		/* Uu tien network-prefix, fallback network-address */
		if (!is_wildcard(cols[3])) {
			/* Dung network-prefix */
			if (parse_ip_prefix(cols[3], &rule->dst_ip, &rule->dst_mask) != 0) {
				fprintf(stderr,
					"[PARSER] Loi: Parse dst IP prefix '%s' that bai tai dong %d\n",
					cols[3], line_no);
				fclose(fp);
				return -1;
			}
		} else if (!is_wildcard(cols[4])) {
			/* Fallback: dung network-address (IP don -> /32) */
			if (parse_ip_prefix(cols[4], &rule->dst_ip, &rule->dst_mask) != 0) {
				fprintf(stderr,
					"[PARSER] Loi: Parse dst IP address '%s' that bai tai dong %d\n",
					cols[4], line_no);
				fclose(fp);
				return -1;
			}
		} else {
			/* Wildcard: 0.0.0.0/0 */
			rule->dst_ip   = 0;
			rule->dst_mask = 0;
		}

		/* --- Source IP --- */
		/* Uu tien src-ip, fallback src-prefix */
		if (!is_wildcard(cols[7])) {
			/* Dung src-ip */
			if (parse_ip_prefix(cols[7], &rule->src_ip, &rule->src_mask) != 0) {
				fprintf(stderr,
					"[PARSER] Loi: Parse src IP '%s' that bai tai dong %d\n",
					cols[7], line_no);
				fclose(fp);
				return -1;
			}
		} else if (!is_wildcard(cols[8])) {
			/* Fallback: dung src-prefix */
			if (parse_ip_prefix(cols[8], &rule->src_ip, &rule->src_mask) != 0) {
				fprintf(stderr,
					"[PARSER] Loi: Parse src prefix '%s' that bai tai dong %d\n",
					cols[8], line_no);
				fclose(fp);
				return -1;
			}
		} else {
			/* Wildcard: 0.0.0.0/0 */
			rule->src_ip   = 0;
			rule->src_mask = 0;
		}

		/* --- Destination Port (network-port) --- */
		if (is_wildcard(cols[5])) {
			rule->dst_port_low  = 0;
			rule->dst_port_high = 65535;
		} else {
			if (parse_port_range(cols[5], &rule->dst_port_low,
					     &rule->dst_port_high) != 0) {
				fprintf(stderr,
					"[PARSER] Loi: Parse dst port '%s' that bai tai dong %d\n",
					cols[5], line_no);
				fclose(fp);
				return -1;
			}
		}

		/* --- Source Port --- */
		if (is_wildcard(cols[9])) {
			rule->src_port_low  = 0;
			rule->src_port_high = 65535;
		} else {
			if (parse_port_range(cols[9], &rule->src_port_low,
					     &rule->src_port_high) != 0) {
				fprintf(stderr,
					"[PARSER] Loi: Parse src port '%s' that bai tai dong %d\n",
					cols[9], line_no);
				fclose(fp);
				return -1;
			}
		}

		/* --- Protocol --- */
		if (parse_protocol(cols[6], &rule->protocol,
				   &rule->protocol_mask) != 0) {
			fprintf(stderr,
				"[PARSER] Loi: Parse protocol '%s' that bai tai dong %d\n",
				cols[6], line_no);
			fclose(fp);
			return -1;
		}

		/* --- Userdata = (so thu tu dong) + 1 --- */
		/* num_rules la 0-based, userdata bat dau tu 1 */
		rule->userdata = (uint32_t)(num_rules + 1);

		/* --- Build action_map[userdata] --- */
		action_map[rule->userdata].action = pol->action;
		snprintf(action_map[rule->userdata].group_name,
			sizeof(action_map[rule->userdata].group_name),
			"%s", group);

		num_rules++;
	}

	fclose(fp);

	printf("[PARSER] Da load %d rule tu '%s'\n", num_rules, filepath);

	/* In chi tiet de debug / kiem chung */
	for (int i = 0; i < num_rules; i++) {
		parsed_rule_t *r = &parsed_rules[i];
		printf("  Rule[%2d]: userdata=%-3u group=%-25s "
			"dst=%u.%u.%u.%u/%-2u src=%u.%u.%u.%u/%-2u "
			"dport=%u-%u sport=%u-%u proto=%-3u "
			"precedence=%-5u action=%s\n",
			i, r->userdata, r->group_name,
			(r->dst_ip >> 24) & 0xFF,
			(r->dst_ip >> 16) & 0xFF,
			(r->dst_ip >> 8)  & 0xFF,
			 r->dst_ip        & 0xFF,
			/* Tinh prefix len tu mask */
			r->dst_mask == 0 ? 0 : __builtin_popcount(r->dst_mask),
			(r->src_ip >> 24) & 0xFF,
			(r->src_ip >> 16) & 0xFF,
			(r->src_ip >> 8)  & 0xFF,
			 r->src_ip        & 0xFF,
			r->src_mask == 0 ? 0 : __builtin_popcount(r->src_mask),
			r->dst_port_low, r->dst_port_high,
			r->src_port_low, r->src_port_high,
			r->protocol,
			r->precedence,
			action_map[r->userdata].action == ACTION_FORWARD
				? "FORWARD" : "DROP");
	}

	return num_rules;
}
