# SPIFast — API Reference

> **Phiên bản:** 1.0 (2026-07-07)  
> **Mô tả:** Tài liệu tham chiếu đầy đủ cho tất cả hàm, cấu trúc và biến toàn cục trong SPIFast.

---

## Mục Lục

- [Module `header_parser`](#module-header_parser)
- [Module `parser`](#module-parser)
- [Module `acl`](#module-acl)
- [Module `worker`](#module-worker)
- [Module `main` (Internal Functions)](#module-main-internal-functions)
- [Cấu Trúc Dữ Liệu](#cấu-trúc-dữ-liệu)
- [Hằng Số](#hằng-số)
- [Biến Toàn Cục](#biến-toàn-cục)

---

## Module `header_parser`

**Header:** `src/header_parser.h`  
**Implementation:** `src/header_parser.c`

---

### `parse_packet_5tuple()`

```c
int parse_packet_5tuple(struct rte_mbuf *mbuf, five_tuple_t *out);
```

**Mô tả:** Trích xuất 5-tuple từ một mbuf bằng phương pháp Zero-copy (cast con trỏ). Parse L2 → L3 → L4.

**Tham số:**

| Tên | Hướng | Kiểu | Mô tả |
|---|---|---|---|
| `mbuf` | In | `struct rte_mbuf *` | Gói tin nhận từ `rte_eth_rx_burst()` |
| `out` | Ra | `five_tuple_t *` | Cấu trúc 5-tuple sẽ được điền dữ liệu |

**Giá trị trả về:**

| Giá trị | Ý nghĩa |
|---|---|
| `0` | Thành công — `out` đã được điền đầy đủ |
| `-1` | Packet không phải IPv4 (ARP, IPv6, ...) — caller phải `free` mbuf |

**Đặc điểm quan trọng:**
- Gán field-by-field, không `memcpy` raw (do padding trong `five_tuple_t`)
- Tất cả giá trị IP/port trong `out` giữ **Network Byte Order** (NBO) từ header gốc
- Protocol khác TCP/UDP: `src_port = dst_port = 0`, vẫn trả về `0` (để ACL quyết định)
- Tính L4 offset chính xác bằng `(ip->version_ihl & 0x0F) * 4` (hỗ trợ IP Options)

**Ví dụ sử dụng:**
```c
five_tuple_t tuple;
if (parse_packet_5tuple(mbuf, &tuple) < 0) {
    // Non-IPv4, skip
    rte_pktmbuf_free(mbuf);
    continue;
}
// tuple.src_ip, tuple.dst_ip ở NBO — đúng cho rte_acl_classify()
```

---

## Module `parser`

**Header:** `src/parser.h`  
**Implementation:** `src/parser.c`

---

### `load_policy()`

```c
int load_policy(const char *filepath);
```

**Mô tả:** Load file `SPI_policy.csv`, xây dựng bảng `policy_table[]`.

**Tham số:**

| Tên | Hướng | Kiểu | Mô tả |
|---|---|---|---|
| `filepath` | In | `const char *` | Đường dẫn tới file CSV (VD: `"SPI_policy.csv"`) |

**Giá trị trả về:**

| Giá trị | Ý nghĩa |
|---|---|
| `n > 0` | Số policy đã load thành công |
| `-1` | Lỗi (không mở được file, format sai, action không hợp lệ) |

**Side effects:**
- Ghi vào `policy_table[0..n-1]`
- Set `num_policies = n`

**Điều kiện tiên quyết:** Không có (đây là hàm load đầu tiên).

**Ràng buộc:** `Action` chỉ chấp nhận `"FORWARD"` hoặc `"DROP"` (case-insensitive). Giá trị khác → fatal error, `return -1`.

---

### `load_rules()`

```c
int load_rules(const char *filepath);
```

**Mô tả:** Load file `SPI_rule.csv`, xây dựng `parsed_rules[]` và `action_map[]`.

**Tham số:**

| Tên | Hướng | Kiểu | Mô tả |
|---|---|---|---|
| `filepath` | In | `const char *` | Đường dẫn tới file CSV (VD: `"SPI_rule.csv"`) |

**Giá trị trả về:**

| Giá trị | Ý nghĩa |
|---|---|
| `n > 0` | Số rule đã load thành công |
| `-1` | Lỗi (policy chưa load, file không mở được, parse lỗi) |
| *(không trả về)* | `rte_exit()` nếu `group_name` trong rule không tồn tại trong policy |

**Side effects:**
- Ghi vào `parsed_rules[0..n-1]`
- Ghi vào `action_map[1..n]` (index 0 = "Default/Unmatched")
- Set `num_rules = n`

**Điều kiện tiên quyết:** `load_policy()` phải được gọi trước.

**Xử lý cột thiếu:** Nếu dòng CSV thiếu cột → pad bằng `""` (= wildcard), in warning.

---

## Module `acl`

**Header:** `src/acl.h`  
**Implementation:** `src/acl.c`

---

### `acl_build_all()`

```c
int acl_build_all(void);
```

**Mô tả:** Xây dựng toàn bộ DPDK ACL contexts từ `parsed_rules[]` và `policy_table[]`.

**Giá trị trả về:**

| Giá trị | Ý nghĩa |
|---|---|
| `0` | Thành công — `filter_groups[].acl_ctx` đã sẵn sàng |
| `-1` | Lỗi: `num_rules <= 0`, `num_policies <= 0`, `rte_acl_create()` fail, `rte_acl_add_rules()` fail, `rte_acl_build()` fail |

**Side effects:**
- Populate `filter_groups[0..num_groups-1]`
- Sort `filter_groups[]` tăng dần theo `precedence`
- Gán `filter_groups[i].group_id = i` (sau sort)
- Tính `filter_groups[i].global_rule_offset`
- Populate `rule_action_map[]`
- Set `num_groups`, `num_rules_total`
- Gọi `rte_acl_create()` và `rte_acl_build()` cho mỗi group

**Điều kiện tiên quyết:** `load_policy()` và `load_rules()` đã thành công.

**Thứ tự sort:** Insertion sort `O(n²)` — chấp nhận được vì `n ≤ MAX_GROUPS = 256`.

---

### `acl_free_all()`

```c
void acl_free_all(void);
```

**Mô tả:** Giải phóng tất cả `rte_acl_ctx` trong `filter_groups[]`. Gọi khi thoát chương trình.

**Side effects:**
- Gọi `rte_acl_free(filter_groups[g].acl_ctx)` cho mỗi group có `acl_ctx != NULL`
- Set `filter_groups[g].acl_ctx = NULL` sau khi free

---

## Module `worker`

**Header:** `src/worker.h`  
**Implementation:** `src/worker.c`

---

### `worker_rings_init()`

```c
int worker_rings_init(void);
```

**Mô tả:** Khởi tạo `NUM_WORKERS` ring IPC (SPSC) và reset tất cả stats.

**Giá trị trả về:**

| Giá trị | Ý nghĩa |
|---|---|
| `0` | Thành công |
| `-1` | Lỗi: `rte_ring_create()` thất bại |

**Side effects:**
- Gán `worker_rings[0..NUM_WORKERS-1]`
- `memset(worker_stats, 0, ...)`
- `memset(&disp_stats, 0, ...)`

**Tên ring:** `"spifast_ring_{i}"` (i = 0, 1, 2, 3)

---

### `dispatcher_run()`

```c
int dispatcher_run(void *arg);
```

**Mô tả:** Vòng lặp chính của Dispatcher. Chạy trên **Master lcore 0**. Blocking cho đến khi nhận SIGINT.

**Tham số:**

| Tên | Hướng | Kiểu | Mô tả |
|---|---|---|---|
| `arg` | In | `void *` | Không dùng (tagged `__rte_unused`) |

**Giá trị trả về:** `0` (luôn — sau khi SIGINT và cleanup)

**Hành vi:**
1. Đăng ký signal handler cho `SIGINT`/`SIGTERM`
2. `while (!force_quit)`: Rx burst → parse → hash → enqueue
3. In runtime stats mỗi 1 giây
4. Khi `force_quit`: gửi NULL sentinel vào mỗi `worker_rings[i]`

**Side effects:**
- Cập nhật `disp_stats.*` liên tục
- In ra stdout mỗi giây
- Enqueue mbuf vào `worker_rings[]`

---

### `worker_main()`

```c
int worker_main(void *arg);
```

**Mô tả:** Vòng lặp chính của mỗi Worker. Chạy trên **Worker lcore 1–4**.

**Tham số:**

| Tên | Hướng | Kiểu | Mô tả |
|---|---|---|---|
| `arg` | In | `void *` | Cast từ `worker_id` (uint32_t): 0, 1, 2, hoặc 3 |

**Giá trị trả về:** `0` (khi nhận NULL sentinel và thoát sạch)

**Hành vi:**
1. Dequeue từ `worker_rings[worker_id]`
2. Nếu NULL → thoát
3. Parse 5-tuple
4. Classify tuần tự qua `filter_groups[]`
5. Cập nhật `worker_stats[worker_id].*`
6. `rte_pktmbuf_free(mbuf)`

**Điều kiện thoát:** Nhận `NULL` từ ring (sentinel do Dispatcher gửi khi SIGINT).

---

### `print_final_stats()`

```c
void print_final_stats(void);
```

**Mô tả:** Collect stats từ tất cả Worker và in tổng kết cuối. Verify Missing Rate = 0%.

**Điều kiện tiên quyết:** Tất cả Worker đã thoát (`rte_eal_mp_wait_lcore()` đã hoàn thành).

**Output:** In ra stdout theo format `SPI FINAL STATS` (xem mục 9.2 trong TECHNICAL_SPECIFICATION.md).

---

## Module `main` (Internal Functions)

---

### `spifast_mempool_init()` *(static)*

```c
static struct rte_mempool *spifast_mempool_init(void);
```

Tạo mempool tên `"SPIFAST_MBUF_POOL"` với 8192 mbufs, cache 256, data size `4096 + RTE_PKTMBUF_HEADROOM`. Gọi `rte_exit()` nếu thất bại.

---

### `spifast_check_ports()` *(static)*

```c
static uint16_t spifast_check_ports(void);
```

Kiểm tra `rte_eth_dev_count_avail() >= 1`. Gọi `rte_exit()` nếu không có port.

---

### `spifast_port_setup()` *(static)*

```c
static void spifast_port_setup(uint16_t port_id);
```

Configure port `port_id`:
- 1 RX queue, 0 TX queue
- `rxmode.offloads = 0` (scatter disabled — bắt buộc cho `infinite_rx`)
- 128 RX descriptors
- `rte_eth_dev_start()`

Gọi `rte_exit()` nếu bất kỳ bước nào thất bại.

---

## Cấu Trúc Dữ Liệu

### `five_tuple_t`

```c
typedef struct {
    uint8_t  protocol;   // offset 0
    // 3 bytes padding (tự nhiên)
    uint32_t src_ip;     // offset 4 — NBO
    uint32_t dst_ip;     // offset 8 — NBO
    uint16_t src_port;   // offset 12 — NBO
    uint16_t dst_port;   // offset 14 — NBO
} five_tuple_t;          // sizeof = 16
```

### `policy_entry_t`

```c
typedef struct {
    char     group_name[64];
    uint32_t precedence;
    uint32_t action;  // ACTION_FORWARD hoặc ACTION_DROP
} policy_entry_t;
```

### `action_map_t`

```c
typedef struct {
    char     group_name[64];
    uint32_t action;
} action_map_t;
// Dùng: action_map[userdata] → {group, action}
// userdata=0: "Default/Unmatched" (reserved)
// userdata=1..n: rule thứ (userdata-1) theo thứ tự CSV
```

### `parsed_rule_t`

```c
typedef struct {
    uint32_t dst_ip;         // HBO (sau ntohl)
    uint32_t dst_mask;       // VD: 0xFFFFC000 cho /18
    uint32_t src_ip;         // HBO
    uint32_t src_mask;
    uint16_t dst_port_low;
    uint16_t dst_port_high;
    uint16_t src_port_low;
    uint16_t src_port_high;
    uint8_t  protocol;       // IPPROTO_TCP/UDP, 0=any
    uint8_t  protocol_mask;  // 0xFF hoặc 0x00
    uint32_t precedence;
    uint32_t userdata;       // = dòng_CSV_index + 1
    char     group_name[64];
} parsed_rule_t;
```

### `rule_action_map_t`

```c
typedef struct {
    uint32_t group_id;
    char     group_name[64];
    uint32_t action;
} rule_action_map_t;
// Index: global rule index (0-based)
// rule_action_map[filter_groups[g].global_rule_offset + local_result - 1]
```

### `filter_group_t`

```c
typedef struct {
    uint32_t            group_id;           // 0-based sau khi sort
    char                group_name[64];
    uint32_t            action;
    uint32_t            precedence;
    struct rte_acl_ctx *acl_ctx;            // NULL nếu group rỗng
    uint32_t            num_rules;
    uint32_t            global_rule_offset; // offset vào rule_action_map[]
} filter_group_t;
```

### `worker_stats_t`

```c
typedef struct {
    volatile uint64_t hit_count[MAX_RULES];
    volatile uint64_t group_hit_count[MAX_GROUPS];
    volatile uint64_t default_drop_count;
    volatile uint64_t total_classified;
} worker_stats_t;
```

### `dispatcher_stats_t`

```c
typedef struct {
    volatile uint64_t total_rx_pkts;
    volatile uint64_t total_rx_bytes;
    volatile uint64_t ring_drop_count;
    volatile uint64_t non_ipv4_count;
} dispatcher_stats_t;
```

---

## Hằng Số

| Tên | Giá trị | File | Mô tả |
|---|---|---|---|
| `NUM_WORKERS` | `4` | `worker.h` | Số Worker lcore |
| `RING_SIZE` | `1024` | `worker.h` | Capacity mỗi ring |
| `HASH_SEED` | `0` | `worker.h` | Seed jhash (cố định) |
| `RX_BURST_SIZE` | `32` | `worker.h` | Burst size rx |
| `MAX_RULES` | `1024` | `parser.h` | Giới hạn tổng rule |
| `MAX_GROUPS` | `256` | `parser.h` | Giới hạn số group |
| `ACTION_DROP` | `0` | `parser.h` | DROP action |
| `ACTION_FORWARD` | `1` | `parser.h` | FORWARD action |
| `NUM_MBUFS` | `8192` | `main.c` | Số mbuf trong pool |
| `MBUF_CACHE_SIZE` | `256` | `main.c` | Per-lcore mbuf cache |
| `MBUF_DATA_SIZE` | `4096 + RTE_PKTMBUF_HEADROOM` | `main.c` | Max mbuf data size |
| `NUM_RX_DESC` | `128` | `main.c` | RX descriptors |
| `LINE_BUF_SIZE` | `2048` | `parser.c` | Buffer đọc dòng CSV |
| `NUM_FIELDS_IPV4` | `5` | `acl.c` | Số field ACL rule |
| `MBUF_POOL_NAME` | `"SPIFAST_MBUF_POOL"` | `main.c` | Tên mempool |

---

## Biến Toàn Cục

| Tên | Kiểu | Định nghĩa | Khai báo extern | Mô tả |
|---|---|---|---|---|
| `policy_table` | `policy_entry_t[MAX_GROUPS]` | `parser.c` | `parser.h` | Bảng policy từ CSV |
| `num_policies` | `int` | `parser.c` | `parser.h` | Số policy đã load |
| `action_map` | `action_map_t[MAX_RULES]` | `parser.c` | `parser.h` | Ánh xạ userdata → action |
| `parsed_rules` | `parsed_rule_t[MAX_RULES]` | `parser.c` | `parser.h` | Mảng rule đã parse |
| `num_rules` | `int` | `parser.c` | `parser.h` | Số rule đã load |
| `filter_groups` | `filter_group_t[MAX_GROUPS]` | `acl.c` | `acl.h` | Mảng group đã sort |
| `num_groups` | `uint32_t` | `acl.c` | `acl.h` | Số group |
| `rule_action_map` | `rule_action_map_t[MAX_RULES]` | `acl.c` | `acl.h` | Global rule → action map |
| `num_rules_total` | `uint32_t` | `acl.c` | `acl.h` | Tổng số rule (= num_rules) |
| `worker_rings` | `struct rte_ring *[NUM_WORKERS]` | `worker.c` | `worker.h` | Mảng IPC ring |
| `worker_stats` | `worker_stats_t[NUM_WORKERS]` | `worker.c` | `worker.h` | Per-worker stats |
| `disp_stats` | `dispatcher_stats_t` | `worker.c` | `worker.h` | Dispatcher stats |
| `force_quit` | `volatile int` (static) | `worker.c` | *(không extern)* | SIGINT flag |
| `spifast_pktmbuf_pool` | `struct rte_mempool *` (static) | `main.c` | *(không extern)* | Mbuf pool |
