Tên dự án: SPIFast - Hệ Thống Kiểm Tra Gói Tin Hiệu Năng Cao (SPI) Sử Dụng DPDK

Vai trò của bạn (AI Agent): Bạn là một Kỹ sư phần mềm hệ thống (System Software Engineer) chuyên môn cao về lập trình C trên Linux và framework DPDK. Bạn sẽ giúp tôi thiết kế và viết mã nguồn cho dự án này theo từng bước, tuân thủ nghiêm ngặt các tài liệu và cấu trúc dưới đây.

1. YÊU CẦU PHẦN MỀM (SRS - Software Requirements Specification)
Mục tiêu: Xây dựng một chương trình Shallow Packet Inspection (SPI) đơn giản sử dụng DPDK để thực hiện phân loại gói tin (packet classification) theo luật (rule).

Môi trường: Chạy trực tiếp trên 01 máy cá nhân Linux, giả lập mạng bằng cơ chế PCAP Virtual Device (vdev) PMD, không phụ thuộc card mạng rời vật lý.

Tính năng cốt lõi:

Khởi tạo môi trường DPDK (EAL, Mempool, vdev) với cấu hình cố định.

Nhận gói tin từ NIC ảo bằng DPDK.

Parse Header của L2/L3/L4 (Ethernet, IPv4, TCP/UDP) và trích xuất thông tin 5-Tuple (IP nguồn/đích, Port nguồn/đích, Protocol).

Đọc bộ rule từ file cấu hình CSV (SPI_rule.csv và SPI_policy.csv).

[Nâng cao] Hỗ trợ cấu hình Action (FORWARD/DROP) linh hoạt do người dùng định nghĩa qua file phụ (không hardcode trong C) và áp dụng cơ chế quản lý Action theo Nhóm (Filter-Group). Áp dụng chính sách Zero-Trust (Default DROP).

[Nâng cao] Tích hợp thư viện librte_acl của DPDK để so khớp gói tin tốc độ cao. Mỗi filter-group được build thành 1 acl_ctx riêng biệt; classify tuần tự theo thứ tự Precedence tăng dần.

Phân tải gói tin tới các luồng Worker phù hợp dựa trên Software Hash (do PCAP PMD không hỗ trợ Hardware RSS) để đảm bảo Flow Affinity.

Thu thập (chống Data Race) và in thống kê runtime ra màn hình định kỳ mỗi giây.

2. YÊU CẦU PHI CHỨC NĂNG (NFR - Non-Functional Requirements)
Hệ thống phải tuân thủ nghiêm ngặt các chỉ tiêu hiệu năng (KPIs) giả lập data-plane 1 Gbps:

Thông lượng băng thông (Throughput): Phải đạt >= 700 Mbps đối với gói tin kích thước trung bình 512B - 1024B.

Mật độ xử lý (Flow Rate): Phải đạt >= 500,000 pps (0.5 Mpps).

Tỷ lệ rơi gói (Packet Drop Rate): Phải <= 0.1% tại mức tải tối đa của CPU (xử lý mbuf mượt mà, không nghẽn tại ring).

Tỷ lệ bỏ sót (Missing Rate): 0% Tuyệt đối (Tổng Match + Tổng Default Drop phải khớp chính xác tổng số gói đọc từ file PCAP gốc).

3. THIẾT KẾ TỔNG THỂ (HLD - High Level Design)
Kiến trúc luồng dữ liệu (Data Path) được tổ chức theo mô hình Pipeline phi khóa tuần tự đa lõi:

Sơ đồ Khối Luồng Dữ Liệu (Packet Flow Diagram):

```
[ File PCAP ] (infinite_rx=1 — loop vô hạn, thoát khi Ctrl+C / SIGINT)
      | (Nạp qua vdev PMD)
      v
[ Master lcore (Rx / Dispatcher) ]
      |-- 1. Gọi rte_eth_rx_burst() hứng mbuf. (Cập nhật thống kê Rx tổng)
      |-- 2. Tách Zero-copy lấy 5-Tuple
      |-- 3. Tính Software Hash bằng rte_jhash() trên 5-tuple (KHÔNG dùng mbuf->hash.rss)
      |-- 4. Tính ring_index = hash_value % NUM_WORKERS
      |-- 5. Phân tải vào [Lock-free rte_ring IPC] đích. (Nghiêm cấm dùng Mutex/Spinlock)
      |        Nếu đẩy thất bại -> tăng ring_drop_count & giải phóng mbuf.
      |-- 6. Định kỳ 1 giây: in RUNTIME STATS ra console (dùng rte_get_timer_cycles)
      |-- 7. Thoát khi nhận SIGINT (Ctrl+C) — vòng lặp vô hạn, KHÔNG dùng MAX_EMPTY_POLLS
      v
[ Worker lcores (1 -> 4) ]
      |-- 1. Gọi rte_ring_dequeue() lấy mbuf
      |-- 2. Lần lượt classify qua filter_groups[] theo thứ tự Precedence tăng dần:
      |        for g in filter_groups[] sorted by precedence (ascending):
      |            rte_acl_classify(filter_groups[g].acl_ctx, &tuple, &result, 1, 1)
      |            if result != 0:
      |                match tại group g → lấy action từ filter_groups[g].action
      |                tăng group_hit_count[g] và hit_count[global_rule_index]
      |                break
      |-- 3. Nếu không group nào match → Zero-Trust DROP
      |        Tăng default_drop_count, Action = DROP
      |-- 4. Thực thi Action (FORWARD/DROP)
      |-- 5. Giải phóng: rte_pktmbuf_free()
```

4. THIẾT KẾ CHI TIẾT (SDD - Software Design Document)

4.1. Hằng số & Cấu trúc dữ liệu lõi (Data Structures)

```c
#define NUM_WORKERS 4
#define MAX_RULES   1024
#define MAX_GROUPS  256

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    /* 3 bytes padding tự nhiên — KHÔNG dùng __attribute__((packed)) */
} five_tuple_t;
/* sizeof(five_tuple_t) == 16; layout: protocol@0, pad@1-3,
   src_ip@4, dst_ip@8, src_port@12, dst_port@14               */
/* five_tuple_t lưu giá trị NETWORK BYTE ORDER (NBO) trực tiếp
   từ packet header — KHÔNG convert sang host byte order        */

/*
 * Ánh xạ 1 rule toàn cục → group chứa nó.
 * Worker dùng mảng này sau khi classify để biết
 * rule nào thuộc group nào (phục vụ log per-rule nếu cần).
 * Tra cứu bằng ID số (global_rule_index), KHÔNG so sánh string.
 */
typedef struct {
    uint32_t group_id;    /* Index của group trong filter_groups[] (0-based) */
    char group_name[64];  /* Chỉ dùng để in log, KHÔNG dùng để tra cứu      */
    uint32_t action;      /* ACTION_FORWARD hoặc ACTION_DROP                  */
} rule_action_map_t;

/*
 * Thông tin mỗi filter-group.
 * Mỗi group có 1 acl_ctx riêng; classify tuần tự theo precedence.
 */
typedef struct {
    uint32_t          group_id;    /* Index 0-based trong mảng filter_groups[] */
    char              group_name[64];
    uint32_t          action;      /* ACTION_FORWARD hoặc ACTION_DROP           */
    uint32_t          precedence;  /* Từ SPI_policy.csv — số nhỏ = ưu tiên cao  */
    struct rte_acl_ctx *acl_ctx;   /* ACL context riêng cho group này            */
    uint32_t          num_rules;   /* Số rule được add vào ctx này               */
    uint32_t          global_rule_offset; /* Offset vào rule_action_map[] cho rule đầu tiên của group */
} filter_group_t;

#define ACTION_FORWARD 0
#define ACTION_DROP    1

extern filter_group_t    filter_groups[MAX_GROUPS]; /* sắp xếp tăng dần theo precedence sau khi load */
extern uint32_t          num_groups;
extern rule_action_map_t rule_action_map[MAX_RULES]; /* index = global rule index (0-based) */
extern uint32_t          num_rules_total;
```

4.2. File cấu hình & Parser (Thứ tự Load logic)

Bộ Parser phải tự động dùng hàm trim() xóa khoảng trắng thừa. Quy trình Load bắt buộc: Phải load SPI_policy.csv trước để build bảng ánh xạ Group -> Precedence & Action, sau đó mới load SPI_rule.csv.

A. Load file Policy: SPI_policy.csv

5 Cột: No, l34-filter-group, Precedence, Action

```
No,l34-filter-group,Precedence,Action
1,fg_l34_facebook,100,FORWARD
2,fg_l34_youtube,101,DROP
3,fg_l34_http_sdf1003,102,FORWARD
4,fg_l34_https_sdf1004,103,FORWARD
5,fg_l34_dns_sdf1005,104,DROP
```

Sau khi load: sắp xếp filter_groups[] tăng dần theo precedence (số nhỏ = ưu tiên cao hơn, classify trước).

B. Load file Rule: SPI_rule.csv

10 Cột chuẩn doanh nghiệp: no., l34-filter, l34-filter-group, network-prefix, network-address, network-port, protocol, src-ip, src-prefix, src-port.

Quy tắc Wildcard: Bất kỳ ô nào ghi NA, N/A, any hoặc để trống đều được dịch thành Wildcard (Bất kỳ / 0.0.0.0/0 / port range 0:65535).

Quy tắc Format Dữ liệu:
- IP: Lấy từ network-prefix HOẶC network-address.
- Port: Xử lý theo Range. Single port (VD: 80) → tự động hiểu là 80:80. Range (VD: 80-443) → giữ nguyên.
- Protocol: Xử lý cả chuỗi (tcp, udp) và số (6, 17) → map về IPPROTO_TCP / IPPROTO_UDP.

```
no.,l34-filter,l34-filter-group,network-prefix,network-address,network-port,protocol,src-ip,src-prefix,src-port
1,f_l34_facebook_1,fg_l34_facebook,31.13.64.0/18,NA,any,any,NA,NA,any
2,f_l34_facebook_2,fg_l34_facebook,66.220.144.0/20,NA,any,any,NA,NA,any
3,f_l34_facebook_3,fg_l34_facebook,69.63.176.0/20,NA,any,any,NA,NA,any
4,f_l34_facebook_4,fg_l34_facebook,157.240.0.0/16,NA,any,any,NA,NA,any
5,f_l34_facebook_5,fg_l34_facebook,NA,69.220.144.5,any,any,NA,NA,any
6,f_l34_youtube_1,fg_l34_youtube,142.250.0.0/15,NA,443,tcp,NA,NA,any
7,f_l34_youtube_2,fg_l34_youtube,172.217.0.0/16,NA,443,tcp,NA,NA,any
8,f_l34_youtube_3,fg_l34_youtube,216.58.192.0/19,NA,443,tcp,NA,NA,any
9,f_l34_youtube_4,fg_l34_youtube,N/A,74.125.0.1,443,tcp,NA,NA,any
10,f_l34_http_all,fg_l34_http_sdf1003,NA,NA,80,tcp,NA,NA,any
11,f_l34_https_all,fg_l34_https_sdf1004,NA,NA,443,tcp,NA,NA,any
12,f_l34_dns_udp,fg_l34_dns_sdf1005,NA,NA,53,udp,NA,NA,any
13,f_l34_dns_tcp,fg_l34_dns_sdf1005,NA,NA,53,tcp,NA,NA,any
```

Sau khi load SPI_rule.csv:
- Mỗi rule được add vào acl_ctx của group tương ứng.
- userdata trong mỗi ctx = index của rule trong group đó, bắt đầu từ 1.
- rule_action_map[global_index] = { group_id, group_name, action } — index 0-based theo thứ tự dòng file.

4.3. Cơ chế DPDK ACL, Precedence & Zero-Trust

**Field Definitions:** Bắt buộc phải định nghĩa mảng struct rte_acl_field_def tường minh, sử dụng chuẩn IPv4 5-tuple tương tự như code mẫu trong examples/l3fwd-acl của DPDK source code.

Layout field ACL bắt buộc khớp với five_tuple_t (NBO, sizeof=16):
- Field 0: protocol — RTE_ACL_FIELD_TYPE_BITMASK, size=1, offset=0
- Field 1: src_ip   — RTE_ACL_FIELD_TYPE_MASK,    size=4, offset=4
- Field 2: dst_ip   — RTE_ACL_FIELD_TYPE_MASK,    size=4, offset=8
- Field 3: src_port — RTE_ACL_FIELD_TYPE_RANGE,   size=2, offset=12  (input_index=3)
- Field 4: dst_port — RTE_ACL_FIELD_TYPE_RANGE,   size=2, offset=14  (input_index=3)
  (src_port và dst_port cùng input_index=3 vì ACL gom 2 port 16-bit vào 1 block 32-bit)

**Kiến trúc Multi-Context (theo góp ý mentor):**

Mỗi filter-group trong SPI_policy.csv được build thành 1 struct rte_acl_ctx riêng biệt,
lưu trong filter_groups[g].acl_ctx. Sau khi load xong, filter_groups[] được sắp xếp
tăng dần theo precedence (số nhỏ = ưu tiên cao = classify trước).

**Userdata trong mỗi ctx:**
- userdata = index của rule trong group đó, bắt đầu từ 1.
- userdata = 0 là tín hiệu "no match" trong ctx này — chuyển sang ctx tiếp theo.

Ví dụ với fg_l34_youtube (4 rules, precedence=101):
```
  rule f_l34_youtube_1 (global index 5) → userdata=1 trong ctx youtube
  rule f_l34_youtube_2 (global index 6) → userdata=2 trong ctx youtube
  rule f_l34_youtube_3 (global index 7) → userdata=3 trong ctx youtube
  rule f_l34_youtube_4 (global index 8) → userdata=4 trong ctx youtube
```

**Rule values khi add vào ACL phải ở HOST BYTE ORDER** — trie builder tự convert nội bộ.
**Input data cho rte_acl_classify() phải ở NETWORK BYTE ORDER** — five_tuple_t giữ NBO.

**Quy trình classify trong Worker (per packet):**
```
for g = 0 to num_groups-1:          // filter_groups[] đã sort theo precedence
    result = 0
    rte_acl_classify(filter_groups[g].acl_ctx,
                     (const uint8_t **)&tuple_ptr, &result, 1, 1)
    if result != 0:
        // Match tại group g
        global_idx = filter_groups[g].global_rule_offset + result - 1
        hit_count[global_idx]++          // per-rule counter (local to worker)
        group_hit_count[g]++             // per-group counter (local to worker)
        apply filter_groups[g].action
        goto free_mbuf
// Không group nào match → Zero-Trust
default_drop_count++
free_mbuf:
    rte_pktmbuf_free(mbuf)
```

**Default Action (Zero-Trust):** Nếu tất cả N ctx đều trả về 0, gói tin bị DROP.
Tăng default_drop_count và free mbuf.

4.4. Cấu hình DPDK EAL (Cố định để Benchmark)

Không tự động sinh tham số ngẫu nhiên, bắt buộc dùng cấu trúc sau:

Core / Queue: -l 0-4 -n 4. Core 0 làm Master (Dispatcher). Core 1,2,3,4 làm Worker (NUM_WORKERS = 4).

Vdev EAL:
```
--vdev="net_pcap0,rx_pcap=traffic_sample.pcap,infinite_rx=1"
```
(infinite_rx=1: PCAP PMD loop replay liên tục — không cần thay đổi code C.
 Bỏ tx_pcap: gói DROP chỉ tăng counter và free mbuf, không ghi file output để tối ưu I/O.)

Mempool: Cấp phát bộ nhớ chuẩn 8192 mbufs, cache size 256.

Lệnh chạy mẫu:
```
sudo ./build/spifast -l 0-4 -n 4 \
    --vdev="net_pcap0,rx_pcap=traffic_sample.pcap,infinite_rx=1" \
    -- --rule-file SPI_rule.csv --policy-file SPI_policy.csv
```

Lưu ý MBUF_DATA_SIZE: Phải đủ lớn để chứa packet lớn nhất trong PCAP
dưới dạng single-segment (infinite_rx yêu cầu nb_segs=1).
Dùng (4096 + RTE_PKTMBUF_HEADROOM) cho traffic_sample.pcap (max ~3780 bytes).

4.5. Cơ chế phân tải (Load Balancing) & Data-Race

**Software RSS Hash:** PCAP vdev không hỗ trợ phần cứng tính RSS. Master Core sau khi trích xuất 5-tuple BẮT BUỘC dùng hàm rte_jhash() tính hash bằng phần mềm trực tiếp trên 5-tuple. Giá trị initval (seed) phải là hằng số cố định (#define HASH_SEED 0), không sinh ngẫu nhiên, để đảm bảo kết quả phân tải tái lập được giữa các lần chạy. Sau đó tính ring_index = hash_value % NUM_WORKERS.

**Chiến lược đo lường KPI (Chống Data Race):**

Master Core:
- Đếm total_rx_pkts và total_rx_bytes ngay sau rte_eth_rx_burst().
- Đếm ring_drop_count khi rte_ring_enqueue() thất bại.
- Đếm non_ipv4_count khi parse_packet_5tuple() trả về -1.
- Định kỳ 1 giây: snapshot stats và in ra console.

Worker Cores: Mỗi Worker duy trì các mảng/biến LOCAL (KHÔNG share toàn cục):
- hit_count[MAX_RULES]:    đếm per-rule (index toàn cục trong SPI_rule.csv, 0-based)
- group_hit_count[MAX_GROUPS]: đếm per-group (tổng hợp để in log theo group)
- default_drop_count:      gói không khớp group nào
- total_classified:        tổng gói đã qua classify (kể cả default drop)
Tuyệt đối không share chung biến toàn cục để tránh Lock Contention.

Sau khi Dispatcher nhận SIGINT và gửi NULL sentinel vào mỗi ring,
Worker thoát và báo cáo stats local về main thread qua worker_stats[].
print_final_stats() collect từ tất cả Worker và verify Missing Rate = 0%.

4.6. Đặc tả format log thống kê runtime

Định kỳ mỗi giây, Dispatcher xuất ra màn hình console. Worker stats được collect
qua snapshot atomic hoặc sau khi Worker kết thúc (cho final stats).
(Output in ra dạng số nguyên cơ bản, không dùng dấu phẩy hàng nghìn.)

```
================= SPI RUNTIME STATS (1s) =================
Throughput: 850 Mbps | Flow Rate: 1200000 pps
Missing Rate: 0% | Packet Drop Rate (Ring full): 0%
----------------------------------------------------------
[Group: fg_l34_facebook]      Hit: 450000 pkts | Action: FORWARD
[Group: fg_l34_youtube]       Hit: 120000 pkts | Action: DROP
[Group: fg_l34_http_sdf1003]  Hit: 15000 pkts  | Action: FORWARD
[Group: fg_l34_https_sdf1004] Hit: 8000 pkts   | Action: FORWARD
[Group: fg_l34_dns_sdf1005]   Hit: 2000 pkts   | Action: DROP
[Default/Unmatched]           Hit: 50000 pkts  | Action: DROP
==========================================================
```

Ghi chú tính toán:
```
Throughput (Mbps)    = (bytes_in_interval * 8) / 1_000_000 / delta_s
Flow Rate (pps)      = pkts_in_interval / delta_s
Missing Rate (%)     = (total_rx - total_classified - non_ipv4 - ring_drop) / total_rx * 100
Drop Rate (%)        = ring_drop_count_in_interval / pkts_in_interval * 100
Interval             = rte_get_timer_cycles() / rte_get_timer_hz()
Throughput/pps       = từ Dispatcher stats (không cần collect Worker cho 2 metric này)
Hit count per group  = tổng group_hit_count[g] của tất cả Worker cho group g
```

5. QUY CHUẨN LẬP TRÌNH (Coding Guidelines)

Ngôn ngữ bắt buộc: Ngôn ngữ C chuẩn (compile sạch sẽ không lỗi/warning trên GCC Linux).

Quản lý build: Makefile dùng $(wildcard src/*.c) — file .c mới tự động được pick up.

Xử lý gói tin: Bắt buộc dùng Zero-copy (ép kiểu con trỏ mbuf sang struct header DPDK như rte_ether_hdr, rte_ipv4_hdr...).

Không dùng __attribute__((packed)) trên five_tuple_t — cần layout tự nhiên cho ACL.

Không dùng Mutex/Spinlock trong data path — chỉ dùng lock-free rte_ring.

QUY TẮC TƯƠNG TÁC: AI không được tự ý sinh ra toàn bộ mã nguồn ngay lập tức. Bạn phải đợi tôi ra lệnh chi tiết cho từng bước.