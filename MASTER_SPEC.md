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

[Nâng cao] Tích hợp thư viện librte_acl của DPDK để so khớp gói tin tốc độ cao.

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

Sơ đồ Khối Luồng Dữ Luệu (Packet Flow Diagram):

Plaintext
[ File PCAP ]
      | (Nạp qua vdev PMD)
      v
[ Master lcore (Rx / Dispatcher) ]
      |-- 1. Gọi rte_eth_rx_burst() hứng mbuf. (Cập nhật thống kê Rx tổng)
      |-- 2. Tách Zero-copy lấy 5-Tuple
      |-- 3. Tính Software Hash bằng rte_jhash() trên 5-tuple (KHÔNG dùng mbuf->hash.rss)
      |-- 4. Tính ring_index = hash_value % NUM_WORKERS
      |-- 5. Phân tải vào [Lock-free rte_ring IPC] đích. (Nghiêm cấm dùng Mutex/Spinlock)
      |        Nếu đẩy thất bại -> tăng ring_drop_count & giải phóng mbuf.
      v
[ Worker lcores (1 -> 4) ]
      |-- 1. Gọi rte_ring_dequeue() lấy mbuf
      |-- 2. Đưa vào rte_acl_classify() (DPDK ACL) tìm userdata (index)
      |-- 3. Tra mảng tĩnh action_map[userdata] -> { Rule/Group, Action }
      |      * Nếu không khớp (Zero-Trust): Tăng default_drop_count, Action = DROP
      |-- 4. Đọc Action (FORWARD/DROP) và thực thi
      |-- 5. Cập nhật thống kê Hit count (Local variable của từng core)
      |-- 6. Giải phóng: rte_pktmbuf_free()
4. THIẾT KẾ CHI TIẾT (SDD - Software Design Document)
4.1. Hằng số & Cấu trúc dữ liệu lõi (Data Structures)
C
#define NUM_WORKERS 4
#define MAX_RULES 1024
#define MAX_GROUPS 256

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
} five_tuple_t;

// Cấu trúc ánh xạ Userdata từ rte_acl_classify trả về
typedef struct {
    char group_name[64];
    uint32_t action; // FORWARD hoặc DROP
} action_map_t;

// Mảng tĩnh toàn cục lưu ánh xạ: Userdata (chỉ số dòng) -> Action Map
extern action_map_t action_map[MAX_RULES];
4.2. File cấu hình & Parser (Thứ tự Load logic)
Bộ Parser phải tự động dùng hàm trim() xóa khoảng trắng thừa. Quy trình Load bắt buộc: Phải load SPI_policy.csv trước để build bảng ánh xạ Group -> Precedence & Action, sau đó mới load SPI_rule.csv.

A. Load file Policy: SPI_policy.csv (Bảng User Action):

3 Cột: l34-filter-group, Precedence, Action

file csv chuẩn như sau:

No,l34-filter-group,Precedence,Action
1,fg_l34_facebook,100,FORWARD
2,fg_l34_youtube,101,DROP
3,fg_l34_http_sdf1003,102,FORWARD
4,fg_l34_https_sdf1004,103,FORWARD
5,fg_l34_dns_sdf1005,104,DROP

B. Load file Rule: SPI_rule.csv (Chuẩn parser DPDK ACL):

10 Cột chuẩn doanh nghiệp: no., l34-filter, l34-filter-group, network-prefix, network-address, network-port, protocol, src-ip, src-prefix, src-port.

Quy tắc Wildcard: Bất kỳ ô nào ghi NA, N/A, any hoặc để trống đều được dịch thành Wildcard (Bất kỳ / 0.0.0.0/0 / 0:65535).

Quy tắc Format Dữ liệu:

IP: Lấy từ -prefix HOẶC -address / -ip.

Port: Xử lý theo Range. Nếu file ghi single port (VD: 80), parser tự động hiểu là 80-80. Nếu ghi range (VD: 80-443), giữ nguyên range.

Protocol: Xử lý được cả chuỗi (tcp, udp) và số hiệu (6, 17), tự động map về hằng số IPPROTO_TCP hoặc IPPROTO_UDP.

file csv chuẩn như sau:

no.,l34-filter,l34-filter-group,network-prefix,network-address,network-port,protocol,src-ip,src-prefix,src-port
1,f_l34_facebook_1,fg_l34_facebook,31.13.64.0/18,NA,any,any,NA,NA,any
2,f_l34_facebook_2,fg_l34_facebook,66.220.144.0/20,NA,any,any,NA,NA,any
3,f_l34_facebook_3,fg_l34_facebook,69.63.176.0/20,NA,any,any,NA,NA,any
4,f_l34_facebook_4,fg_l34_facebook,157.240.0.0/16,NA,any,any,NA,NA,any
5,f_l34_facebook_4,fg_l34_facebook,NA,69.220.144.5,any,any,NA,NA,any
6,f_l34_youtube_1,fg_l34_youtube,142.250.0.0/15,NA,443,tcp,NA,NA,any
7,f_l34_youtube_2,fg_l34_youtube,172.217.0.0/16,NA,443,tcp,NA,NA,any
8,f_l34_youtube_3,fg_l34_youtube,216.58.192.0/19,NA,443,tcp,NA,NA,any
9,f_l34_youtube_4,fg_l34_youtube,N/A,74.125.0.1,443,tcp,NA,NA,any
10,f_l34_http_all,fg_l34_http_sdf1003,NA,NA,80,tcp,NA,NA,any
11,f_l34_https_all,fg_l34_https_sdf1004,NA,NA,443,tcp,NA,NA,any
12,f_l34_dns_udp,fg_l34_dns_sdf1005,NA,NA,53,udp,NA,NA,any
13,f_l34_dns_tcp,fg_l34_dns_sdf1005,NA,NA,53,tcp,NA,NA,any


4.3. Cơ chế DPDK ACL, Precedence & Zero-Trust
Field Definitions: Bắt buộc phải định nghĩa mảng struct rte_acl_field_def tường minh, sử dụng chuẩn IPv4 5-tuple tương tự như code mẫu trong examples/l3fwd-acl của DPDK source code.

Precedence (Độ ưu tiên): Khi gọi rte_acl_add_rules(), tham số priority của luật lấy từ Precedence (đã nạp từ Policy).

Userdata Map: Tham số userdata khi add rule bắt buộc phải là index tuần tự bắt đầu từ 1 (1, 2, 3...) tương ứng với số thứ tự dòng của file SPI_rule.csv (tức userdata = dòng_thứ_i + 1). Giá trị userdata = 0 được dành riêng làm tín hiệu "no match" — không gán cho bất kỳ rule thật nào, vì đây là giá trị mặc định mà rte_acl_classify() trả về khi gói tin không khớp luật nào. Lúc này, rte_acl_classify() trả về index, ta dùng nó tra cứu trực tiếp mảng tĩnh action_map[userdata] để lấy Action trong O(1).

Default Action (Zero-Trust): Nếu rte_acl_classify() trả về 0 (không khớp luật), mặc định gói tin bị DROP. Tăng default_drop_count và free mbuf.

4.4. Cấu hình DPDK EAL (Cố định để Benchmark)
Không tự động sinh tham số ngẫu nhiên, bắt buộc dùng cấu trúc sau:

Core / Queue: --lcores='0-4'. Core 0 làm Master. Core 1,2,3,4 làm Worker (NUM_WORKERS = 4).

Vdev EAL: --vdev="net_pcap0,rx_pcap=traffic_sample.pcap" (Lưu ý: Bỏ tx_pcap vì theo Zero-Trust gói tin bị DROP sẽ chỉ tăng counter và free mbuf, không đẩy ra file output để tối ưu I/O).

Mempool: Cấp phát bộ nhớ chuẩn 8192 mbufs, cache size 256.

4.5. Cơ chế phân tải (Load Balancing) & Data-Race
Software RSS Hash: PCAP vdev không hỗ trợ phần cứng tính RSS. Master Core sau khi trích xuất 5-tuple BẮT BUỘC dùng hàm rte_jhash() (hoặc tương đương) tính hash bằng phần mềm trực tiếp trên 5-tuple. Giá trị initval (seed) của rte_jhash() phải là một hằng số cố định (ví dụ #define HASH_SEED 0), không sinh ngẫu nhiên, để đảm bảo kết quả phân tải tái lập được giữa các lần chạy phục vụ benchmark/debug. Sau đó tính ring_index = hash_value % NUM_WORKERS để đẩy gói tin qua rte_ring.

Chiến lược đo lường KPI (Chống Data Race):

Master Core: Đếm tổng mbuf & bytes sau rte_eth_rx_burst(). Cập nhật ring_drop_count nếu rte_ring_enqueue() thất bại.

Worker Cores: Mỗi Worker duy trì biến Local (Hit Count, Default Drop Count). Tuyệt đối không share chung biến toàn cục để tránh Lock Contention.

4.6. Đặc tả format log thống kê runtime
Định kỳ mỗi giây, Master (hoặc luồng quản lý) xuất ra màn hình console định dạng chuẩn. (Lưu ý: Output in ra dạng số nguyên cơ bản, không cần dùng dấu phẩy định dạng hàng nghìn để tránh phức tạp logic in ấn).

Plaintext
================= SPI RUNTIME STATS (1s) =================
Throughput: 850 Mbps | Flow Rate: 1200000 pps
Missing Rate: 0% | Packet Drop Rate (Ring full): 0%
----------------------------------------------------------
[Group: fg_l34_facebook]   Hit: 450000 pkts | Action: FORWARD
[Group: fg_l34_youtube]    Hit: 120000 pkts | Action: FORWARD
[Group: fg_l34_http_s...]  Hit: 15000 pkts  | Action: DROP
[Default/Unmatched]        Hit: 50000 pkts  | Action: DROP
==========================================================
5. QUY CHUẨN LẬP TRÌNH (Coding Guidelines)
Ngôn ngữ bắt buộc: Ngôn ngữ C chuẩn (compile sạch sẽ không lỗi trên môi trường GCC Linux).

Quản lý build: Sử dụng Makefile hoặc CMakeLists.txt.

Xử lý gói tin: Bắt buộc dùng Zero-copy (ép kiểu con trỏ mbuf sang các struct header mạng có sẵn của DPDK như rte_ether_hdr, rte_ipv4_hdr...).

QUY TẮC TƯƠNG TÁC: AI không được tự ý sinh ra toàn bộ mã nguồn ngay lập tức. Bạn phải đợi tôi ra lệnh chi tiết cho từng bước (ví dụ: "Bây giờ hãy viết Makefile", hoặc "Hãy viết module Parser").
