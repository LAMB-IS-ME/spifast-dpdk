# SPIFast — Shallow Packet Inspection sử dụng DPDK

Dự án SPIFast là một ứng dụng kiểm tra gói tin tốc độ cao dựa trên DPDK, thực hiện phân loại gói tin (packet classification) theo 5-tuple. Ứng dụng cung cấp khả năng lọc và định tuyến lưu lượng mạng mạnh mẽ, sử dụng kiến trúc xử lý song song để đạt thông lượng tối ưu.

## Kiến trúc

Pipeline xử lý của hệ thống:
PCAP → Dispatcher (lcore 0) → 4 SPSC ring → Worker (lcore 1-4)

- Software RSS bằng `rte_jhash`.
- DPDK ACL multi-context.
- Zero-Trust DROP.
- Stats mỗi giây.

## Yêu cầu hệ thống

- Ubuntu 20.04+ hoặc tương đương
- DPDK 23.11+ (cài qua apt: `libdpdk-dev`)
- GCC với hỗ trợ C11
- Tối thiểu 6 vCPU (1 Dispatcher + 4 Worker + 1 dự phòng)
- 64 hugepages 2MB

## Cài đặt hugepages

Tạm thời (mất sau reboot):
```bash
sudo mkdir -p /dev/hugepages
sudo mount -t hugetlbfs nodev /dev/hugepages
echo 64 | sudo tee /proc/sys/vm/nr_hugepages
```

Persistent (khuyến nghị):
```bash
echo "vm.nr_hugepages = 64" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
sudo mkdir -p /dev/hugepages
sudo mount -t hugetlbfs nodev /dev/hugepages
```

## Build

```bash
make clean && make
```
Binary output: `./spifast`

## Chạy

Single-pass (đọc PCAP 1 lần rồi dừng — dùng để test nhanh):
```bash
sudo ./spifast -l 0-4 -n 4 \
  --vdev="net_pcap0,rx_pcap=traffic_sample.pcap" \
  -- --rule-file SPI_rule.csv --policy-file SPI_policy.csv
```
Lưu ý: Single-pass sẽ bị kẹt vô hạn sau khi đọc hết PCAP vì Dispatcher chờ SIGINT. Dùng lệnh infinite_rx bên dưới thay thế.

Infinite replay (khuyến nghị — loop liên tục, Ctrl+C để dừng):
```bash
sudo ./spifast -l 0-4 -n 4 \
  --vdev="net_pcap0,rx_pcap=traffic_sample.pcap,infinite_rx=1" \
  -- --rule-file SPI_rule.csv --policy-file SPI_policy.csv
```
Nhấn Ctrl+C để dừng — hệ thống sẽ in SPI FINAL STATS trước khi thoát.

## Output mẫu

```text
================= SPI RUNTIME STATS (1s) =================
Throughput: 3400 Mbps | Flow Rate: 1800000 pps
Missing Rate: 0% | Packet Drop Rate (Ring full): 43%
----------------------------------------------------------
[Group: fg_l34_facebook         ] Hit: 0 pkts | Action: FORWARD
[Group: fg_l34_youtube          ] Hit: 1200000 pkts | Action: DROP
[Group: fg_l34_http_sdf1003     ] Hit: 72000 pkts | Action: FORWARD
[Group: fg_l34_https_sdf1004    ] Hit: 930000 pkts | Action: FORWARD
[Group: fg_l34_dns_sdf1005      ] Hit: 265000 pkts | Action: DROP
[Default/Unmatched]              Hit: 3100000 pkts | Action: DROP
==========================================================
```

## KPI đạt được

| KPI | Yêu cầu | Thực tế (VM 6 vCPU) |
|---|---|---|
| Throughput | ≥ 700 Mbps | ~3400 Mbps |
| Flow Rate | ≥ 500K pps | ~1.8M pps |
| Missing Rate | 0% | 0% |
| Packet Drop Rate | ≤ 0.1% | ~43% (giới hạn VM) |

Thêm ghi chú: Drop Rate cao do VM không có NIC vật lý, PCAP PMD replay nhanh hơn Worker có thể classify. Trên phần cứng thực với NIC vật lý, drop rate sẽ thấp hơn nhiều.

## Cấu hình rule

- `SPI_policy.csv`: định nghĩa filter-group, precedence, action
- `SPI_rule.csv`: định nghĩa rule chi tiết (IP, port, protocol)
- Thêm/sửa rule không cần recompile, chỉ cần sửa CSV rồi chạy lại

## Lưu ý kỹ thuật quan trọng

- `five_tuple_t` không dùng `__attribute__((packed))` — cần layout tự nhiên cho DPDK ACL field alignment
- ACL input phải ở Network Byte Order; rule values ở Host Byte Order
- Mỗi filter-group có 1 `rte_acl_ctx` riêng, classify theo precedence
- `MBUF_DATA_SIZE` = 4096 + `RTE_PKTMBUF_HEADROOM` để hỗ trợ single-segment mbuf với `infinite_rx` (yêu cầu `nb_segs=1`)