# SPIFast — Sơ Đồ Kiến Trúc & Luồng Dữ Liệu

> **Phiên bản:** 1.0 (2026-07-07)

---

## 1. Kiến Trúc Module Tổng Thể

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                           SPIFAST APPLICATION                                  │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │  main.c  — Entry Point & Orchestrator                                   │  │
│  │                                                                         │  │
│  │  rte_eal_init() → mempool_init() → port_setup()                        │  │
│  │  load_policy() → load_rules() → acl_build_all() → worker_rings_init()  │  │
│  │  remote_launch(worker_main × 4) → dispatcher_run()                     │  │
│  └──────┬───────────────────────────────────────────────────────┬──────────┘  │
│         │ calls                                                 │ calls       │
│         ▼                                                       ▼             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  parser.h/c  │  │    acl.h/c   │  │  worker.h/c  │  │header_parser.h/c │  │
│  │              │  │              │  │              │  │                  │  │
│  │load_policy() │  │acl_build_all │  │dispatcher_run│  │parse_packet_     │  │
│  │load_rules()  │  │acl_free_all()│  │worker_main() │  │  5tuple()        │  │
│  │              │  │              │  │print_final_  │  │                  │  │
│  │policy_table[]│  │filter_groups │  │  stats()     │  │(Zero-copy cast   │  │
│  │parsed_rules[]│  │rule_action_  │  │worker_rings[]│  │ L2/L3/L4 header) │  │
│  │action_map[]  │  │  map[]       │  │worker_stats[]│  │                  │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │  DPDK Framework (EAL, PMD, ACL, Ring, Mempool, Cycles)                 │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Phụ Thuộc Module (Dependency Graph)

```
        main.c
       /  |  |  \
      /   |  |   \
parser   acl  worker  header_parser
  |       |      |  \      |
  |       |      |   \     |
  |     parser  acl  header_parser
  |
(stdlib, arpa/inet, netinet/in)
```

**Chi tiết `#include` thực tế:**

```
main.c
  ├── parser.h    (load_policy, load_rules, five_tuple_t)
  ├── acl.h       (acl_build_all, acl_free_all, filter_group_t)
  └── worker.h    (worker_rings_init, dispatcher_run, worker_main, print_final_stats)

worker.c
  ├── worker.h
  ├── header_parser.h  (parse_packet_5tuple)
  └── acl.h            (filter_groups[], num_groups)

acl.c
  ├── acl.h
  └── parser.h         (parsed_rules[], policy_table[], num_rules, num_policies)

header_parser.c
  └── header_parser.h
      └── parser.h     (five_tuple_t)

parser.c
  └── parser.h
```

---

## 3. Luồng Dữ Liệu Khởi Tạo (Startup Sequence)

```
 TIME ──────────────────────────────────────────────────────────────────────────►

 main()
   │
   ├─[1]─ rte_eal_init()
   │        Parse --lcores 0-4, -n 4, --vdev net_pcap0
   │        Khởi tạo memory, lcore mapping, vdev
   │
   ├─[2]─ spifast_mempool_init()
   │        rte_pktmbuf_pool_create("SPIFAST_MBUF_POOL", 8192, 256, 0, ~4224, sock)
   │        → spifast_pktmbuf_pool
   │
   ├─[3]─ spifast_check_ports()
   │        rte_eth_dev_count_avail() → 1 port (net_pcap0)
   │
   ├─[4]─ spifast_port_setup(port=0)
   │        rte_eth_dev_configure(port=0, rx=1, tx=0)
   │        rte_eth_rx_queue_setup(port=0, q=0, 128 desc)
   │        rte_eth_dev_start(port=0)
   │
   ├─[5]─ load_policy("SPI_policy.csv")
   │        parser.c:
   │          fopen → skip header → parse 5 rows
   │          → policy_table[0..4] = {facebook, youtube, http, https, dns}
   │          num_policies = 5
   │
   ├─[6]─ load_rules("SPI_rule.csv")
   │        parser.c:
   │          Guard: num_policies > 0 ✓
   │          fopen → skip header → parse 13 rows
   │          For each row:
   │            lookup_policy(group_name) → policy_entry_t*
   │            parse_ip_prefix(), parse_port_range(), parse_protocol()
   │            → parsed_rules[0..12]
   │            → action_map[1..13]
   │          num_rules = 13
   │
   ├─[7]─ acl_build_all()
   │        acl.c:
   │          Bước 1: filter_groups[] ← policy_table[] (5 groups)
   │          Bước 2: Insertion sort by precedence
   │                  [facebook:100, youtube:101, http:102, https:103, dns:104]
   │          Bước 3: Reassign group_id = 0,1,2,3,4
   │          Bước 4: Count rules per group
   │                  [5, 4, 1, 1, 2]
   │          Bước 5: Compute global_rule_offset
   │                  [0, 5, 9, 10, 11]
   │          Bước 6: Populate rule_action_map[0..12]
   │          Bước 7: For each group:
   │                    rte_acl_create("spifast_acl_{group}")
   │                    rte_acl_add_rules() × num_rules
   │                    rte_acl_build()
   │          num_groups=5, num_rules_total=13
   │
   ├─[8]─ worker_rings_init()
   │        Create: spifast_ring_0..3 (SPSC, size=1024)
   │        Reset: worker_stats[], disp_stats
   │
   ├─[9]─ rte_eal_remote_launch(worker_main, 0, lcore=1)
   │       rte_eal_remote_launch(worker_main, 1, lcore=2)
   │       rte_eal_remote_launch(worker_main, 2, lcore=3)
   │       rte_eal_remote_launch(worker_main, 3, lcore=4)
   │         → 4 Worker threads bắt đầu polling rings
   │
   └─[10]─ dispatcher_run(NULL)  [BLOCKING]
             ↑
             └── Chạy trên lcore 0 cho đến khi SIGINT
```

---

## 4. Luồng Xử Lý Packet Chi Tiết (Data Path)

### 4.1 Dispatcher Path (lcore 0)

```
                    ┌─────────────────────────────────┐
                    │  vdev net_pcap0                  │
                    │  traffic_sample.pcap (infinite)  │
                    └────────────────┬────────────────┘
                                     │
                    ┌────────────────▼────────────────┐
                    │  rte_eth_rx_burst(0, 0, mbufs, 32)│
                    │  nb_rx = 0..32 mbufs             │
                    └────────────────┬────────────────┘
                                     │
                    ┌────────────────▼────────────────┐
                    │  Stats Update                    │
                    │  total_rx_pkts += nb_rx          │
                    │  total_rx_bytes += Σ pkt_len     │
                    └────────────────┬────────────────┘
                                     │
                    ┌────────────────▼────────────────┐
                    │  for i = 0..nb_rx-1:            │
                    │                                  │
                    │  parse_packet_5tuple(mbufs[i])   │
                    │           │                      │
                    │    fail?──┼──YES──► non_ipv4++   │
                    │           │         free(mbuf)   │
                    │           NO        continue     │
                    │           │                      │
                    │  rte_jhash(&tuple, 16, seed=0)   │
                    │  ring_idx = hash % 4             │
                    │           │                      │
                    │  rte_ring_enqueue(               │
                    │    worker_rings[ring_idx], mbuf) │
                    │           │                      │
                    │    fail?──┼──YES──► ring_drop++  │
                    │           │         free(mbuf)   │
                    │           NO                     │
                    │           │                      │
                    │  (mbuf now owned by Worker ring) │
                    └────────────────┬────────────────┘
                                     │
                    ┌────────────────▼────────────────┐
                    │  Stats Timer (every 1 second)    │
                    │  delta_s = Δcycles / tsc_hz      │
                    │  mbps = bytes×8 / 1e6 / delta_s  │
                    │  pps  = pkts / delta_s           │
                    │  Snapshot worker_stats[]         │
                    │  Print RUNTIME STATS             │
                    └─────────────────────────────────┘
```

### 4.2 Worker Path (lcore 1-4)

```
  rte_ring_dequeue(worker_rings[id], &obj)
         │
    NULL?──YES──────────────────────────────────────────► EXIT
         │
    NO (mbuf)
         │
  parse_packet_5tuple(mbuf, &tuple)
         │
    fail?──YES──► free(mbuf), continue
         │
    NO
         │
  ┌──────▼──────────────────────────────────────────────┐
  │  ACL Multi-Context Classify (tuần tự theo precedence)│
  │                                                      │
  │  g=0: fg_l34_facebook (prec=100)                    │
  │  ┌───────────────────────────────────────────┐       │
  │  │ rte_acl_classify(acl_ctx[0], &data, &r) │       │
  │  │ r != 0? ──YES──► MATCH facebook           │       │
  │  │                   global_idx = 0 + r - 1  │       │
  │  │                   hit_count[global_idx]++ │       │
  │  │                   group_hit_count[0]++    │       │
  │  │                   total_classified++       │       │
  │  │                   action = FORWARD         │       │
  │  │                   goto free_mbuf           │       │
  │  │ r == 0? ──YES──► next group               │       │
  │  └───────────────────────────────────────────┘       │
  │                                                      │
  │  g=1: fg_l34_youtube (prec=101)                     │
  │  ┌───────────────────────────────────────────┐       │
  │  │ rte_acl_classify(acl_ctx[1], &data, &r) │       │
  │  │ r != 0? ──YES──► MATCH youtube            │       │
  │  │                   global_idx = 5 + r - 1  │       │
  │  │                   ... update stats        │       │
  │  │                   action = DROP            │       │
  │  │                   goto free_mbuf           │       │
  │  │ r == 0? continue ...                      │       │
  │  └───────────────────────────────────────────┘       │
  │                                                      │
  │  g=2,3,4: fg_l34_http, https, dns (102,103,104)     │
  │  ... (tương tự)                                      │
  │                                                      │
  │  ALL GROUPS MISS → Zero-Trust DROP                   │
  │    default_drop_count++                              │
  │    total_classified++                                │
  └──────────────────────────────────────────────────────┘
         │
  free_mbuf:
  rte_pktmbuf_free(mbuf)
         │
  [Next dequeue]
```

---

## 5. Memory Layout & Ownership

```
HUGEPAGES MEMORY
┌─────────────────────────────────────────────────────────┐
│  SPIFAST_MBUF_POOL (rte_mempool)                        │
│  ┌───────────┬───────────┬─────────────┬───────────┐   │
│  │  mbuf[0]  │  mbuf[1]  │     ...     │ mbuf[8191]│   │
│  │  (4224B)  │  (4224B)  │             │  (4224B)  │   │
│  └───────────┴───────────┴─────────────┴───────────┘   │
│                                                         │
│  rte_ring[0..3] (ring buffers — pointer arrays)         │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐    │
│  │ ring_0[1024] │ │ ring_1[1024] │ │ ring_2[1024] │ ...│
│  │ (void* each) │ │              │ │              │    │
│  └──────────────┘ └──────────────┘ └──────────────┘    │
│                                                         │
│  ACL Contexts (per-group trie data)                     │
│  ┌────────────────────────────────────────────────┐     │
│  │ acl_ctx[facebook] | acl_ctx[youtube] | ...    │     │
│  └────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────┘

MBUF OWNERSHIP TIMELINE:
  PCAP PMD allocs → Dispatcher reads → ring enqueue → Worker dequeues → free
  OR (drop): Dispatcher allocs → ring fail → Dispatcher frees immediately
  OR (non-IPv4): Dispatcher gets → parse fails → Dispatcher frees immediately
```

---

## 6. Cấu Trúc Ring IPC

```
DISPATCHER (lcore 0) — Single Producer
         │
         │ rte_ring_enqueue(worker_rings[ring_idx], mbuf)
         │   ring_idx = jhash(tuple) % 4
         │
         ├─────────────────► spifast_ring_0 ─────────────► WORKER 0 (lcore 1)
         ├─────────────────► spifast_ring_1 ─────────────► WORKER 1 (lcore 2)
         ├─────────────────► spifast_ring_2 ─────────────► WORKER 2 (lcore 3)
         └─────────────────► spifast_ring_3 ─────────────► WORKER 3 (lcore 4)
                                                Single Consumer per ring

RING FLAGS: RING_F_SP_ENQ | RING_F_SC_DEQ
  → SPSC (Single Producer Single Consumer) = Lock-Free

RING SIZE: 1024 slots
  → Nếu ring đầy: Dispatcher tăng ring_drop_count và free mbuf
  → Không block, không retry (non-blocking enqueue)

SHUTDOWN PROTOCOL:
  SIGINT → force_quit=1 → Dispatcher gửi NULL sentinel vào mỗi ring
  Worker nhận NULL → thoát vòng lặp
```

---

## 7. ACL Multi-Context Architecture

```
SPI_policy.csv                    ACL Contexts (sau acl_build_all)
─────────────                     ──────────────────────────────────
fg_l34_facebook   prec=100  ───► acl_ctx[0] "spifast_acl_fg_l34_facebook"
fg_l34_youtube    prec=101  ───► acl_ctx[1] "spifast_acl_fg_l34_youtube"
fg_l34_http       prec=102  ───► acl_ctx[2] "spifast_acl_fg_l34_http_sdf1003"
fg_l34_https      prec=103  ───► acl_ctx[3] "spifast_acl_fg_l34_https_sdf1004"
fg_l34_dns        prec=104  ───► acl_ctx[4] "spifast_acl_fg_l34_dns_sdf1005"

filter_groups[] (sorted by precedence ascending):
  [0]: facebook (prec=100, rules=5, offset=0,  action=FORWARD)
  [1]: youtube  (prec=101, rules=4, offset=5,  action=DROP)
  [2]: http     (prec=102, rules=1, offset=9,  action=FORWARD)
  [3]: https    (prec=103, rules=1, offset=10, action=FORWARD)
  [4]: dns      (prec=104, rules=2, offset=11, action=DROP)

rule_action_map[] (global index → {group, action}):
  [0..4]:   facebook rules → FORWARD
  [5..8]:   youtube rules  → DROP
  [9]:      http rule      → FORWARD
  [10]:     https rule     → FORWARD
  [11..12]: dns rules      → DROP

Global Index Calculation:
  Worker gets result=R from acl_ctx[g]
  global_idx = filter_groups[g].global_rule_offset + R - 1
  action     = filter_groups[g].action  (không cần tra rule_action_map)
  stats→hit_count[global_idx]++
```

---

## 8. Byte Order Flow

```
CSV Files (text)
  "31.13.64.0/18"
         │
         │ parse_ip_prefix() → inet_pton() → ntohl()
         ▼
parsed_rules[i].dst_ip  = HOST BYTE ORDER (HBO)
parsed_rules[i].dst_mask = HBO

         │
         │ acl_build_all() → rte_acl_add_rules()
         │ ar.field[2].value.u32 = pr->dst_ip  (HBO)
         ▼
rte_acl_ctx (trie built internally)
  DPDK trie builder converts HBO → NBO internally

         │
         │ rte_acl_classify(ctx, &data_ptr, ...)
         │ data = (const uint8_t *)&tuple  ← five_tuple_t
         ▼
five_tuple_t.dst_ip  = NETWORK BYTE ORDER (NBO) ← từ ip->dst_addr trực tiếp
                                                   KHÔNG gọi ntohl()

                     MATCH khi NBO input khớp NBO pattern trong trie ✓
```

---

## 9. Stats Collection Architecture

```
DISPATCHER (lcore 0)              WORKER i (lcore i+1)
────────────────────              ────────────────────
disp_stats:                       worker_stats[i]:
  total_rx_pkts  ◄─ rx_burst        hit_count[r]       ◄─ ACL classify
  total_rx_bytes ◄─ rx_burst        group_hit_count[g] ◄─ ACL classify
  ring_drop_count◄─ enqueue fail    default_drop_count ◄─ no match
  non_ipv4_count ◄─ parse fail      total_classified   ◄─ every packet

PERIODIC STATS PRINT (every 1s, by Dispatcher):
  Read disp_stats (own data, no race)
  Read worker_stats[*] (snapshot volatile — may be slightly stale, acceptable)
  Aggregate: snap_group[g] = Σ worker_stats[w].group_hit_count[g]

FINAL STATS (after rte_eal_mp_wait_lcore()):
  All workers have exited → worker_stats[] is frozen
  Safe to read without any concurrency concern

MISSING RATE VERIFICATION:
  total_accounted = total_classified + non_ipv4_count + ring_drop_count
  assert(total_accounted == total_rx_pkts)  → Missing Rate = 0%
```

---

## 10. Shutdown Sequence

```
USER presses Ctrl+C
        │
        ▼
signal_handler(SIGINT)
  force_quit = 1

        │
        ▼ (in next while loop check)
dispatcher_run() exits while loop

        │
        ▼
for i = 0..3:
  while rte_ring_enqueue(worker_rings[i], NULL) != 0:
    busy-wait  ← retry until ring has space

        │
        ▼
Worker i receives NULL sentinel
  break out of for loop
  printf("[WORKER i] Finished: classified=%lu, default_drop=%lu")
  return 0

        │
        ▼
rte_eal_mp_wait_lcore()  ← in main(), waits for all lcores to return 0

        │
        ▼
print_final_stats()
  Collect all worker_stats[]
  Print SPI FINAL STATS
  Verify Missing Rate

        │
        ▼
acl_free_all()   → rte_acl_free() for each ctx
rte_eal_cleanup()
return 0
```
