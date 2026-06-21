# ============================================================
# Makefile - SPIFast (SPI Packet Classifier using DPDK)
# ============================================================
# Build chuẩn DPDK >= 20.11 dùng pkg-config (không dùng RTE_SDK/RTE_TARGET cũ)
# ============================================================

APP := spifast

# Thư mục mã nguồn / build
SRC_DIR := src
BUILD_DIR := build

# Tự động lấy danh sách file .c trong src/ (sẽ tăng dần khi thêm module)
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# ------------------------------------------------------------
# pkg-config cho libdpdk (bắt buộc cài dpdk-dev / libdpdk-dev trước)
# ------------------------------------------------------------
PKGCONF := pkg-config
PC_FILE := libdpdk

ifeq ($(shell $(PKGCONF) --exists $(PC_FILE) && echo 0),0)
    DPDK_CFLAGS := $(shell $(PKGCONF) --cflags $(PC_FILE))
    DPDK_LIBS   := $(shell $(PKGCONF) --libs $(PC_FILE))
else
    $(error "Khong tim thay libdpdk qua pkg-config. Kiem tra: pkg-config --list-all | grep dpdk")
endif

# ------------------------------------------------------------
# Cờ biên dịch
# ------------------------------------------------------------
CC := gcc
CFLAGS := -O3 -g -Wall -Wextra -std=gnu11
CFLAGS += -I$(SRC_DIR)
CFLAGS += $(DPDK_CFLAGS)

LDFLAGS := $(DPDK_LIBS)

# ------------------------------------------------------------
# Targets
# ------------------------------------------------------------
.PHONY: all clean run

all: $(BUILD_DIR) $(APP)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(APP): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(APP)

# Chạy thử nghiệm nhanh (cấu hình EAL cố định theo spec 4.4)
# Yêu cầu: đã setup hugepages, có traffic_sample.pcap trong thư mục hiện tại
run: all
	sudo ./$(APP) --lcores='0-4' \
		--vdev="net_pcap0,rx_pcap=traffic_sample.pcap" \
		-- -r SPI_rule.csv -p SPI_policy.csv
