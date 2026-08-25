# eBPF Firewall Engineering Makefile
.PHONY: all deps build-bpf build netns-up netns-down cgroup-setup cgroup-down run-agent test-phase1 test-phase2 test-phase3 dump-maps monitor clean

CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86
BPF2GO ?= go run github.com/cilium/ebpf/cmd/bpf2go
GO ?= go

CLIENT_NS = client
SERVER_NS = server
IFACE = veth-s

all: build-bpf build

## 1. Environment & Dependency Checks
deps:
	@echo "==> Checking build dependencies..."
	@which $(CLANG) >/dev/null || (echo "clang missing"; exit 1)
	@which $(GO) >/dev/null || (echo "go missing"; exit 1)
	@which ip >/dev/null || (echo "iproute2 missing"; exit 1)
	@echo "==> All dependencies satisfied."

## 2. eBPF Compilation
build-bpf:
	@echo "==> Generating eBPF Go bindings via go generate..."
	$(GO) generate ./pkg/bpf/...


## 3. Go Binary Build
build:
	@echo "==> Building Go control plane binaries..."
	mkdir -p bin
	$(GO) build -o bin/firewall-agent ./cmd/firewall-agent
	$(GO) build -o bin/firewall-ctl ./cmd/firewall-ctl
	$(GO) build -o bin/firewall-tui ./cmd/firewall-tui
	$(GO) build -o bin/pktgen ./cmd/pktgen

## 4. Test Environment Provisioning
netns-up:
	@sudo ./scripts/setup_netns.sh

netns-down:
	@sudo ./scripts/teardown_netns.sh

cgroup-setup:
	@sudo ./scripts/setup_cgroup.sh

cgroup-down:
	@sudo ./scripts/teardown_cgroup.sh


## 5. Execution & Phase Integration Testing
run-agent:
	@echo "==> Running firewall agent in server netns attached to $(IFACE)..."
	sudo ip netns exec $(SERVER_NS) ./bin/firewall-agent --iface $(IFACE) --config configs/policy.example.yaml

test-phase1: netns-up
	@echo "==> Executing Phase 1 Stateless XDP Drop Test..."
	@echo "[1] Testing connectivity before policy load (expect PASS)..."
	sudo ip netns exec $(CLIENT_NS) ping -c 2 10.0.0.2
	@echo "[2] Starting firewall agent in background..."
	sudo ip netns exec $(SERVER_NS) ./bin/firewall-agent --iface $(IFACE) --block-cidr 10.0.0.1/32 & AGENT_PID=$$!; \
	sleep 2; \
	echo "[3] Testing blocked CIDR (expect DROP / 100% loss)..."; \
	sudo ip netns exec $(CLIENT_NS) ping -c 3 -W 1 10.0.0.2 || true; \
	sudo kill -9 $$AGENT_PID 2>/dev/null || true
	@make netns-down

test-phase2: netns-up
	@echo "==> Executing Phase 2 TC Stateful Conntrack Test..."
	sudo $(GO) test -v ./test/e2e -run TestStatefulConntrack

test-phase3: netns-up cgroup-setup
	@echo "==> Executing Phase 3 Cgroup Identity Resolution Test..."
	sudo $(GO) test -v ./test/e2e -run TestCgroupIdentity

## 6. Inspection & Debugging Tools
dump-maps:
	@echo "==> Dumping active eBPF maps..."
	sudo bpftool map dump name xdp_stats_map || true
	sudo bpftool map dump name lpm_blocklist || true
	sudo bpftool map dump name conntrack_map || true

monitor:
	@echo "==> Streaming BPF kernel tracepipe..."
	sudo cat /sys/kernel/debug/tracing/trace_pipe

## 7. Clean Artifacts
clean: netns-down cgroup-down
	@echo "==> Cleaning build artifacts..."
	rm -rf bin/
	rm -f pkg/bpf/xdp_bpf* pkg/bpf/tc_bpf*
	@echo "==> Clean complete."
