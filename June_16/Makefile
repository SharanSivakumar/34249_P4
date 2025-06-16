# -------- Makefile for ddos_filter demo -----------------------

P4SRC      := ddos_filter.p4
JSON       := ddos_filter.json
SWITCH_BIN := simple_switch
P4C        := p4c-bm2-ss
PORT0      := veth0
PORT1      := veth1
CLI_PORT   := 9090

.PHONY: build setup run test stop clean

# ---------- 1. Build ---------------------------------------------------------
build: $(JSON)

$(JSON): $(P4SRC)
	@echo "==> Compiling $(P4SRC)..."
	$(P4C) --target bmv2 --arch v1model -o $(JSON) $(P4SRC)
	@echo "==> Build done: $(JSON)"

# ---------- 2. Network set-up -----------------------------------------------
setup:
	@echo "==> Creating veth pair $(PORT0)<->$(PORT1)"
	-@sudo ip link del $(PORT0) 2>/dev/null || true
	sudo ip link add $(PORT0) type veth peer name $(PORT1)
	sudo ip addr add 10.0.0.2/24 dev $(PORT1) || true
	sudo ip link set $(PORT0) up
	sudo ip link set $(PORT1) up
	@echo "==> veth ready"

# ---------- 3. Run BMv2 ------------------------------------------------------
run: build setup
	@echo "==> Starting BMv2 switch..."
	@sudo pkill $(SWITCH_BIN) 2>/dev/null || true
	sudo ~/behavioral-model/targets/simple_switch/simple_switch \
	    -i 0@$(PORT0) -i 1@$(PORT1) --thrift-port $(CLI_PORT) -- $(JSON) &
	@sleep 1
	@echo "==> Switch running (PID $$!)"

# ---------- 4. Execute the Python test --------------------------------------
test:
	@echo "==> Running test.py..."
	sudo python3 test.py

# ---------- 5. Stop everything ----------------------------------------------
stop:
	@echo "==> Stopping BMv2 and related processes..."
	-@sudo pkill $(SWITCH_BIN) 2>/dev/null || true
	-@sudo pkill -f tcpdump 2>/dev/null || true
	-@sudo pkill -f python3 2>/dev/null || true
	@echo "==> Done"

# ---------- 6. Clean artefacts & veth ---------------------------------------
clean: stop
	@echo "==> Removing veth pair and build files..."
	-@sudo ip link del $(PORT0) 2>/dev/null || true
	-@rm -f $(JSON)
	@echo "==> Workspace clean"
