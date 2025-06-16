# -------- Makefile for ddos_guard demo -----------------------

P4SRC      := ddos_guard.p4
JSON       := ddos_guard.json
P4INFO     := ddos_guard.p4info
SWITCH_BIN := simple_switch
P4C        := p4c-bm2-ss          # change to plain p4c if you prefer
PORT0      := veth0
PORT1      := veth1
CLI_PORT   := 9090                # default Thrift port

.PHONY: build setup run test stop clean

# ---------- 1. Build ---------------------------------------------------------
build: $(JSON)

$(JSON): $(P4SRC)
	@echo "==> Compiling $(P4SRC)..."
	$(P4C) $(P4SRC) -o $(JSON)
	@echo "==> Build done: $(JSON)"

# ---------- 2. Network set-up -----------------------------------------------
setup:
	@echo "==> Creating veth pair $(PORT0)<->$(PORT1)"
	-@sudo ip link del $(PORT0) 2>/dev/null || true
	sudo ip link add $(PORT0) type veth peer name $(PORT1)
	sudo ip link set $(PORT0) up
	sudo ip link set $(PORT1) up
	@echo "==> veth ready"

# ---------- 3. Run BMv2 ------------------------------------------------------
run: build setup
	@echo "==> Starting BMv2 switch..."
	@sudo pkill $(SWITCH_BIN) 2>/dev/null || true
	sudo $(SWITCH_BIN) -i 0@$(PORT0) -i 1@$(PORT1) $(JSON) \
	    --device-id 0 --thrift-port $(CLI_PORT) &
	@sleep 1
	@echo "==> Switch running (PID $$!)"

# ---------- 4. Execute the Python test --------------------------------------
test:
	@echo "==> Running Scapy test script..."
	sudo python3 send_packets.py

# ---------- 5. Stop everything ----------------------------------------------
stop:
	@echo "==> Stopping BMv2 and helpers..."
	-@sudo pkill $(SWITCH_BIN) 2>/dev/null || true
	-@sudo pkill -f tcpdump 2>/dev/null || true
	-@sudo pkill -f python3 2>/dev/null || true
	@echo "==> Done"

# ---------- 6. Clean artefacts & veth ---------------------------------------
clean: stop
	@echo "==> Removing veth pair and build files..."
	-@sudo ip link del $(PORT0) 2>/dev/null || true
	-@rm -f $(JSON) $(P4INFO)
	@echo "==> Workspace clean"
