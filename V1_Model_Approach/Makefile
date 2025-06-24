P4SRC      := ddos_filter.p4
JSON       := ddos_filter.json
P4INFO     := ddos_filter.p4info
SWITCH_BIN := simple_switch
P4C        := p4c-bm2-ss
PORT0      := veth0
PORT1      := veth1
CLI_PORT   := 9090
TEST_SCRIPT := send_packets.py
P4CLI      := simple_switch_CLI
TIMESTAMP_SCRIPT := timestamp.py

.PHONY: all build setup run config test stop clean run_all

build: $(JSON)

$(JSON): $(P4SRC)
	@echo "Compiling $(P4SRC)..."
	$(P4C) --target bmv2 --arch v1model -o $(JSON) $(P4SRC)
	@echo "Build completed: $(JSON)"

setup:
	@echo "Creating veth pair $(PORT0)<->$(PORT1)"
	-@sudo ip link del $(PORT0) 2>/dev/null || true
	sudo ip link add $(PORT0) type veth peer name $(PORT1)
	sudo ip addr add 10.0.0.1/24 dev $(PORT0)
	sudo ip addr add 10.0.0.2/24 dev $(PORT1)
	sudo ip link set $(PORT0) up
	sudo ip link set $(PORT1) up
	@echo "veth interfaces configured and active"

run_all: build setup
	@echo "Starting BMv2 switch..."
	-@sudo pkill $(SWITCH_BIN) 2>/dev/null || true
	sudo $(SWITCH_BIN) -i 0@$(PORT0) -i 1@$(PORT1) $(JSON) \
		--device-id 0 --thrift-port $(CLI_PORT) &> /dev/null &
	@sleep 2
	@echo "BMv2 switch is now running"

config:
	@echo "Installing default rules and register values..."
	echo 'table_add allowed_ports allow 80 =>' | $(P4CLI) --thrift-port $(CLI_PORT)
	echo 'table_add allowed_ports allow 53 =>' | $(P4CLI) --thrift-port $(CLI_PORT)
	echo 'table_add blacklist_check drop 10.0.0.1 =>' | $(P4CLI) --thrift-port $(CLI_PORT)
	echo 'table_add whitelist allow 10.0.0.200 =>' | $(P4CLI) --thrift-port $(CLI_PORT)
	echo 'register_write port_thresh 80 10' | $(P4CLI) --thrift-port $(CLI_PORT)
	echo 'register_write port_thresh 53 10' | $(P4CLI) --thrift-port $(CLI_PORT)
	echo 'register_write port_thresh 777 5' | $(P4CLI) --thrift-port $(CLI_PORT)
	@echo "Configuration completed"

test:
	@echo "Starting timestamp updater..."
	nohup python3 $(TIMESTAMP_SCRIPT) &> timestamp.log &
	@echo "Running test script..."
	sudo python3 $(TEST_SCRIPT)



stop:
	@echo "Stopping BMv2 and related background processes..."
	-@sudo pkill $(SWITCH_BIN) 2>/dev/null || true
	-@sudo pkill -f tcpdump 2>/dev/null || true
	-@sudo pkill -f python3 $(TEST_SCRIPT) 2>/dev/null || true
	-@sudo pkill -f $(TIMESTAMP_SCRIPT) 2>/dev/null || true
	@echo "Processes terminated successfully"

clean: stop
	@echo "Cleaning up build artifacts and interfaces..."
	-@sudo ip link del $(PORT0) 2>/dev/null || true
	-@rm -f $(JSON) $(P4INFO)
	@echo "Workspace cleaned"

run: clean build setup run_all config test
	@echo "All setup and test steps completed successfully"
