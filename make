P4FILE=ddos_filter.p4
P4C=p4c
BMV2_SWITCH=simple_switch
RUNTIME_CLI=simple_switch_CLI
JSON=$(P4FILE:.p4=.json)

build:
	$(P4C) --target bmv2 --arch v1model -o $(JSON) $(P4FILE)

start:
	sudo $(BMV2_SWITCH) -i 0@veth0 -i 1@veth2 $(JSON)

test:
	sudo python3 test.py

stop:
	sudo pkill -9 simple_switch || true

clean:
	rm -f *.json *.log
