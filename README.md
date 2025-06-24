
# 34249_P4

## P4 Projects: V1 Model Approach & TNA Architecture

This repository contains two approaches to achieve DDoS Mitigation through Dataplane programming using P4 :

1. **V1 Model Approach**: An implementation designed for the BMv2 software switch using the `v1model` architecture.  
2. **TNA Architecture on Tofino**: An implementation designed for the Intel Tofino switch using the `TNA` architecture.

---

### 1. **V1 Model Approach**

This section details the setup and operation of the V1 Model approach using the BMv2 behavioral model.

#### **Setup Instructions**

To run this setup, you need to copy the contents of the `./V1_Model_Approach` folder into the `./behavioral-model/examples/custom_extern` directory of your BMv2 source installation. This is necessary for any custom externs used by the P4 program to be recognized by BMv2.

#### **Makefile Commands**

- **`make build`** – Compile the P4 source (`.p4`) into a BMv2-compatible JSON.  
- **`make setup`** – Create and configure veth pairs (`PORT0`, `PORT1`) for switch interfaces.  
- **`make run_all`** – Build (if needed), set up veths, and launch BMv2 switch with the compiled P4 program.  
- **`make config`** – Use P4Runtime CLI to install table rules and initialize registers (e.g., port thresholds).  
- **`make test`** – Launch background timestamp script and execute main test script.  
- **`make stop`** – Stop BMv2, Python processes, and clean up background tasks.  
- **`make clean`** – Stop all processes and remove generated artifacts and interfaces.  
- **`make run`** – Full pipeline: `clean → build → setup → run_all → config → test`.

---

### 2. **TNA Architecture on Tofino**

This section details the setup and operation of the TNA approach using the Intel Tofino SDE for the Nix package manager.

#### **Setup Instructions**

To run this setup, you need to import the `./ddos_filter_tna.p4` file into the Tofino switch, which can be done either directly using a USB drive, or remotely using "ssh".

#### **Compiling Commands**

Once the file is on the switch, it can be compiled by running the following commands:
- **`sde-env-9.13.4`** _ where "9.13.4" is the SDE version. This command enters the SDE.
- **`p4_build.sh ddos_filter_tna.p4`** _ Compiles the specified p4 file.
- **`run_switchd.sh -p ddos_filter_tna`** _ Runs the specified p4 file.

---
