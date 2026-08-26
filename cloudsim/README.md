# SecureIaC CloudSim Plus Testbed

## Overview

This folder contains the CloudSim Plus simulation environment developed
for the SecureIaC project Review 1.

The purpose of the simulation is to establish a working cloud simulation
testbed and demonstrate successful execution of virtual machines and
cloud-based tasks.

## Software Environment

- Java: JDK 17.0.12
- Maven: 3.9.16
- CloudSim Plus: 8.5.7
- Operating System: Windows 11

## Simulation Configuration

The simulation contains:

- 1 Datacenter
- 2 Hosts
- 3 Virtual Machines (VMs)
- 1 DatacenterBroker
- 6 Cloudlets / tasks

### Datacenter

One simulated datacenter is created.

### Hosts

Two hosts are created. Each host contains:

- 4 CPU cores
- 1000 MIPS per CPU core
- 8192 MB RAM
- 10000 Mbps bandwidth
- 1000000 MB storage

### Virtual Machines

Three VMs are created and submitted to the DatacenterBroker.

### Cloudlets

Six Cloudlets are created with different workload lengths and submitted
through the DatacenterBroker.

## Build

From the `cloudsim` directory, run:

```bash
mvn clean package