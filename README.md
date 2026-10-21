# Balancer-Proxy: Zero-Copy Responses Web3 RPC Gateway

[![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white)]()
[![C](https://img.shields.io/badge/C-A8B9CC?logo=c&logoColor=black)]()
[![Kernel: Linux](https://img.shields.io/badge/Kernel-Linux%206.8%2B-orange.svg)]()
[![Data Plane: KTLS + splice](https://img.shields.io/badge/Data%20Plane-KTLS%20%2B%20splice(2)-green.svg)]()
[![Observability: eBPF CO-RE](https://img.shields.io/badge/Tracing-eBPF%20fentry-red.svg)](./internal/ebpf/src/bpf_h2_parser.c)
[![License: All Rights Reserved](https://img.shields.io/badge/License-All%20Rights%20Reserved-red?logo=gnu&logoColor=white)](LICENSE)

A specialized, performance L7 Web3 RPC Gateway designed for high-throughput blockchain node infrastructures.

Designed for infrastructure scenarios where clients (validators, indexers, dApp backends, arbitrage bots) utilize persistent HTTP/2 connections and implement their own request-retry mechanisms upon connection drops.

## Key Architectural Features

- **Asymmetric Data Plane:** Inbound JSON-RPC requests are handled in Go userspace (header parsing, routing). Heavy node responses (blocks, logs, transactions) are transferred **entirely within Linux kernel space** via the `splice(2)` system call and **Kernel TLS (`kTLS`)**, bypassing application memory copying.
- **Session Model (1 Client to 1 Backend):** Load balancing and upstream binding are performed at the connection level.
- **eBPF In-Kernel Telemetry:** HTTP/2 status tracing (200 OK, 429, 5xx) is performed inside the kernel using an `fentry` hook on `splice_to_socket`, reading data directly from pipe memory pages.
- **Lock-Free Routing (RCU):** Network topology is stored in immutable snapshots swapped via atomic pointers. Routing utilizes core-local counters (`procPin`).

---

## System Requirements

- **OS:** Linux (Kernel 6.8+ Debian-based distribution with `CONFIG_TLS` and `CONFIG_BPF_SYSCALL` support).
- **Tools:** Go 1.26+, `clang` 14+, `gcc`, `make`, `docker`.
- **Privileges:** `root` (required for loading eBPF programs and reading `/proc/kcore`).

---

## Build and Run

### 1. Configuration
Ensure `config.json` with chain node manifests is properly set up in the project root.

### 2. Building the Project
To verify dependencies, generate routes, compile eBPF/C components, and build the static Go binary, run:

```bash
make
sudo ./proxy
```
### 3. Docker Benchmark Suite (Comparing with NGINX)
Assumes Docker is already installed:
```bash
make docker-build
make benchmark
```

## Detailed documentation

- [Data plane and routing architecture (kTLS, splice, eBPF)](docs/architecture.md)
- [Fault tolerance, quarantine, and health checking (Circuit Breaker)](docs/circuit_breaker.md)
- [Development and optimization plans (Roadmap)](docs/roadmap.md)