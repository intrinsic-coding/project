// Package main is the entrypoint for the Web3 RPC Gateway (balancer-proxy).
//
// Architecture Highlights:
//   - Zero-Copy Data Plane: Uses Linux Kernel TLS (kTLS) and splice(2) to stream multi-megabyte
//     HTTP/2 RPC responses directly between upstream backend sockets and downstream clients.
//   - In-Kernel Telemetry: Traces pipe buffers using an eBPF fentry probe on splice_to_socket,
//     inspecting HTTP/2 status codes without copying packet payloads into userspace.
//   - Lock-Free Routing Plane: Leverages Per-CPU core round-robin counters (procPin),
//     pre-allocated flat arenas (AllIps, LogicalEntities), and atomic RCU snapshots.
package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"balancer/internal/chains"
	"balancer/internal/ebpf"
	"balancer/internal/ktls"
	"balancer/internal/routes"
	"balancer/internal/server"
	"balancer/internal/telemetry"
	"balancer/internal/utils"
)

// BuildTime: 1792592986

func main() {
	const port = "8443"
	const certFile = "certs/server.crt"
	const keyFile = "certs/server.key"

	// 1. Process Hardening: Audit TLS certificate SPKI fingerprint and elevate RLIMIT_NOFILE to 65535.
	if err := utils.LogFingerprintAndLimitFD(certFile, keyFile); err != nil {
		return
	}

	// 2. OpenSSL & kTLS Subsystem: Initialize global server and client SSL_CTX handles.
	ktls.InitServer()
	slog.Info("Starting ktls Traffic Server", "port", port)

	closeListener := func(ln net.Listener) {
		err := ln.Close()
		if err != nil {
			slog.Error("Failed to close listener", "error", err)
		}
	}

	// 3. Graceful Shutdown Context: Listen for SIGINT / SIGTERM signals.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 4. eBPF Tracing Subsystem:
	//    - Resolves live KASLR base offsets from /proc/kcore.
	//    - Loads and attaches the fentry/splice_to_socket probe.
	//    - Spawns ringbuf error readers and per-CPU metrics aggregation workers.
	mgr, err := ebpf.Load(ctx, telemetry.On200OK, telemetry.OnError)
	if err != nil {
		slog.Error("Failed to load ebpf", "error", err)
		return
	}
	defer func(mgr *ebpf.Manager) {
		err := mgr.Close()
		if err != nil {
			slog.Error("Failed to close ebpf", "error", err)
		}
	}(mgr)

	// 5. Routing Engine Initialization:
	//    - Pins host SNI C-strings once using runtime.Pinner.
	//    - Populates the canonical flat arenas (AllIps and LogicalEntities).
	//    - Computes vertical "snake" interleaving across providers and publishes the initial RCU snapshot.
	state, err := routes.InitRoutesFromConfig(ctx)
	if err != nil {
		slog.Error("InitRoutesFromConfig error", "error", err)
		return
	}

	// 6. Chain Drivers Wiring: Binds self-registered blockchain drivers to generated numeric ChainIDs.
	chains.InitDrivers()

	// 7. Core HTTP/2 Server: Listens on the incoming port and performs kTLS handshakes for clients.
	ln, err := server.H2Server(ctx, mgr, port)
	if err != nil {
		return
	}

	server.LogTopology(state, "[Init Topology]")

	// 8. Background Maintenance Workers:
	//    - DNS Resolver: Periodically polls nameservers, appends new IPs, and atomically updates topology.
	//    - Health Checker: Probes quarantined endpoints (L4 TCP+TLS and L7 JSON-RPC) to rehabilitate healed nodes.
	server.StartDNSResolver(ctx, 10*time.Second)
	server.StartHealthChecker(ctx, 15*time.Second)

	// 9. Observability Server: Exposes Prometheus metrics on :9090/metrics.
	shutdownTel, errTel := telemetry.Init(":9090")
	if errTel != nil {
		slog.Error("Failed to init telemetry", "err", errTel)
		closeListener(ln)
		return
	}
	defer func() {
		if err := shutdownTel(ctx); err != nil {
			slog.Error("Failed to shutdown telemetry", "err", err)
		}
	}()

	// 10. Wait for Termination Signal.
	<-ctx.Done()
	slog.Info("Exiting server...")

	// 11. Graceful Teardown: Close listener, unpin memory, release kernel pipes, flush telemetry.
	closeListener(ln)
	routes.ShutdownRoutes()
	ktls.ClosePipePool()
}
