package routes

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"syscall"
	"time"
	_ "unsafe"

	"balancer/internal/ktls"

	"golang.org/x/sys/unix"
)

// Direct runtime linkage to procPin / procUnpin:
// Pins the running goroutine to the current logical processor (P). This guarantees that
// accessing the Per-P array (PerPStores[pid]) is strictly core-local and free of race conditions
// without requiring atomic CAS operations or OS thread locks.
//
//go:linkname procPin runtime.procPin
func procPin() int

//go:linkname procUnpin runtime.procUnpin
func procUnpin()

// Dial establishes an outbound non-blocking L4 TCP connection to the target IP entry:
//   - Extracts raw file descriptor via SyscallConn.
//   - Sets socket to non-blocking false for the Cgo OpenSSL kTLS handshake phase.
//   - Enforces TCP_USER_TIMEOUT (2000 ms, RFC 5482): if in-flight packets are dropped (e.g. firewall drop),
//     the Linux kernel forcefully aborts the socket with ETIMEDOUT instead of hanging for hours in TCP retransmissions.
func Dial(ctx context.Context, ipIdx int32) (net.Conn, int, error) {
	tcpConn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialTCP(
		ctx, "tcp", netip.AddrPort{}, AllIps[ipIdx].AddrPort)
	if err != nil {
		return nil, 0, err
	}
	conn := net.Conn(tcpConn)
	var fd int
	raw, err := conn.(syscall.Conn).SyscallConn()
	if err == nil {
		err = raw.Control(func(f uintptr) { fd = int(f) })
	}
	if err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	if err = syscall.SetNonblock(fd, false); err != nil {
		_ = conn.Close()
		return nil, -1, err
	}
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, 2000)
	return conn, fd, nil
}

// MarkDeadL4 marks a specific L4 IP entry as unhealthy upon transport connect failure.
func MarkDeadL4(ipIdx int32) {
	if int(ipIdx) < int(TotalIps.Load()) {
		AllIps[ipIdx].Status.Store(StateUnhealthy)
		AllIps[ipIdx].DisabledUntilMs.Store(uint64(time.Now().UnixMilli()))
	}
}

// MarkDeadL7 marks a LogicalEntity as unhealthy upon TLS/kTLS handshake failure.
func MarkDeadL7(le *ktls.LogicalEntity) {
	if le != nil {
		le.Status.Store(StateUnhealthy)
		le.DisabledUntilSec.Store(uint32(time.Now().Unix()))
	}
}

// HandleL7Error evaluates HTTP status codes returned by backend RPC nodes:
//   - Status 429, 502, 503, 504, 408: triggers an immediate GROUP BAN across all LogicalEntities
//     sharing the same (ChainID, SniPtr, Path). Comparing SniPtr is an O(1) pointer comparison (200ns)
//     preventing sequential round-robin burn of sibling IPs belonging to an already degraded provider.
//   - Status 401, 403: implements a sliding window (3 failures within 10s) before group-banning for 120s.
//   - Generic 500: quarantines only the individual failing LogicalEntity for 60s.
func HandleL7Error(leID uint64, status uint16) {
	if leID >= uint64(TotalLEs.Load()) {
		return
	}
	target := &LogicalEntities[leID]
	nowSec := uint32(time.Now().Unix())
	var banDuration uint32

	switch {
	// Cluster degradation or rate limiting: ban all sibling IPs for this provider on this chain.
	case status == 429:
		banDuration = 10
		slog.Warn("Node rate limited (429), banning entire host", "le_id", leID)
	case status == 502 || status == 503 || status == 504 || status == 408:
		banDuration = 60
		slog.Warn("Host cluster degraded (5xx), banning entire host", "le_id", leID, "status", status)

	// Auth error sliding window: requires 3 errors within AuthErrorWindowSec to trigger ban.
	case status == 401 || status == 403:
		lastSec := target.LastErrorSec.Load()
		if nowSec-lastSec > AuthErrorWindowSec {
			target.LastErrorSec.Store(nowSec)
			target.ErrorCount.Store(1)
			return
		}
		if target.ErrorCount.Add(1) >= AuthErrorThreshold {
			banDuration = 120
			target.ErrorCount.Store(0)
			slog.Error("Auth failed repeatedly (401/403), banning entire host", "le_id", leID)
		} else {
			return
		}
	default:
		// Generic 500: quarantine individual LE.
		target.Status.Store(StateUnhealthy)
		target.DisabledUntilSec.Store(nowSec + 60)
		return
	}

	// Group quarantine sweep: match ChainID, SniPtr (O(1) scalar comparison), and Path.
	total := int(TotalLEs.Load())
	disabledUntil := nowSec + banDuration
	for i := range total {
		le := &LogicalEntities[i]
		if le.ChainID == target.ChainID && le.SniPtr == target.SniPtr && le.Path == target.Path {
			le.Status.Store(StateUnhealthy)
			le.DisabledUntilSec.Store(disabledUntil)
		}
	}
}

// GetRoute selects the next upstream LogicalEntity from the active RCU generation snapshot.
// Evaluates per-CPU core round-robin counters using procPin, returning in 1 CPU instruction.
func GetRoute(state *RoutingState, chainID int) (*ktls.LogicalEntity, error) {
	if chainID < 0 || chainID >= MaxChains {
		return nil, fmt.Errorf("invalid chain ID")
	}
	gen := &state.Chains[chainID]
	if gen.Count == 0 {
		return nil, fmt.Errorf("no upstreams in chain %d", chainID)
	}
	pid := procPin()
	idx := PerPStores[pid].LocalRrCounters[chainID]
	PerPStores[pid].LocalRrCounters[chainID]++
	procUnpin()
	leIdx := gen.ActiveIndices[idx%gen.Count]
	return &LogicalEntities[leIdx], nil
}

// DialFallbackSlowPath iterates through alternate endpoints in the active snake ring if primary dial fails.
// Skips endpoints flagged as StateUnhealthy, attempting TCP connect and kTLS handshake until success.
//
//go:noinline
func DialFallbackSlowPath(
	ctx context.Context, state *RoutingState, chainID int, failedTrioId uint64,
	cbMetricTCP func(ctx context.Context, state *RoutingState, leID uint64, ms float64),
	cbMetricTLS func(ctx context.Context, state *RoutingState, leID uint64, ms float64),
	cbMetricQuarantine func(ctx context.Context, le *ktls.LogicalEntity, reason string),
) (net.Conn, *ktls.LogicalEntity, error) {
	if chainID < 0 || chainID >= MaxChains {
		return nil, nil, fmt.Errorf("invalid chain ID")
	}
	gen := &state.Chains[chainID]
	if gen.Count == 0 {
		return nil, nil, fmt.Errorf("no upstreams in chain %d", chainID)
	}
	pid := procPin()
	startIdx := PerPStores[pid].LocalRrCounters[chainID]
	PerPStores[pid].LocalRrCounters[chainID]++
	procUnpin()
	leCount := gen.Count
	indices := gen.ActiveIndices
	var tMetric time.Time

	for i := uint64(1); i < leCount; i++ {
		leIdx := indices[(startIdx+i)%leCount]
		le := &LogicalEntities[leIdx]
		if le.Id == failedTrioId {
			continue
		}
		if AllIps[le.IpIdx].Status.Load() != StateHealthy || le.Status.Load() != StateHealthy {
			continue
		}
		tMetric = time.Now()
		conn, fd, errDial := Dial(ctx, le.IpIdx)
		if errDial != nil {
			MarkDeadL4(le.IpIdx)
			cbMetricQuarantine(ctx, le, "failed l4: "+errDial.Error())
			continue
		}
		cbMetricTCP(ctx, state, le.Id, float64(time.Since(tMetric))*1e-6)

		tMetric = time.Now()
		upConn, errUpstream := ktls.DialUpstream(fd, conn, le.SniPtr)
		if errUpstream != nil {
			_ = conn.Close()
			MarkDeadL7(le)
			cbMetricQuarantine(ctx, le, "failed l7: "+errUpstream.Error())
			continue
		}
		cbMetricTLS(ctx, state, le.Id, float64(time.Since(tMetric))*1e-6)
		return upConn, le, nil
	}
	return nil, nil, fmt.Errorf("all upstreams failed in chain %d", chainID)
}

// RecordRequestBytes adds incoming request bytes to core-local atomic storage (procPin).
//
//go:noinline
func RecordRequestBytes(leID uint64, bytes uint64) {
	pid := procPin()
	PerPMetricsStore[pid][leID].RequestBytes.Add(bytes)
	procUnpin()
}

// RecordResponseBytes adds spliced response bytes to core-local atomic storage (procPin).
//
//go:noinline
func RecordResponseBytes(leID uint64, bytes uint64) {
	pid := procPin()
	PerPMetricsStore[pid][leID].ResponseBytes.Add(bytes)
	procUnpin()
}
