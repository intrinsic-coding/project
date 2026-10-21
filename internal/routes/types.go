package routes

import (
	"errors"
	"net/netip"
	"runtime"
	"sync/atomic"

	"balancer/internal/ebpf"
	"balancer/internal/ktls"

	"go.opentelemetry.io/otel/metric"
)

const (
	// MaxIPs defines the maximum unique L4 IP endpoints held in the canonical flat arena (256).
	MaxIPs = ebpf.LesPerCPU >> 1

	// MaxLEs defines the maximum LogicalEntities in the canonical flat arena (512), matching eBPF LE_PER_CPU.
	MaxLEs = ebpf.LesPerCPU
)

// IpEntry models a single physical L4 network endpoint in the canonical arena.
type IpEntry struct {
	AddrPort        netip.AddrPort // Parsed IPv4/IPv6 socket address and port
	AddrPortStr     string         // Pre-formatted string cache (e.g. "1.1.1.1:443")
	Status          atomic.Uint64  // L4 health status: StateHealthy (0) or StateUnhealthy (1)
	DisabledUntilMs atomic.Uint64  // Unix epoch timestamp (milliseconds) until L4 reconnect cooldown expires
}

// ChainGeneration holds the active round-robin interleaving sequence for a specific chain.
type ChainGeneration struct {
	ActiveIndices []int  // Flattened "snake" index sequence referencing LogicalEntities
	Count         uint64 // Length of ActiveIndices for O(1) modulo arithmetic
}

// RoutingState represents an immutable RCU snapshot of the active network topology.
// Swapped atomically via GlobalRoutingState.Store() when DNS changes occur.
type RoutingState struct {
	Chains      [MaxChains]ChainGeneration
	MetricAttrs []metric.MeasurementOption // Pre-computed OpenTelemetry measurement options
}

// PerPStore maintains thread-local round-robin counters pinned to logical Go processor IDs (P).
type PerPStore struct {
	LocalRrCounters [MaxChains]uint64
}

// LeMetrics stores atomic byte volume counters aggregated across CPU cores.
type LeMetrics struct {
	RequestBytes  atomic.Uint64
	ResponseBytes atomic.Uint64
}

const (
	StateHealthy       = 0
	StateUnhealthy     = 1
	AuthErrorWindowSec = 10 // Sliding window duration (seconds) for auth error accumulation
	AuthErrorThreshold = 3  // Consecutive 401/403 errors required to trigger cluster quarantine
)

var (

	// Canonical Flat Arenas: Pre-allocated static arrays ensuring zero runtime allocations
	// and eliminating lost update races across goroutines.

	AllIps          [MaxIPs]IpEntry
	LogicalEntities [MaxLEs]ktls.LogicalEntity
	TotalIps        atomic.Uint32
	TotalLEs        atomic.Uint32

	// GlobalRoutingState holds the active immutable RCU snapshot.
	GlobalRoutingState atomic.Pointer[RoutingState]

	// PerPStores partitions state by GOMAXPROCS to eliminate lock contention on hot paths.
	PerPStores       []PerPStore
	PerPMetricsStore [][]LeMetrics

	// LePinners stores runtime.Pinner handles to ensure pinned C-strings survive GC sweeps.
	LePinners []runtime.Pinner

	// ErrNodeQuarantined is returned when a connection is dropped due to active node quarantine.
	ErrNodeQuarantined = errors.New("node quarantined")
)
