package server

import (
	"net/netip"
	"testing"
	"unsafe"

	"balancer/internal/routes"

	"go.opentelemetry.io/otel/metric"
)

func resetArenaForTest() {
	routes.TotalIps.Store(0)
	routes.TotalLEs.Store(0)
}

// TestFindOrAddIP_DeduplicationAndLimit asserts that duplicate IP addresses re-use their existing slot
// without incrementing TotalIps, and verifies that exceeding MaxIPs safely returns -1 without panicking.
func TestFindOrAddIP_DeduplicationAndLimit(t *testing.T) {
	resetArenaForTest()

	ip1 := netip.MustParseAddrPort("127.0.0.1:443")
	ip2 := netip.MustParseAddrPort("127.0.0.2:443")

	idx0 := findOrAddIP(ip1)
	if idx0 != 0 {
		t.Fatalf("Expected index 0, got %d", idx0)
	}
	if routes.TotalIps.Load() != 1 {
		t.Fatalf("Expected TotalIps=1, got %d", routes.TotalIps.Load())
	}

	idx0Dup := findOrAddIP(ip1)
	if idx0Dup != 0 {
		t.Fatalf("Expected deduplicated index 0, got %d", idx0Dup)
	}
	if routes.TotalIps.Load() != 1 {
		t.Fatalf("TotalIps should remain 1 on duplicate, got %d", routes.TotalIps.Load())
	}

	idx1 := findOrAddIP(ip2)
	if idx1 != 1 {
		t.Fatalf("Expected index 1, got %d", idx1)
	}
	if routes.TotalIps.Load() != 2 {
		t.Fatalf("Expected TotalIps=2, got %d", routes.TotalIps.Load())
	}

	// Boundary check: verify overflow handling.
	routes.TotalIps.Store(routes.MaxIPs)
	ipOverflow := netip.MustParseAddrPort("10.0.0.1:443")
	overflowIdx := findOrAddIP(ipOverflow)
	if overflowIdx != -1 {
		t.Fatalf("Expected -1 on MaxIPs overflow, got %d", overflowIdx)
	}
}

// TestFindOrAddLE_DeduplicationAndLimit ensures logical entity deduplication on (ChainID, IpIdx, Path),
// verifies pre-allocation of metric attributes, and validates MaxLEs capacity bounds.
func TestFindOrAddLE_DeduplicationAndLimit(t *testing.T) {
	resetArenaForTest()

	routes.AllIps[0] = routes.IpEntry{
		AddrPort:    netip.MustParseAddrPort("127.0.0.1:443"),
		AddrPortStr: "127.0.0.1:443",
	}
	routes.TotalIps.Store(1)

	state := &routes.RoutingState{
		MetricAttrs: make([]metric.MeasurementOption, routes.MaxLEs),
	}

	dummyHost := "rpc.ankr.com\x00"
	dummySniPtr := unsafe.Pointer(unsafe.StringData(dummyHost))
	dummySniLen := int32(len("rpc.ankr.com"))

	leIdx0 := findOrAddLE(routes.Chain0, "rpc.ankr.com", "/eth/key", dummySniPtr, dummySniLen, 0, state)
	if leIdx0 != 0 {
		t.Fatalf("Expected LE index 0, got %d", leIdx0)
	}
	if routes.TotalLEs.Load() != 1 {
		t.Fatalf("Expected TotalLEs=1, got %d", routes.TotalLEs.Load())
	}
	if state.MetricAttrs[0] == nil {
		t.Error("MetricAttrs[0] should be initialized for new LE")
	}

	leIdx0Dup := findOrAddLE(routes.Chain0, "rpc.ankr.com", "/eth/key", dummySniPtr, dummySniLen, 0, state)
	if leIdx0Dup != 0 {
		t.Fatalf("Expected deduplicated LE index 0, got %d", leIdx0Dup)
	}
	if routes.TotalLEs.Load() != 1 {
		t.Fatalf("TotalLEs should remain 1 on duplicate LE, got %d", routes.TotalLEs.Load())
	}

	leIdx1 := findOrAddLE(routes.Chain0, "rpc.ankr.com", "/eth/different-path", dummySniPtr, dummySniLen, 0, state)
	if leIdx1 != 1 {
		t.Fatalf("Expected LE index 1 for different path, got %d", leIdx1)
	}
	if routes.TotalLEs.Load() != 2 {
		t.Fatalf("Expected TotalLEs=2, got %d", routes.TotalLEs.Load())
	}

	// Boundary check: verify overflow handling.
	routes.TotalLEs.Store(routes.MaxLEs)
	overflowLE := findOrAddLE(routes.Chain0, "rpc.ankr.com", "/eth/overflow", dummySniPtr, dummySniLen, 0, state)
	if overflowLE != -1 {
		t.Fatalf("Expected -1 on MaxLEs overflow, got %d", overflowLE)
	}
}
