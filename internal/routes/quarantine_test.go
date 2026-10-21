package routes

import (
	"testing"
	"time"
	"unsafe"

	"balancer/internal/ktls"
)

// setupQuarantineTestArena initializes a controlled mock arena containing 4 entities:
// - LE#0: Chain0 (ETH), Ankr, IP#0
// - LE#1: Chain0 (ETH), Ankr, IP#1
// - LE#2: Chain0 (ETH), QuickNode, IP#2
// - LE#3: Chain1 (Solana), Ankr, IP#0 (same host, but distinct chain and path)
func setupQuarantineTestArena() (sniAnkr unsafe.Pointer, sniQuick unsafe.Pointer) {
	bufAnkr := []byte("rpc.ankr.com\x00")
	bufQuick := []byte("quicknode.pro\x00")

	sniAnkr = unsafe.Pointer(&bufAnkr[0])
	sniQuick = unsafe.Pointer(&bufQuick[0])

	LogicalEntities[0] = ktls.LogicalEntity{
		Id:      0,
		ChainID: Chain0,
		SniPtr:  sniAnkr,
		SniLen:  12,
		Path:    "/eth/key",
		IpIdx:   0,
	}
	LogicalEntities[1] = ktls.LogicalEntity{
		Id:      1,
		ChainID: Chain0,
		SniPtr:  sniAnkr,
		SniLen:  12,
		Path:    "/eth/key",
		IpIdx:   1,
	}
	LogicalEntities[2] = ktls.LogicalEntity{
		Id:      2,
		ChainID: Chain0,
		SniPtr:  sniQuick,
		SniLen:  13,
		Path:    "/eth/key",
		IpIdx:   2,
	}
	LogicalEntities[3] = ktls.LogicalEntity{
		Id:      3,
		ChainID: Chain1,
		SniPtr:  sniAnkr,
		SniLen:  12,
		Path:    "/solana/key",
		IpIdx:   0,
	}

	for i := range 4 {
		LogicalEntities[i].Status.Store(StateHealthy)
		LogicalEntities[i].DisabledUntilSec.Store(0)
		LogicalEntities[i].ErrorCount.Store(0)
		LogicalEntities[i].LastErrorSec.Store(0)
	}

	AllIps[0] = IpEntry{AddrPortStr: "1.1.1.1:443"}
	AllIps[1] = IpEntry{AddrPortStr: "1.1.1.2:443"}
	AllIps[2] = IpEntry{AddrPortStr: "2.2.2.2:443"}

	for i := range 3 {
		AllIps[i].Status.Store(StateHealthy)
		AllIps[i].DisabledUntilMs.Store(0)
	}

	TotalLEs.Store(4)
	TotalIps.Store(3)

	return sniAnkr, sniQuick
}

// TestHandleL7Error_GroupBan_429 asserts that HTTP 429 rate limit triggers an immediate group ban:
// Both Ankr ETH entities (LE#0 and LE#1) must be quarantined, while QuickNode (LE#2) and Ankr Solana (LE#3) remain healthy.
func TestHandleL7Error_GroupBan_429(t *testing.T) {
	setupQuarantineTestArena()

	now := uint32(time.Now().Unix())
	HandleL7Error(0, 429)

	if LogicalEntities[0].Status.Load() != StateUnhealthy {
		t.Errorf("LE#0 expected StateUnhealthy, got %d", LogicalEntities[0].Status.Load())
	}
	if LogicalEntities[1].Status.Load() != StateUnhealthy {
		t.Errorf("LE#1 (neighbor Ankr) expected StateUnhealthy via group ban, got %d", LogicalEntities[1].Status.Load())
	}
	if LogicalEntities[0].DisabledUntilSec.Load() < now+9 {
		t.Errorf("LE#0 DisabledUntilSec expected >= %d, got %d", now+9, LogicalEntities[0].DisabledUntilSec.Load())
	}

	if LogicalEntities[2].Status.Load() != StateHealthy {
		t.Errorf("LE#2 (QuickNode) should NOT be banned, got %d", LogicalEntities[2].Status.Load())
	}
	if LogicalEntities[3].Status.Load() != StateHealthy {
		t.Errorf("LE#3 (Ankr Solana) should NOT be banned, got %d", LogicalEntities[3].Status.Load())
	}
}

// TestHandleL7Error_GroupBan_502 verifies that 5xx gateway failures trigger cluster-wide 60s quarantine.
func TestHandleL7Error_GroupBan_502(t *testing.T) {
	setupQuarantineTestArena()

	now := uint32(time.Now().Unix())
	HandleL7Error(1, 502)

	if LogicalEntities[0].Status.Load() != StateUnhealthy || LogicalEntities[1].Status.Load() != StateUnhealthy {
		t.Error("Expected both LE#0 and LE#1 to be Unhealthy after 502")
	}
	if LogicalEntities[1].DisabledUntilSec.Load() < now+59 {
		t.Errorf("DisabledUntilSec expected >= %d (60s ban), got %d", now+59, LogicalEntities[1].DisabledUntilSec.Load())
	}
	if LogicalEntities[2].Status.Load() != StateHealthy {
		t.Error("QuickNode should remain Healthy")
	}
}

// TestHandleL7Error_SingleBan_500 verifies that generic 500 errors quarantine only the single failing LE.
func TestHandleL7Error_SingleBan_500(t *testing.T) {
	setupQuarantineTestArena()

	HandleL7Error(0, 500)

	if LogicalEntities[0].Status.Load() != StateUnhealthy {
		t.Errorf("LE#0 expected Unhealthy, got %d", LogicalEntities[0].Status.Load())
	}
	if LogicalEntities[1].Status.Load() != StateHealthy {
		t.Errorf("LE#1 should remain Healthy on generic 500, got %d", LogicalEntities[1].Status.Load())
	}
}

// TestHandleL7Error_SlidingWindow_401 tests threshold escalation on consecutive auth errors.
func TestHandleL7Error_SlidingWindow_401(t *testing.T) {
	setupQuarantineTestArena()

	now := uint32(time.Now().Unix())

	// Attempt 1: Under threshold (1/3)
	HandleL7Error(0, 401)
	if LogicalEntities[0].Status.Load() != StateHealthy {
		t.Error("LE#0 should be Healthy after 1st 401")
	}
	if LogicalEntities[0].ErrorCount.Load() != 1 {
		t.Errorf("Expected ErrorCount=1, got %d", LogicalEntities[0].ErrorCount.Load())
	}

	// Attempt 2: Under threshold (2/3)
	HandleL7Error(0, 401)
	if LogicalEntities[0].Status.Load() != StateHealthy {
		t.Error("LE#0 should be Healthy after 2nd 401")
	}
	if LogicalEntities[0].ErrorCount.Load() != 2 {
		t.Errorf("Expected ErrorCount=2, got %d", LogicalEntities[0].ErrorCount.Load())
	}

	// Attempt 3: Threshold reached (3/3) -> Triggers group quarantine for 120s
	HandleL7Error(0, 401)
	if LogicalEntities[0].Status.Load() != StateUnhealthy {
		t.Errorf("LE#0 expected Unhealthy after 3rd 401, got %d", LogicalEntities[0].Status.Load())
	}
	if LogicalEntities[1].Status.Load() != StateUnhealthy {
		t.Errorf("LE#1 expected Unhealthy via group ban after 3rd 401, got %d", LogicalEntities[1].Status.Load())
	}
	if LogicalEntities[0].DisabledUntilSec.Load() < now+119 {
		t.Errorf("Expected ban duration >= 120s, got %d", LogicalEntities[0].DisabledUntilSec.Load())
	}
}

// TestMarkDeadL4 verifies L4 socket level quarantine.
func TestMarkDeadL4(t *testing.T) {
	setupQuarantineTestArena()

	nowMs := uint64(time.Now().UnixMilli())
	MarkDeadL4(0)

	if AllIps[0].Status.Load() != StateUnhealthy {
		t.Errorf("AllIps[0] expected StateUnhealthy, got %d", AllIps[0].Status.Load())
	}
	if AllIps[0].DisabledUntilMs.Load() < nowMs {
		t.Errorf("AllIps[0] DisabledUntilMs expected >= %d, got %d", nowMs, AllIps[0].DisabledUntilMs.Load())
	}
	if AllIps[1].Status.Load() != StateHealthy {
		t.Errorf("AllIps[1] expected StateHealthy, got %d", AllIps[1].Status.Load())
	}
}
