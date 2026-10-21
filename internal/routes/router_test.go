package routes

import (
	"runtime"
	"testing"

	"balancer/internal/ktls"
)

func initTestPerP() {
	if len(PerPStores) == 0 {
		numP := runtime.GOMAXPROCS(0)
		PerPStores = make([]PerPStore, numP)
	}
}

// TestMatchChainID validates fast byte-prefix matching against incoming URL request paths.
func TestMatchChainID(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected int
	}{
		{"ETH root", "/eth", Chain0},
		{"ETH subpath", "/eth/rpc/v1", Chain0},
		{"Solana root", "/solana", Chain1},
		{"Solana subpath", "/solana/mainnet", Chain1},
		{"TRX root", "/trx", Chain2},
		{"TRX subpath", "/trx/key", Chain2},
		{"Unknown path", "/polygon", -1},
		{"Partial mismatch", "/sol", -1},
		{"Empty path", "", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchChainID([]byte(tt.path))
			if got != tt.expected {
				t.Errorf("MatchChainID(%q) = %d, expected %d", tt.path, got, tt.expected)
			}
		})
	}
}

// TestGetChainNameByID validates mapping of numeric chain IDs to human-readable string labels.
func TestGetChainNameByID(t *testing.T) {
	tests := []struct {
		id       int32
		expected string
	}{
		{Chain0, "eth"},
		{Chain1, "solana"},
		{Chain2, "trx"},
		{-1, ""},
		{99, ""},
	}

	for _, tt := range tests {
		got := GetChainNameByID(tt.id)
		if got != tt.expected {
			t.Errorf("GetChainNameByID(%d) = %q, expected %q", tt.id, got, tt.expected)
		}
	}
}

// TestGetRoute_Validation asserts boundary guards against invalid IDs and empty chains (divide-by-zero protection).
func TestGetRoute_Validation(t *testing.T) {
	initTestPerP()
	state := &RoutingState{}

	if _, err := GetRoute(state, -1); err == nil {
		t.Error("GetRoute(-1) expected error, got nil")
	}

	if _, err := GetRoute(state, MaxChains); err == nil {
		t.Errorf("GetRoute(%d) expected error, got nil", MaxChains)
	}

	state.Chains[Chain0] = ChainGeneration{
		ActiveIndices: nil,
		Count:         0,
	}
	if _, err := GetRoute(state, Chain0); err == nil {
		t.Error("GetRoute on empty chain expected error, got nil")
	}
}

// TestGetRoute_RoundRobinCycle tests strict deterministic cycling through the interleaved snake sequence.
func TestGetRoute_RoundRobinCycle(t *testing.T) {
	initTestPerP()

	LogicalEntities[0] = ktls.LogicalEntity{Id: 0, Path: "/node-0"}
	LogicalEntities[1] = ktls.LogicalEntity{Id: 1, Path: "/node-1"}
	LogicalEntities[2] = ktls.LogicalEntity{Id: 2, Path: "/node-2"}

	expectedSequence := []uint64{0, 2, 1}

	state := &RoutingState{}
	state.Chains[Chain0] = ChainGeneration{
		ActiveIndices: []int{0, 2, 1},
		Count:         3,
	}

	for round := range 2 {
		for i, expectedID := range expectedSequence {
			le, err := GetRoute(state, Chain0)
			if err != nil {
				t.Fatalf("GetRoute unexpected error on step %d: %v", i, err)
			}
			if le.Id != expectedID {
				t.Errorf("Step %d (round %d): expected LE#%d, got LE#%d", i, round, expectedID, le.Id)
			}
		}
	}
}
