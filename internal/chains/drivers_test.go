package chains

import (
	"net/http"
	"testing"

	"balancer/internal/routes"
)

// TestInitDrivers asserts that all chains configured in StaticChainManifests
// are mapped to non-nil drivers in the flat Drivers array.
func TestInitDrivers(t *testing.T) {
	InitDrivers()

	for chainID := range routes.MaxChains {
		driver := Drivers[chainID]
		if driver == nil {
			t.Fatalf("Driver for chainID %d is nil after InitDrivers", chainID)
		}
		expectedName := routes.GetChainNameByID(int32(chainID))
		if driver.Name() != expectedName {
			t.Errorf("ChainID %d: expected driver name %q, got %q", chainID, expectedName, driver.Name())
		}
		if len(driver.ProbePayload()) == 0 {
			t.Errorf("ChainID %d (%s): ProbePayload is empty", chainID, driver.Name())
		}
	}
}

// TestSolanaDriver_ParseResponse tests fast byte-level validation of Solana getHealth RPC responses.
func TestSolanaDriver_ParseResponse(t *testing.T) {
	d := &SolanaDriver{}

	tests := []struct {
		name       string
		statusCode int
		body       string
		expectedOK bool
	}{
		{"Valid getHealth", http.StatusOK, `{"jsonrpc":"2.0","result":"ok","id":1}`, true},
		{"Node behind", http.StatusOK, `{"jsonrpc":"2.0","error":{"code":-32005,"message":"Node is behind"},"id":1}`, false},
		{"Rate limit 429", http.StatusTooManyRequests, `Too Many Requests`, false},
		{"Server Error 500", http.StatusInternalServerError, `Internal Error`, false},
		{"Empty body", http.StatusOK, ``, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := d.ParseResponse(tt.statusCode, []byte(tt.body))
			if res.Healthy != tt.expectedOK {
				t.Errorf("Solana ParseResponse(%d, %s) = %v, expected %v",
					tt.statusCode, tt.body, res.Healthy, tt.expectedOK)
			}
		})
	}
}

// TestETHDriver_ParseResponse tests Ethereum JSON-RPC blockNumber parsing and hex-to-uint64 conversion.
func TestETHDriver_ParseResponse(t *testing.T) {
	d := &ETHDriver{}

	tests := []struct {
		name           string
		statusCode     int
		body           string
		expectedOK     bool
		expectedHeight uint64
	}{
		{
			name:           "Valid blockNumber 0x10d4f (68943)",
			statusCode:     http.StatusOK,
			body:           `{"jsonrpc":"2.0","id":1,"result":"0x10d4f"}`,
			expectedOK:     true,
			expectedHeight: 68943,
		},
		{
			name:           "Valid blockNumber 0x1 (1)",
			statusCode:     http.StatusOK,
			body:           `{"jsonrpc":"2.0","id":1,"result":"0x1"}`,
			expectedOK:     true,
			expectedHeight: 1,
		},
		{
			name:           "RPC Error response",
			statusCode:     http.StatusOK,
			body:           `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid request"}}`,
			expectedOK:     false,
			expectedHeight: 0,
		},
		{
			name:           "HTTP 502 Bad Gateway",
			statusCode:     http.StatusBadGateway,
			body:           `Bad Gateway`,
			expectedOK:     false,
			expectedHeight: 0,
		},
		{
			name:           "Malformed JSON",
			statusCode:     http.StatusOK,
			body:           `{"jsonrpc":"2.0","result": broken`,
			expectedOK:     false,
			expectedHeight: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := d.ParseResponse(tt.statusCode, []byte(tt.body))
			if res.Healthy != tt.expectedOK {
				t.Errorf("EVM ParseResponse(%d) Healthy = %v, expected %v",
					tt.statusCode, res.Healthy, tt.expectedOK)
			}
			if res.Height != tt.expectedHeight {
				t.Errorf("EVM ParseResponse(%d) Height = %d, expected %d",
					tt.statusCode, res.Height, tt.expectedHeight)
			}
		})
	}
}

// TestTronDriver_ParseResponse tests Tron RPC endpoint validation.
func TestTronDriver_ParseResponse(t *testing.T) {
	d := &TronDriver{}

	tests := []struct {
		name       string
		statusCode int
		body       string
		expectedOK bool
	}{
		{"Valid blockNumber", http.StatusOK, `{"jsonrpc":"2.0","id":1,"result":"0x54321"}`, true},
		{"RPC Error", http.StatusOK, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000}}`, false},
		{"HTTP 503", http.StatusServiceUnavailable, `Unavailable`, false},
		{"Empty response", http.StatusOK, ``, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := d.ParseResponse(tt.statusCode, []byte(tt.body))
			if res.Healthy != tt.expectedOK {
				t.Errorf("Tron ParseResponse(%d) = %v, expected %v",
					tt.statusCode, res.Healthy, tt.expectedOK)
			}
		})
	}
}
