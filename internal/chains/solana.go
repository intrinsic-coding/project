package chains

import (
	"bytes"
	"net/http"
)

func init() {
	Register(&SolanaDriver{})
}

// SolanaDriver handles JSON-RPC probing for Solana validators and RPC clusters.
type SolanaDriver struct{}

// getHealth returns "ok" if the validator is within healthy slot distance from cluster head.
var solanaPayload = []byte(`{"jsonrpc":"2.0","id":1,"method":"getHealth"}`)

func (d *SolanaDriver) Name() string { return "solana" }

func (d *SolanaDriver) ProbePayload() []byte {
	return solanaPayload
}

// ParseResponse verifies HTTP 200 and checks for the `"ok"` result token without full JSON unmarshaling.
func (d *SolanaDriver) ParseResponse(statusCode int, body []byte) ProbeResult {
	if statusCode != http.StatusOK {
		return ProbeResult{Healthy: false}
	}
	// Zero-alloc fast path: Solana returns {"jsonrpc":"2.0","result":"ok","id":1} on healthy state.
	if bytes.Contains(body, []byte(`"ok"`)) {
		return ProbeResult{Healthy: true}
	}
	return ProbeResult{Healthy: false}
}
