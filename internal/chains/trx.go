package chains

import (
	"encoding/json"
	"net/http"
)

func init() {
	Register(&TronDriver{})
}

// TronDriver handles JSON-RPC health verification for TRON network gateways.
type TronDriver struct{}

var trxPayload = []byte(`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`)

func (d *TronDriver) Name() string { return "trx" }

func (d *TronDriver) ProbePayload() []byte {
	return trxPayload
}

// ParseResponse validates that the Tron JSON-RPC endpoint returned a non-error payload.
func (d *TronDriver) ParseResponse(statusCode int, body []byte) ProbeResult {
	if statusCode != http.StatusOK || len(body) == 0 {
		return ProbeResult{Healthy: false}
	}
	var resp struct {
		Result any `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Result == nil {
		return ProbeResult{Healthy: false}
	}
	return ProbeResult{Healthy: true}
}
