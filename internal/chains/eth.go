package chains

import (
	"encoding/json"
	"net/http"
	"strconv"
)

func init() {
	Register(&ETHDriver{})
}

// ETHDriver handles JSON-RPC probing for Ethereum and EVM-compatible networks.
type ETHDriver struct{}

// Static payload requesting the latest block number via eth_blockNumber.
var ethPayload = []byte(`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`)

func (d *ETHDriver) Name() string { return "eth" }

func (d *ETHDriver) ProbePayload() []byte {
	return ethPayload
}

// ParseResponse validates that the response returned HTTP 200 and a valid hex block height (0x...).
func (d *ETHDriver) ParseResponse(statusCode int, body []byte) ProbeResult {
	if statusCode != http.StatusOK || len(body) == 0 {
		return ProbeResult{Healthy: false}
	}

	var resp struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.Result) < 3 {
		return ProbeResult{Healthy: false}
	}

	// Parse hex block number (stripping leading "0x") into uint64.
	height, _ := strconv.ParseUint(resp.Result[2:], 16, 64)
	return ProbeResult{
		Healthy: height > 0,
		Height:  height,
	}
}
