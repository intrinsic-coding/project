package server

import (
	"bytes"
	"strings"
	"testing"
	"unsafe"

	"balancer/internal/ktls"
	"balancer/internal/routes"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// TestUpdateHeaders verifies that incoming HTTP/2 pseudo-headers are correctly mutated:
// - Rewrites :authority and host headers to the upstream node SNI.
// - Strips the chain prefix and attaches the configured backend path (handling trailing slashes and subpaths).
// - Preserves regular payload headers such as content-type without corruption.
func TestUpdateHeaders(t *testing.T) {
	hostAnkr := "rpc.ankr.com\x00"
	sniAnkr := unsafe.Pointer(unsafe.StringData(hostAnkr))
	lenAnkr := int32(len("rpc.ankr.com"))

	hostSolana := "api.mainnet-beta.solana.com\x00"
	sniSolana := unsafe.Pointer(unsafe.StringData(hostSolana))
	lenSolana := int32(len("api.mainnet-beta.solana.com"))

	leEth := &ktls.LogicalEntity{
		ChainID: routes.Chain0, // eth (prefix len = len("/eth"))
		SniPtr:  sniAnkr,
		SniLen:  lenAnkr,
		Path:    "/eth/secret-key",
	}

	leSolana := &ktls.LogicalEntity{
		ChainID: routes.Chain1, // solana (prefix len = len("/solana"))
		SniPtr:  sniSolana,
		SniLen:  lenSolana,
		Path:    "/",
	}

	tests := []struct {
		name              string
		le                *ktls.LogicalEntity
		inputPath         string
		inputAuthority    string
		expectedPath      string
		expectedAuthority string
	}{
		{
			name:              "ETH root path rewrite",
			le:                leEth,
			inputPath:         "/eth",
			inputAuthority:    "my-balancer.local",
			expectedPath:      "/eth/secret-key",
			expectedAuthority: "rpc.ankr.com",
		},
		{
			name:              "ETH root path with trailing slash",
			le:                leEth,
			inputPath:         "/eth/",
			inputAuthority:    "my-balancer.local",
			expectedPath:      "/eth/secret-key",
			expectedAuthority: "rpc.ankr.com",
		},
		{
			name:              "ETH subpath appending",
			le:                leEth,
			inputPath:         "/eth/v1/jsonrpc",
			inputAuthority:    "my-balancer.local",
			expectedPath:      "/eth/secret-key/v1/jsonrpc",
			expectedAuthority: "rpc.ankr.com",
		},
		{
			name:              "Solana root path rewrite (le.Path is /)",
			le:                leSolana,
			inputPath:         "/solana",
			inputAuthority:    "my-balancer.local",
			expectedPath:      "/",
			expectedAuthority: "api.mainnet-beta.solana.com",
		},
		{
			name:              "Solana subpath rewrite (le.Path is /)",
			le:                leSolana,
			inputPath:         "/solana/custom/path",
			inputAuthority:    "my-balancer.local",
			expectedPath:      "/custom/path",
			expectedAuthority: "api.mainnet-beta.solana.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var outBuf bytes.Buffer
			wFramer := http2.NewFramer(&outBuf, strings.NewReader(""))

			var hPackBuf bytes.Buffer
			encoder := hpack.NewEncoder(&hPackBuf)
			encoder.SetMaxDynamicTableSize(0)

			inputFrame := &http2.MetaHeadersFrame{
				HeadersFrame: &http2.HeadersFrame{
					FrameHeader: http2.FrameHeader{
						StreamID: 1,
						Flags:    http2.FlagHeadersEndHeaders,
					},
				},
				Fields: []hpack.HeaderField{
					{Name: ":method", Value: "POST"},
					{Name: ":authority", Value: tt.inputAuthority},
					{Name: ":path", Value: tt.inputPath},
					{Name: "content-type", Value: "application/json"},
				},
			}

			err := UpdateHeaders(wFramer, inputFrame, tt.le, encoder, &hPackBuf)
			if err != nil {
				t.Fatalf("UpdateHeaders failed: %v", err)
			}

			// Validate generated block by decoding it with a standard HPACK decoder.
			rFramer := http2.NewFramer(ioDiscard{}, &outBuf)
			frame, err := rFramer.ReadFrame()
			if err != nil {
				t.Fatalf("Failed to read back generated frame: %v", err)
			}

			headersFrame, ok := frame.(*http2.HeadersFrame)
			if !ok {
				t.Fatalf("Expected *http2.HeadersFrame, got %T", frame)
			}

			decodedFields := make(map[string]string)
			decoder := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
				decodedFields[f.Name] = f.Value
			})
			if _, err := decoder.Write(headersFrame.HeaderBlockFragment()); err != nil {
				t.Fatalf("Failed to decode HPACK fragment: %v", err)
			}

			if gotAuth := decodedFields[":authority"]; gotAuth != tt.expectedAuthority {
				t.Errorf("Expected :authority = %q, got %q", tt.expectedAuthority, gotAuth)
			}
			if gotPath := decodedFields[":path"]; gotPath != tt.expectedPath {
				t.Errorf("Expected :path = %q, got %q", tt.expectedPath, gotPath)
			}
			if gotCT := decodedFields["content-type"]; gotCT != "application/json" {
				t.Errorf("Expected content-type = application/json, got %q", gotCT)
			}
		})
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
