package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"
	"unsafe"

	"balancer/internal/chains"
	"balancer/internal/routes"
	"balancer/internal/telemetry"
)

// StartHealthChecker launches background probes to detect node recoveries:
// - L4: Fast TCP+TLS probing to rehabilitate network endpoints after timeouts or connection drops.
// - L7: Lightweight blockchain-specific JSON-RPC probes via chain drivers to lift application quarantines.
func StartHealthChecker(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				slog.Info("Starting health checker")
				checkUnhealthyIPs(ctx)
				checkUnhealthyLEs(ctx)
				slog.Info("Finish health checker")
			}
		}
	}()
}

// checkUnhealthyIPs inspects L4-quarantined endpoints. If the 10-second cooldown has passed,
// it executes a raw TCP + TLS handshake probe to verify port reachability.
func checkUnhealthyIPs(ctx context.Context) {
	totalIPs := int(routes.TotalIps.Load())
	nowMs := uint64(time.Now().UnixMilli())

	for i := range totalIPs {
		ip := &routes.AllIps[i]
		if ip.Status.Load() != routes.StateUnhealthy {
			continue
		}
		slog.Info("Found unhealthy IP address", "ip", ip.AddrPortStr)

		// Respect the 10-second L4 quarantine cooldown.
		if nowMs < ip.DisabledUntilMs.Load()+10000 {
			continue
		}

		dialer := &net.Dialer{Timeout: 2 * time.Second}
		tlsConn, err := tls.DialWithDialer(dialer, "tcp", ip.AddrPortStr, &tls.Config{
			InsecureSkipVerify: true,
		})

		if err == nil {
			_ = tlsConn.Close()
			ip.Status.Store(routes.StateHealthy)
			slog.Info("[HealthChecker] IP recovered (L4/TLS OK)", "ip", ip.AddrPortStr)
			telemetry.RecordRecovery(ctx, "", "", ip.AddrPortStr)
		} else {
			// Extend quarantine upon failure to prevent continuous socket thrashing.
			ip.DisabledUntilMs.Store(nowMs)
		}
	}
}

// checkUnhealthyLEs tests L7-quarantined logical entities whose ban period (DisabledUntilSec) has expired.
// It retrieves probe payloads from the respective chain driver and restores healthy status on valid responses.
func checkUnhealthyLEs(ctx context.Context) {
	totalLEs := int(routes.TotalLEs.Load())
	nowSec := uint32(time.Now().Unix())

	for i := range totalLEs {
		le := &routes.LogicalEntities[i]
		if le.Status.Load() != routes.StateUnhealthy {
			continue
		}

		if nowSec < le.DisabledUntilSec.Load() {
			continue
		}

		// Skip L7 probing if the underlying L4 IP endpoint is still unreachable.
		if routes.AllIps[le.IpIdx].Status.Load() != routes.StateHealthy {
			continue
		}

		driver := chains.Drivers[le.ChainID]
		if driver == nil {
			continue
		}

		host := unsafe.String((*byte)(le.SniPtr), le.SniLen)
		targetIP := routes.AllIps[le.IpIdx].AddrPortStr
		chainName := routes.GetChainNameByID(le.ChainID)

		payload := driver.ProbePayload()
		statusCode, respBody, err := sendL7Probe(ctx, targetIP, host, le.Path, payload)
		if err != nil {
			le.DisabledUntilSec.Store(nowSec + 30)
			continue
		}

		result := driver.ParseResponse(statusCode, respBody)
		if result.Healthy {
			le.Status.Store(routes.StateHealthy)
			le.ErrorCount.Store(0)
			slog.Info("[HealthChecker] LE recovered (L7 200 OK)", "chain", chainName, "host", host, "ip", targetIP)
			telemetry.RecordRecovery(ctx, chainName, host, targetIP)
		} else {
			le.DisabledUntilSec.Store(nowSec + 30)
		}
	}
}

// sendL7Probe issues a non-keepalive HTTP POST request pinned directly to targetIP,
// preserving the SNI and Host headers expected by upstream edge reverse proxies.
func sendL7Probe(ctx context.Context, targetIP, host, path string, payload []byte) (int, []byte, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", targetIP)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   4 * time.Second,
	}

	url := fmt.Sprintf("https://%s%s", host, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	// Bound response reading to 4 KB to prevent buffer exhaustion from unexpectedly large error payloads.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return resp.StatusCode, nil, err
	}

	return resp.StatusCode, body, nil
}
