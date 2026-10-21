package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"balancer/internal/ktls"
	"balancer/internal/routes"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
)

// Telemetry implements a multi-layered observability subsystem aligned with Google SRE Golden Signals:
// - Layer 1 (Traffic & Volume): HTTP request rates and aggregate byte throughput.
// - Layer 2 (Errors & Safety): L7 status codes, circuit breaker quarantine events, and rate limits.
// - Layer 3 (Transport Latency): High-resolution TCP connect and TLS handshake histograms.
// - Layer 4 (Health & Lag): Real-time node status gauges and blockchain slot/block lag behind chain head.
// - Layer 5 (Saturation & Resources): Concurrent active TCP connections and kernel pipe pool utilization.
type Telemetry struct {
	meter metric.Meter

	// Layer 1: Traffic & Volume
	requestsTotal metric.Int64Counter

	// Layer 2: Errors & Circuit Breaker Triggers
	errorsTotal      metric.Int64Counter
	quarantineEvents metric.Int64Counter

	// Layer 3: Transport Latency
	tcpConnectDuration   metric.Float64Histogram
	tlsHandshakeDuration metric.Float64Histogram

	// Layer 4: Health Monitoring & Recovery
	recoveryEvents metric.Int64Counter

	// Layer 5: Resource Saturation
	activeConnections metric.Int64UpDownCounter
}

var (
	globalTel *Telemetry
	telOnce   sync.Once
)

// Init bootstraps the OpenTelemetry Prometheus exporter and starts the HTTP scrapable endpoint server.
// Observable gauges evaluate lazily during Prometheus scrapes, querying the canonical flat arena
// without taking locks or interrupting the high-performance packet data plane.
func Init(metricsPort string) (func(context.Context) error, error) {
	var initErr error
	telOnce.Do(func() {
		exporter, err := prometheus.New()
		if err != nil {
			initErr = fmt.Errorf("failed to initialize prometheus exporter: %w", err)
			return
		}
		res := resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("balancer-proxy"),
		)
		provider := sdkmetric.NewMeterProvider(
			sdkmetric.WithResource(res),
			sdkmetric.WithReader(exporter),
		)
		otel.SetMeterProvider(provider)
		meter := provider.Meter("balancer-proxy")
		t := &Telemetry{meter: meter}

		t.requestsTotal, initErr = meter.Int64Counter("http_requests_total",
			metric.WithDescription("Total count of HTTP requests processed"),
		)
		if initErr != nil {
			return
		}

		t.errorsTotal, _ = meter.Int64Counter("http_errors_total",
			metric.WithDescription("Total count of HTTP error responses"),
		)
		t.quarantineEvents, _ = meter.Int64Counter("circuit_breaker_quarantine_events_total",
			metric.WithDescription("Total count of circuit breaker node quarantine triggers"),
		)
		t.recoveryEvents, _ = meter.Int64Counter("node_recovery_events_total",
			metric.WithDescription("Total count of node recoveries back to healthy state"),
		)
		t.activeConnections, _ = meter.Int64UpDownCounter("proxy_active_connections",
			metric.WithDescription("Current active client TCP connections"),
		)

		// Fine-grained latency buckets optimized for datacenter and edge RPC handshakes (0.1ms to 5000ms).
		optBounds := metric.WithExplicitBucketBoundaries(
			0.1, 0.5, 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000,
		)
		t.tcpConnectDuration, _ = meter.Float64Histogram("transport_tcp_connect_duration_ms",
			metric.WithDescription("Time to establish L4 TCP connection in ms"),
			metric.WithUnit("ms"),
			optBounds,
		)
		t.tlsHandshakeDuration, _ = meter.Float64Histogram("transport_tls_handshake_duration_ms",
			metric.WithDescription("Time to complete ktls handshake in ms"),
			metric.WithUnit("ms"),
			optBounds,
		)

		// Observable counters aggregate Per-P metrics arrays on Prometheus pull to avoid cache-line bouncing.
		_, _ = meter.Int64ObservableCounter("http_request_bytes_total",
			metric.WithDescription("Total bytes received in HTTP requests"),
			metric.WithUnit("By"),
			recordBytes(true),
		)
		_, _ = meter.Int64ObservableCounter("http_response_bytes_total",
			metric.WithDescription("Total bytes sent in HTTP responses"),
			metric.WithUnit("By"),
			recordBytes(false),
		)

		// Observable gauge exporting health status per endpoint: 0=Healthy, 1=Quarantined.
		_, _ = meter.Int64ObservableGauge("node_health_status",
			metric.WithDescription("Current node health: 0=Healthy, 1=Quarantined"),
			metric.WithInt64Callback(func(ctx context.Context, obs metric.Int64Observer) error {
				total := int(routes.TotalLEs.Load())
				for i := range total {
					le := &routes.LogicalEntities[i]
					if le.SniPtr == nil {
						continue
					}
					chain, host, ip := getChainHostIP(le)
					status := int64(0)
					if le.Status.Load() != routes.StateHealthy ||
						routes.AllIps[le.IpIdx].Status.Load() != routes.StateHealthy {
						status = 1
					}
					obs.Observe(status, metric.WithAttributes(
						attribute.String("chain", chain),
						attribute.String("host", host),
						attribute.String("ip", ip),
					))
				}
				return nil
			}),
		)

		// Observable gauge exporting real-time block/slot lag behind the active chain head.
		_, _ = meter.Int64ObservableGauge("node_block_lag_total",
			metric.WithDescription("Node lag in blocks/slots behind chain head"),
			metric.WithInt64Callback(func(ctx context.Context, obs metric.Int64Observer) error {
				total := int(routes.TotalLEs.Load())
				for i := range total {
					le := &routes.LogicalEntities[i]
					if le.SniPtr == nil {
						continue
					}
					chain, host, ip := getChainHostIP(le)
					obs.Observe(int64(le.Lag), metric.WithAttributes(
						attribute.String("chain", chain),
						attribute.String("host", host),
						attribute.String("ip", ip),
					))
				}
				return nil
			}),
		)

		// Kernel pipe pool capacity monitoring for splice(2) zero-copy descriptors.
		_, _ = meter.Int64ObservableGauge("proxy_pipe_pool_available",
			metric.WithDescription("Available pipes in kernel pipe pool"),
			metric.WithInt64Callback(func(ctx context.Context, obs metric.Int64Observer) error {
				obs.Observe(int64(ktls.GetAvailablePipes()))
				return nil
			}),
		)
		_, _ = meter.Int64ObservableGauge("proxy_pipe_pool_capacity",
			metric.WithDescription("Total capacity of kernel pipe pool"),
			metric.WithInt64Callback(func(ctx context.Context, obs metric.Int64Observer) error {
				obs.Observe(ktls.SizePipesPool)
				return nil
			}),
		)

		globalTel = t
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		srv := &http.Server{
			Addr:         metricsPort,
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		}
		go func() {
			slog.Info("Starting Prometheus Metrics Server", "addr", metricsPort)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("Metrics server failed", "error", err)
			}
		}()
	})
	if initErr != nil {
		return nil, initErr
	}
	return func(ctx context.Context) error {
		return nil
	}, nil
}

// Record200OK increments the aggregate request counter for successful HTTP 200 responses.
func Record200OK(ctx context.Context, le *ktls.LogicalEntity, count int64) {
	if globalTel != nil && count > 0 {
		chain, host, ip := getChainHostIP(le)
		globalTel.requestsTotal.Add(ctx, count, metric.WithAttributes(
			attribute.String("chain", chain),
			attribute.String("host", host),
			attribute.String("ip", ip),
			attribute.String("status", "200"),
		))
	}
}

// RecordError increments the failure counter partitioned by HTTP response status code.
func RecordError(ctx context.Context, le *ktls.LogicalEntity, status uint16) {
	if globalTel != nil {
		chain, host, ip := getChainHostIP(le)
		globalTel.errorsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("chain", chain),
			attribute.String("host", host),
			attribute.String("ip", ip),
			attribute.String("status", strconv.Itoa(int(status))),
		))
	}
}

// RecordQuarantine increments the circuit breaker activation counter with the triggering failure reason.
func RecordQuarantine(ctx context.Context, le *ktls.LogicalEntity, reason string) {
	if globalTel != nil {
		chain, host, ip := getChainHostIP(le)
		globalTel.quarantineEvents.Add(ctx, 1, metric.WithAttributes(
			attribute.String("chain", chain),
			attribute.String("host", host),
			attribute.String("ip", ip),
			attribute.String("reason", reason),
		))
	}
}

// RecordRecovery records an endpoint rehabilitation event back to StateHealthy.
func RecordRecovery(ctx context.Context, chain, host, ip string) {
	if globalTel != nil {
		globalTel.recoveryEvents.Add(ctx, 1, metric.WithAttributes(
			attribute.String("chain", chain),
			attribute.String("host", host),
			attribute.String("ip", ip),
		))
	}
}

// RecordTCPConnectDuration records L4 TCP handshake latency in milliseconds.
// Reuses pre-computed MetricAttrs from the immutable RoutingState snapshot to eliminate allocations.
func RecordTCPConnectDuration(ctx context.Context, state *routes.RoutingState, leID uint64, ms float64) {
	if globalTel != nil && state != nil && int(leID) < len(state.MetricAttrs) {
		globalTel.tcpConnectDuration.Record(ctx, ms, state.MetricAttrs[leID])
	}
}

// RecordTLSHandshakeDuration records kTLS client handshake latency in milliseconds.
func RecordTLSHandshakeDuration(ctx context.Context, state *routes.RoutingState, leID uint64, ms float64) {
	if globalTel != nil && state != nil && int(leID) < len(state.MetricAttrs) {
		globalTel.tlsHandshakeDuration.Record(ctx, ms, state.MetricAttrs[leID])
	}
}

// IncrActiveConn increments the active client connection gauge.
func IncrActiveConn(ctx context.Context) {
	if globalTel != nil {
		globalTel.activeConnections.Add(ctx, 1)
	}
}

// DecrActiveConn decrements the active client connection gauge.
func DecrActiveConn(ctx context.Context) {
	if globalTel != nil {
		globalTel.activeConnections.Add(ctx, -1)
	}
}

// On200OK is invoked asynchronously by the eBPF aggregation worker to record batch-parsed 200 OK responses.
func On200OK(ctx context.Context, leID uint32, delta uint64, _ uint64) {
	if leID < routes.TotalLEs.Load() {
		le := &routes.LogicalEntities[leID]
		if le.SniPtr != nil {
			Record200OK(ctx, le, int64(delta))
		}
	}
}

// OnError is invoked asynchronously by the eBPF ringbuf event reader upon intercepting non-200 HTTP/2 responses.
func OnError(ctx context.Context, leID uint64, status uint16) {
	routes.HandleL7Error(leID, status)
	if leID < uint64(routes.TotalLEs.Load()) {
		le := &routes.LogicalEntities[leID]
		if le.SniPtr != nil {
			RecordError(ctx, le, status)
		}
	}
}

// recordBytes aggregates atomic byte counters across Per-CPU arrays (PerPMetricsStore)
// during Prometheus scrape callbacks, avoiding cache contention during high-throughput splice transfers.
func recordBytes(isRequest bool) metric.Int64ObservableOption {
	return metric.WithInt64Callback(func(ctx context.Context, obs metric.Int64Observer) error {
		total := int(routes.TotalLEs.Load())
		for i := range total {
			le := &routes.LogicalEntities[i]
			if le.SniPtr == nil {
				continue
			}
			var totalBytes uint64
			for p := range routes.PerPMetricsStore {
				if isRequest {
					totalBytes += routes.PerPMetricsStore[p][le.Id].RequestBytes.Load()
				} else {
					totalBytes += routes.PerPMetricsStore[p][le.Id].ResponseBytes.Load()
				}
			}
			chain, host, ip := getChainHostIP(le)
			obs.Observe(int64(totalBytes), metric.WithAttributes(
				attribute.String("chain", chain),
				attribute.String("host", host),
				attribute.String("ip", ip),
			))
		}
		return nil
	})
}

// getChainHostIP extracts chain name, target SNI string, and resolved IP from the canonical flat arena.
func getChainHostIP(le *ktls.LogicalEntity) (chain, host, ip string) {
	return routes.GetChainNameByID(le.ChainID),
		unsafe.String((*byte)(le.SniPtr), le.SniLen),
		routes.AllIps[le.IpIdx].AddrPortStr
}
