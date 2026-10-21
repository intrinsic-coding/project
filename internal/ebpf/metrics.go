package ebpf

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// RegisterSession correlates a downstream socket cookie to a LogicalEntity ID in the BPF session_map.
// Invoked immediately before initiating splice(2) to ensure kernel-space tracepoints can attribute responses.
func (m *Manager) RegisterSession(cookie uint64, leID uint64) error {
	ctx := SessionCtx{LeID: leID}
	return m.sessionMap.Update(cookie, ctx, ebpf.UpdateAny)
}

// start launches background ingestion workers for eBPF ring buffer events and per-CPU counter aggregation.
func (m *Manager) start(ctx context.Context) {
	m.wg.Add(2)
	go m.readErrorEventsLoop(ctx)
	go m.aggregateMetricsLoop(ctx)
}

// readErrorEventsLoop drains the error_events ring buffer and dispatches non-200 HTTP/2 responses
// to the registered onError handler to trigger circuit breaker quarantine.
func (m *Manager) readErrorEventsLoop(ctx context.Context) {
	defer m.wg.Done()
	for {
		record, err := m.ringReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			slog.Error("eBPF ringbuf read error", "err", err)
			continue
		}
		if len(record.RawSample) < int(unsafe.Sizeof(ErrorEvent{})) {
			continue
		}
		event := (*ErrorEvent)(unsafe.Pointer(&record.RawSample[0]))
		if m.onError != nil {
			m.onError(ctx, event.LeID, event.Status)
		}
	}
}

// aggregateMetricsLoop scrapes the per-CPU 2D metrics_array every 2 seconds, calculates RPS deltas,
// and publishes 200 OK throughput statistics without locking the kernel execution path.
func (m *Manager) aggregateMetricsLoop(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	numCPU := runtime.NumCPU()

	for {
		select {
		case <-ticker.C:
			for leID := range uint32(LesPerCPU) {
				var total200 uint64
				for cpu := range numCPU {
					idx := uint32((cpu << 9) | int(leID&0x1FF))
					var count uint64
					if err := m.metricsMap.Lookup(idx, &count); err == nil {
						total200 += count
					}
				}
				delta := total200 - m.prevCounts[leID]
				m.prevCounts[leID] = total200
				if delta > 0 {
					slog.Info("[eBPF Telemetry]",
						"le_id", leID,
						"200_ok_rps", delta/2,
						"total", total200,
					)
					if m.on200OK != nil {
						m.on200OK(ctx, leID, delta, total200)
					}
				}
			}
		case <-ctx.Done():
			return
		}
	}
}
