package routes

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"unsafe"

	"balancer/internal/ktls"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// InitRoutesFromConfig initializes routing topology from static chain manifests at application startup:
// 1. Configures Per-P core structures with staggered round-robin offsets to prevent cache thrashing.
// 2. Pins null-terminated SNI C-strings once using runtime.Pinner, preventing memory leaks during runtime.
// 3. Resolves initial DNS mappings and fills the flat canonical arenas (AllIps and LogicalEntities).
// 4. Synthesizes vertical "Snake" interleaving to alternate between distinct providers per request.
// 5. Pre-allocates OpenTelemetry attribute sets to ensure O(1) zero-allocation telemetry on the hot path.
func InitRoutesFromConfig(_ context.Context) (*RoutingState, error) {
	numP := runtime.GOMAXPROCS(0)
	PerPStores = make([]PerPStore, numP)
	for p := range numP {
		for c := range MaxChains {
			// Seed each CPU core with a different starting offset to distribute initial load.
			PerPStores[p].LocalRrCounters[c] = uint64(p)
		}
	}
	LePinners = nil

	// Temporary deduplication cache ensuring each unique hostname string is pinned exactly once.
	type sniEntry struct {
		ptr unsafe.Pointer
		len int32
	}
	sniCache := make(map[string]sniEntry)

	initState := &RoutingState{
		MetricAttrs: make([]metric.MeasurementOption, MaxLEs),
	}
	trioIdx := 0
	ipCount := 0

	// hostTrioGroups partitions LogicalEntity IDs per host:
	// [ [host0_ip0, host0_ip1, ...], [host1_ip0, host1_ip1, ...], ... ]
	for chainID := range StaticChainManifests {
		var hostTrioGroups [][]int
		maxIpsPerHost := 0

		for idx := range StaticChainManifests[chainID] {
			node := &StaticChainManifests[chainID][idx]
			host := node.Host
			path := node.Path
			addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
			if err != nil || len(addrs) == 0 {
				fmt.Printf("[Init] Warning: failed to resolve host %s: %v\n", host, err)
				continue
			}

			// Allocate and pin null-terminated C-string once per host.
			cached, exists := sniCache[host]
			if !exists {
				sniBuf := make([]byte, len(host)+1)
				copy(sniBuf, host)
				sniBuf[len(host)] = 0
				var pinner runtime.Pinner
				pinner.Pin(unsafe.SliceData(sniBuf))
				LePinners = append(LePinners, pinner)
				cached = sniEntry{
					ptr: unsafe.Pointer(unsafe.SliceData(sniBuf)),
					len: int32(len(host)),
				}
				sniCache[host] = cached
			}

			sniPtr := cached.ptr
			sniLen := cached.len
			node.SniPtr = sniPtr
			node.SniLen = sniLen

			var currentHostTrios []int
			for _, addr := range addrs {
				addrPort := netip.AddrPortFrom(addr.Unmap(), 443)

				// Check canonical flat arena for existing IP entry.
				ipIdx := -1
				for idx := 0; idx < ipCount; idx++ {
					if AllIps[idx].AddrPort == addrPort {
						ipIdx = idx
						break
					}
				}
				if ipIdx == -1 {
					if ipCount >= MaxIPs {
						slog.Error("MaxIPs capacity reached", "limit", MaxIPs)
						break
					}
					AllIps[ipCount] = IpEntry{
						AddrPort:    addrPort,
						AddrPortStr: addrPort.String(),
					}
					ipIdx = ipCount
					ipCount++
				}

				if trioIdx >= MaxLEs {
					slog.Error("MaxLEs capacity reached", "limit", MaxLEs)
					break
				}

				LogicalEntities[trioIdx] = ktls.LogicalEntity{
					Path:    strings.Clone(path),
					Id:      uint64(trioIdx),
					SniPtr:  sniPtr,
					SniLen:  sniLen,
					ChainID: int32(chainID),
					IpIdx:   int32(ipIdx),
				}

				// Pre-render immutable measurement options for fast hot-path metric recording.
				initState.MetricAttrs[trioIdx] = metric.WithAttributes(
					attribute.String("chain", GetChainNameByID(int32(chainID))),
					attribute.String("host", host),
					attribute.String("ip", AllIps[ipIdx].AddrPortStr),
				)
				currentHostTrios = append(currentHostTrios, trioIdx)
				trioIdx++
			}

			if len(currentHostTrios) > 0 {
				hostTrioGroups = append(hostTrioGroups, currentHostTrios)
				if len(currentHostTrios) > maxIpsPerHost {
					maxIpsPerHost = len(currentHostTrios)
				}
			}
		}

		// "SNAKE" INTERLEAVING ALGORITHM
		// Transposes the host-by-IP matrix vertically so sequential round-robin steps cycle
		// through alternating host providers (e.g. Ankr -> QuickNode -> dRPC) rather than
		// exhausting multiple IPs of the same provider consecutively.
		var chainTrioIndices []int
		if len(hostTrioGroups) > 0 {
			for step := 0; step < maxIpsPerHost; step++ {
				for _, group := range hostTrioGroups {
					item := group[step%len(group)]
					chainTrioIndices = append(chainTrioIndices, item)
				}
			}
		}

		initState.Chains[chainID] = ChainGeneration{
			ActiveIndices: chainTrioIndices,
			Count:         uint64(len(chainTrioIndices)),
		}
	}

	TotalIps.Store(uint32(ipCount))
	TotalLEs.Store(uint32(trioIdx))

	// Publish the initial immutable snapshot.
	GlobalRoutingState.Store(initState)

	// Pre-allocate fixed-size Per-CPU metrics array (MaxLEs) to eliminate bounds checks.
	PerPMetricsStore = make([][]LeMetrics, numP)
	for p := range numP {
		PerPMetricsStore[p] = make([]LeMetrics, MaxLEs)
	}

	slog.Info(fmt.Sprintf("[Init] Done. Loaded %d unique IPs and %d LogicalEntities across %d CPUs.\n",
		ipCount, trioIdx, numP))

	return initState, nil
}

// ShutdownRoutes releases all runtime.Pinner allocations on application exit.
func ShutdownRoutes() {
	for _, p := range LePinners {
		p.Unpin()
	}
	LePinners = nil
}
