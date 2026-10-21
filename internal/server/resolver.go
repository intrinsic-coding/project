package server

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unsafe"

	"balancer/internal/ktls"
	"balancer/internal/routes"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// StartDNSResolver periodically re-resolves node hostnames across all chains and atomically
// updates the active routing state if IP topology changes are detected.
func StartDNSResolver(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		lastResolved := make(map[string][]netip.Addr)
		seedInitialResolved(lastResolved)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				resolveAndRebuild(ctx, lastResolved)
			}
		}
	}()
}

// seedInitialResolved populates the local resolver cache with IPs mapped during process startup.
func seedInitialResolved(lastResolved map[string][]netip.Addr) {
	totalIP := int(routes.TotalIps.Load())
	for c := range routes.StaticChainManifests {
		for _, node := range routes.StaticChainManifests[c] {
			if _, exists := lastResolved[node.Host]; exists {
				continue
			}
			var ips []netip.Addr
			totalLE := int(routes.TotalLEs.Load())
			for i := range totalLE {
				le := &routes.LogicalEntities[i]
				host := unsafe.String((*byte)(le.SniPtr), le.SniLen)
				if host == node.Host && int(le.IpIdx) < totalIP {
					addr := routes.AllIps[le.IpIdx].AddrPort.Addr()
					if !slices.Contains(ips, addr) {
						ips = append(ips, addr)
					}
				}
			}
			slices.SortFunc(ips, func(a, b netip.Addr) int { return a.Compare(b) })
			lastResolved[node.Host] = ips
		}
	}
}

// resolveAndRebuild queries DNS for all configured hostnames.
// Implements Stale-on-Error resilience: if a lookup fails, previously known IPs are retained.
// If changes are found, it generates a new RCU RoutingState and publishes it via an atomic pointer store.
func resolveAndRebuild(ctx context.Context, lastResolved map[string][]netip.Addr) {
	currentResolved := make(map[string][]netip.Addr)
	hasChanges := false

	// Resolve each unique host exactly once per tick to minimize DNS query load.
	for c := range routes.StaticChainManifests {
		for _, node := range routes.StaticChainManifests[c] {
			host := node.Host
			if _, processed := currentResolved[host]; processed {
				continue
			}
			addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil || len(addrs) == 0 {
				slog.Warn("DNS resolve failed, keeping stale IPs", "host", host, "err", err)
				currentResolved[host] = lastResolved[host]
				continue
			}
			cleanAddrs := make([]netip.Addr, len(addrs))
			for i, a := range addrs {
				cleanAddrs[i] = a.Unmap()
			}
			slices.SortFunc(cleanAddrs, func(a, b netip.Addr) int { return a.Compare(b) })
			currentResolved[host] = cleanAddrs
			if !slices.Equal(cleanAddrs, lastResolved[host]) {
				hasChanges = true
			}
		}
	}

	// Zero-churn optimization: early exit if resolved sets are identical to the active topology.
	if !hasChanges {
		return
	}

	slog.Info("DNS change detected, rebuilding routing topology...")
	currState := routes.GlobalRoutingState.Load()
	nextState := &routes.RoutingState{
		MetricAttrs: make([]metric.MeasurementOption, routes.MaxLEs),
	}
	if currState != nil {
		copy(nextState.MetricAttrs, currState.MetricAttrs)
	}

	// Reconstruct the interleaved snake round-robin indices for each chain.
	for chainID, hosts := range routes.StaticChainManifests {
		var hostTrioGroups [][]int
		maxIpsPerHost := 0
		for _, node := range hosts {
			host := node.Host
			path := node.Path
			sniPtr := node.SniPtr
			sniLen := node.SniLen
			addrs := currentResolved[host]
			var currentHostTrios []int
			for _, addr := range addrs {
				addrPort := netip.AddrPortFrom(addr, 443)
				ipIdx := findOrAddIP(addrPort)
				if ipIdx == -1 {
					continue
				}
				leIdx := findOrAddLE(chainID, host, path, sniPtr, sniLen, int32(ipIdx), nextState)
				if leIdx == -1 {
					continue
				}
				currentHostTrios = append(currentHostTrios, leIdx)
			}
			if len(currentHostTrios) > 0 {
				hostTrioGroups = append(hostTrioGroups, currentHostTrios)
				if len(currentHostTrios) > maxIpsPerHost {
					maxIpsPerHost = len(currentHostTrios)
				}
			}
		}

		// Interleave hosts vertically to prevent consecutive requests hitting the same backend provider.
		var chainTrioIndices []int
		if len(hostTrioGroups) > 0 {
			for step := 0; step < maxIpsPerHost; step++ {
				for _, group := range hostTrioGroups {
					item := group[step%len(group)]
					chainTrioIndices = append(chainTrioIndices, item)
				}
			}
		}
		nextState.Chains[chainID] = routes.ChainGeneration{
			ActiveIndices: chainTrioIndices,
			Count:         uint64(len(chainTrioIndices)),
		}
	}

	// Atomic publication: active in-flight requests proceed unaffected; new requests pick up the nextState.
	routes.GlobalRoutingState.Store(nextState)
	LogTopology(nextState, "[Updated Topology]")
	maps.Copy(lastResolved, currentResolved)
	slog.Info("DNS routing topology successfully updated")
}

// findOrAddIP checks the canonical flat IP arena for an existing AddrPort, appending if absent.
func findOrAddIP(addrPort netip.AddrPort) int {
	total := int(routes.TotalIps.Load())
	for i := range total {
		if routes.AllIps[i].AddrPort == addrPort {
			return i
		}
	}
	if total >= routes.MaxIPs {
		slog.Error("Cannot add new IP: MaxIPs capacity reached", "limit", routes.MaxIPs)
		return -1
	}
	idx := int(routes.TotalIps.Add(1) - 1)
	routes.AllIps[idx] = routes.IpEntry{
		AddrPort:    addrPort,
		AddrPortStr: addrPort.String(),
	}
	return idx
}

// findOrAddLE checks the canonical flat LogicalEntity arena for matching (ChainID, IpIdx, Path),
// appending if absent and pre-allocating its metric attribute options.
func findOrAddLE(
	chainID int, host, path string, sniPtr unsafe.Pointer, sniLen int32, ipIdx int32, state *routes.RoutingState,
) int {
	total := int(routes.TotalLEs.Load())
	for i := range total {
		le := &routes.LogicalEntities[i]
		if le.ChainID == int32(chainID) && le.IpIdx == ipIdx && le.Path == path {
			return i
		}
	}
	if total >= routes.MaxLEs {
		slog.Error("Cannot add new LE: MaxLEs capacity reached", "limit", routes.MaxLEs)
		return -1
	}
	idx := int(routes.TotalLEs.Add(1) - 1)
	routes.LogicalEntities[idx] = ktls.LogicalEntity{
		Path:    strings.Clone(path),
		Id:      uint64(idx),
		SniPtr:  sniPtr,
		SniLen:  sniLen,
		ChainID: int32(chainID),
		IpIdx:   ipIdx,
	}
	state.MetricAttrs[idx] = metric.WithAttributes(
		attribute.String("chain", routes.GetChainNameByID(int32(chainID))),
		attribute.String("host", host),
		attribute.String("ip", routes.AllIps[ipIdx].AddrPortStr),
	)
	return idx
}

// LogTopology renders the active interleaving sequence per chain for operator visibility and verification.
func LogTopology(state *routes.RoutingState, prefix string) {
	if state == nil {
		slog.Info(prefix, "state", "nil")
		return
	}
	for chainID := range state.Chains {
		gen := &state.Chains[chainID]
		var details []string
		for _, leIdx := range gen.ActiveIndices {
			le := &routes.LogicalEntities[leIdx]
			host := unsafe.String((*byte)(le.SniPtr), le.SniLen)
			ip := routes.AllIps[le.IpIdx].AddrPortStr
			details = append(details, fmt.Sprintf(`LE#%d[%s -> %s (path:%s)]`, le.Id, host, ip, le.Path))
		}
		if chainID == 0 {
			println()
		}
		log.Println(prefix, "chain", routes.GetChainNameByID(int32(chainID)), "\n", strings.Join(details, "\n"))
		if chainID < len(state.Chains) {
			println()
		}
	}
}
