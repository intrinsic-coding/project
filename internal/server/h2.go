package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"balancer/internal/ebpf"
	"balancer/internal/ktls"
	"balancer/internal/routes"
	"balancer/internal/telemetry"
	"balancer/internal/utils"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/sys/unix"
)

// h2ClientPreface is the 24-byte magic string required at the start of every HTTP/2 connection (RFC 7540).
var h2ClientPreface = []byte(http2.ClientPreface)

// prefixConn wraps a net.Conn with an unread buffer. It allows inspecting the
// connection preface without discarding read bytes before handing over to the HTTP/2 framer.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// writeFrame forwards incoming downstream HTTP/2 control and data frames to the upstream connection.
// For SettingsFrame, it explicitly forces SETTINGS_HEADER_TABLE_SIZE to 0. Disabling the dynamic
// HPACK table eliminates compression state between endpoints, enabling stateless zero-copy
// packet inspection by the kernel eBPF parser.
func writeFrame(wFramer *http2.Framer, frame http2.Frame) error {
	switch f := frame.(type) {
	case *http2.SettingsFrame:
		if f.IsAck() {
			return wFramer.WriteSettingsAck()
		}
		var settings []http2.Setting
		var hasTableSize bool
		for i := 0; i < f.NumSettings(); i++ {
			setting := f.Setting(i)
			if setting.ID == http2.SettingHeaderTableSize {
				setting.Val = 0
				hasTableSize = true
			}
			settings = append(settings, setting)
		}
		if !hasTableSize {
			settings = append(settings, http2.Setting{
				ID:  http2.SettingHeaderTableSize,
				Val: 0,
			})
		}
		return wFramer.WriteSettings(settings...)
	case *http2.DataFrame:
		return wFramer.WriteData(f.Header().StreamID, f.StreamEnded(), f.Data())
	case *http2.WindowUpdateFrame:
		return wFramer.WriteWindowUpdate(f.Header().StreamID, f.Increment)
	case *http2.PingFrame:
		return wFramer.WritePing(f.IsAck(), f.Data)
	case *http2.RSTStreamFrame:
		return wFramer.WriteRSTStream(f.Header().StreamID, f.ErrCode)
	case *http2.PriorityFrame:
		return wFramer.WritePriority(f.Header().StreamID, f.PriorityParam)
	default:
		return nil
	}
}

// UpdateHeaders modifies HTTP/2 pseudo-headers in-flight:
//  1. Rewrites :authority and host headers to match the upstream node's target SNI.
//  2. Strips the gateway chain route prefix (e.g., /eth, /solana) from :path and prefixes the
//     backend's configured base path (e.g., /eth/secret-key) while preserving subpaths.
func UpdateHeaders(
	wFramer *http2.Framer, f *http2.MetaHeadersFrame,
	le *ktls.LogicalEntity, encoder *hpack.Encoder, buf *bytes.Buffer,
) error {
	buf.Reset()
	authIdx := -1
	for i := range f.Fields {
		hf := &f.Fields[i]
		switch hf.Name {
		case ":authority", "host":
			if le != nil {
				hf.Value = unsafe.String((*byte)(le.SniPtr), le.SniLen)
			} else {
				authIdx = i
			}
		case ":path":
			subpath := hf.Value[routes.ChainPrefixLens[le.ChainID]:]
			if len(subpath) == 0 || subpath == "/" {
				hf.Value = le.Path
			} else if le.Path == "/" {
				hf.Value = subpath
			} else {
				hf.Value = le.Path + subpath
			}
			if authIdx != -1 {
				host := unsafe.String((*byte)(le.SniPtr), le.SniLen)
				f.Fields[authIdx].Value = host
			}
		}
	}
	for _, hf := range f.Fields {
		_ = encoder.WriteField(hf)
	}
	return wFramer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      f.StreamID,
		BlockFragment: buf.Bytes(),
		EndStream:     f.StreamEnded(),
		EndHeaders:    true,
		Priority:      f.Priority,
	})
}

// Proxy coordinates bidirectional HTTP/2 proxying between downstream and upstream connections:
// - Downstream -> Upstream: Forwarded in userspace through http2.Framer to allow header rewriting.
// - Upstream -> Downstream: Executed in kernel space via splice(2) into kTLS sockets, bypassed from userspace.
func Proxy(ctx context.Context, mgr *ebpf.Manager, downstreamConn net.Conn, downFd int) error {
	prefaceBuf := make([]byte, 24)
	n, _ := io.ReadFull(downstreamConn, prefaceBuf)
	if n > 0 && !bytes.Equal(prefaceBuf[:n], h2ClientPreface[:n]) {
		downstreamConn = &prefixConn{Conn: downstreamConn, prefix: prefaceBuf[:n]}
	}
	rFramer := http2.NewFramer(io.Discard, downstreamConn)
	hPackDecoder := hpack.NewDecoder(4096, nil)
	rFramer.ReadMetaHeaders = hPackDecoder

	var (
		upstreamConn  net.Conn
		le            *ktls.LogicalEntity
		spliceWG      sync.WaitGroup
		stagingBuf    bytes.Buffer
		hPackBuf      bytes.Buffer
		hPackEncoder  = hpack.NewEncoder(&hPackBuf)
		activeFramer  = http2.NewFramer(&stagingBuf, strings.NewReader(""))
		localReqBytes uint64
	)
	hPackEncoder.SetMaxDynamicTableSize(0)

	// Ensure clean teardown: closing both connections unblocks any waiting netpoller calls in splice
	// before invoking spliceWG.Wait(), preventing goroutine deadlocks on broken pipes.
	defer func() {
		if downstreamConn != nil {
			_ = downstreamConn.Close()
		}
		spliceWG.Wait()
		if localReqBytes > 0 && le != nil {
			routes.RecordRequestBytes(le.Id, localReqBytes)
			localReqBytes = 0
		}
	}()

	// Capture a single immutable RCU snapshot of the routing topology for the entire connection lifespan.
	state := routes.GlobalRoutingState.Load()
	if state == nil {
		return fmt.Errorf("routing state not initialized")
	}

	for {
		frame, err := rFramer.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		// Fast-path circuit breaker check: immediately abort if selected node or IP is quarantined.
		if le != nil {
			if le.Status.Load() != routes.StateHealthy ||
				routes.AllIps[le.IpIdx].Status.Load() != routes.StateHealthy {
				return routes.ErrNodeQuarantined
			}
		}

		switch f := frame.(type) {
		case *http2.MetaHeadersFrame:
			if le == nil {
				// First request headers: match chain ID, pick upstream node, and establish connection.
				var pathVal string
				for _, hf := range f.Fields {
					if hf.Name == ":path" {
						pathVal = hf.Value
						break
					}
				}
				chainID := routes.MatchChainID(utils.UnsafeBytes(pathVal))
				le, err = routes.GetRoute(state, chainID)
				if err != nil {
					slog.Error("GetRoute failed", "err", err)
					return err
				}

				// Fast-path dial attempt to the primary selected upstream.
				if routes.AllIps[le.IpIdx].Status.Load() == routes.StateHealthy &&
					le.Status.Load() == routes.StateHealthy {
					tMetric := time.Now()
					conn, fd, errDial := routes.Dial(ctx, le.IpIdx)
					if errDial == nil {
						telemetry.RecordTCPConnectDuration(ctx, state, le.Id, float64(time.Since(tMetric))*1e-6)
						tMetric = time.Now()
						upConn, errUpstream := ktls.DialUpstream(fd, conn, le.SniPtr)
						if errUpstream == nil {
							telemetry.RecordTLSHandshakeDuration(ctx, state, le.Id, float64(time.Since(tMetric))*1e-6)
							upstreamConn = upConn
							goto Connected
						}
						_ = conn.Close()
						routes.MarkDeadL7(le)
						telemetry.RecordQuarantine(ctx, le, "failed l7: "+errUpstream.Error())
					} else {
						log.Println("errDial", errDial)
						routes.MarkDeadL4(le.IpIdx)
						telemetry.RecordQuarantine(ctx, le, "failed l4: "+errDial.Error())
					}
				}

				// Slow-path fallback: iterate through healthy nodes in the active round-robin ring.
				{
					upConn, winningLE, errFallback := routes.DialFallbackSlowPath(
						ctx, state, chainID, le.Id,
						telemetry.RecordTCPConnectDuration,
						telemetry.RecordTLSHandshakeDuration,
						telemetry.RecordQuarantine,
					)
					if errFallback != nil {
						slog.Error("All upstreams failed in chain", "chain", chainID, "err", errFallback)
						return errFallback
					}
					upstreamConn = upConn
					le = winningLE
				}

			Connected:
				// Asynchronously stream responses from upstream socket directly into downstream socket via splice(2).
				spliceWG.Go(func() {
					sn, errSplice := ktls.SpliceUpstreamToDownstream(
						le, mgr, upstreamConn, downstreamConn, downFd,
					)
					if errSplice != nil && !ktls.IsKTLSCleanClose(errSplice) {
						var errno syscall.Errno
						if errors.As(errSplice, &errno) &&
							(errors.Is(errno, unix.ECONNREFUSED) ||
								errors.Is(errno, unix.ETIMEDOUT)) {
							slog.Warn(
								"Upstream timed out (unresponsive), quarantining",
								"ip", routes.AllIps[le.IpIdx].AddrPortStr,
							)
							routes.MarkDeadL4(le.IpIdx)
						} else {
							slog.Error("Splice upstream to downstream failed, aborting session",
								"error", errSplice)
						}
						// Forcibly tear down connections to unblock the main loop and trigger graceful defer cleanup.
						_ = upstreamConn.Close()
						_ = downstreamConn.Close()
					}
					if sn > 0 {
						routes.RecordResponseBytes(le.Id, uint64(sn))
					}
				})

				// Flush early frames buffered prior to upstream connection establishment.
				if stagingBuf.Len() > 0 {
					if _, err := upstreamConn.Write(stagingBuf.Bytes()); err != nil {
						return fmt.Errorf("failed to flush staging buffer: %w", err)
					}
					stagingBuf.Reset()
				}
				activeFramer = http2.NewFramer(upstreamConn, strings.NewReader(""))
			}

			if err := UpdateHeaders(activeFramer, f, le, hPackEncoder, &hPackBuf); err != nil {
				return err
			}
			localReqBytes += uint64(f.Header().Length + 9)
		default:
			if err = writeFrame(activeFramer, f); err != nil {
				return err
			}
			localReqBytes += uint64(f.Header().Length + 9)
		}

		if localReqBytes >= 4096 && le != nil {
			routes.RecordRequestBytes(le.Id, localReqBytes)
			localReqBytes = 0
		}
	}
}

// H2Server initializes the TCP listener on the specified port and manages incoming client connections.
// Each client connection undergoes a server-side kTLS handshake before passing control to the proxy pipeline.
func H2Server(
	ctx context.Context, mgr *ebpf.Manager, port string,
) (net.Listener, error) {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		slog.Error("Failed to start ktls listener", "error", err)
		return nil, err
	}
	go func(ln net.Listener) {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					slog.Error("Accept error", "error", err)
				}
				return
			}
			go func(c net.Conn) {
				telemetry.IncrActiveConn(ctx)
				defer func() {
					if errClose := c.Close(); errClose != nil && !errors.Is(errClose, net.ErrClosed) {
						slog.Error("Failed to close downstream connection", "err", errClose)
					} else {
						slog.Debug("Connection was already closed", "err", errClose)
					}
				}()
				downstreamConn, downFd, err := ktls.HandshakeDownstream(c)
				if err != nil {
					telemetry.DecrActiveConn(ctx)
					slog.Error("Downstream handshake failed", "error", err)
					return
				}
				if err := Proxy(ctx, mgr, downstreamConn, downFd); err != nil && !ktls.IsKTLSCleanClose(err) {
					if errors.Is(err, routes.ErrNodeQuarantined) {
						slog.Debug("Connection terminated due to node quarantine", "err", err)
					} else {
						slog.Error("Proxy finished with error", "err", err)
					}
				}
				telemetry.DecrActiveConn(ctx)
			}(conn)
		}
	}(listener)
	return listener, nil
}
