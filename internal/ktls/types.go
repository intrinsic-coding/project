package ktls

/*
	Implementation of Kernel TLS (ktls) provides the following benefits:
	Zero-Copy Data Plane: ktls enables high-performance forwarding of large HTTP/2 DATA responses directly between
		backend and client sockets using splice, bypassing userspace overhead.
	H2 Stack: While the standard net/http supports HTTP/2, it is tightly coupled with the crypto/tls package
		at the compiler and internal level. Even when using hacks to disable encryption, crypto/tls still
		injects a 5-byte TLS record header into every write syscall. Overwriting or stripping these headers
		in-flight is significantly more expensive than using golang.org/x/net/http2 on a raw socket with ktls
		handling the framing at the kernel level.
*/

import (
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"
)

// LogicalEntity represents a single backend endpoint routing identity:
// binds together a ChainID, Target Host SNI, Base Path, and resolved L4 IP.
type LogicalEntity struct {
	Path             string         // Base URL path prefix (e.g. /eth/secret-key)
	Id               uint64         // Unique canonical index in global arena (0..MaxLEs-1)
	SniPtr           unsafe.Pointer // Null-terminated pinned C-string of target hostname
	SniLen           int32          // Length of SNI hostname string
	ChainID          int32          // Chain identifier mapping to routing generation
	Status           atomic.Uint32  // Health state: StateHealthy (0) or StateUnhealthy (1)
	DisabledUntilSec atomic.Uint32  // Unix epoch timestamp (seconds) until quarantine cooldown expires
	LastErrorSec     atomic.Uint32  // Timestamp of most recent L7 error (for sliding window threshold)
	ErrorCount       atomic.Uint32  // Consecutive error counter for sliding window circuit breaker
	IpIdx            int32          // Index of bound IP entry in AllIps arena
	Lag              int32          // Slot/block lag relative to chain head
}

// internalContext defines the raw Cgo memory layout expected by C.Context.
type internalContext struct {
	SniPtr     uintptr
	bufPtr     uint64
	bufCap     int32
	Fd         int32
	pendingLen int32
	rxActive   int32
	status     int32
}

// Context aligns internalContext to 64 bytes to prevent cache-line thrashing across worker threads.
type Context struct {
	internalContext
	pad [64 - unsafe.Sizeof(internalContext{})%64]byte
}

// Pool pairs a Context with a reusable 16 KB scratch buffer for TLS handshake reads.
type Pool struct {
	ctx Context
	buf []byte
}

// contextPool pools handshake buffers to eliminate heap allocations during connection setup spikes.
var contextPool = sync.Pool{
	New: func() any {
		ps := &Pool{
			buf: make([]byte, 16384),
		}
		ps.ctx.bufPtr = uint64(uintptr(unsafe.Pointer(unsafe.SliceData(ps.buf))))
		ps.ctx.bufCap = 16384
		return ps
	},
}

// HandshakeLimiter bounds concurrent Cgo OpenSSL handshake calls to NumCPU,
// preventing runaway OS thread (pthread) creation in the Go runtime under connection surges.
var HandshakeLimiter = make(chan struct{}, runtime.NumCPU())
