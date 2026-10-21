package ebpf

import (
	"context"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	// LesPerCPU defines the maximum Logical Entities supported per CPU slot in BPF maps.
	// Must match LE_PER_CPU in bpf_h2_parser.c and must be a power of 2 for bitmask indexing.
	LesPerCPU = 512
)

// ErrorEvent matches struct error_event_t emitted via the BPF ring buffer.
type ErrorEvent struct {
	LeID        uint64 // LogicalEntity ID associated with the error
	Status      uint16 // HTTP status code (e.g. 429, 500, 502)
	Reserved    uint16 // Reserved alignment padding
	TimestampNs uint64 // Kernel monotonic timestamp (nanoseconds)
	_pad        uint32 // Padding for 8-byte alignment
}

// SessionCtx mirrors struct session_ctx in bpf_h2_parser.c.
//
// Memory Layout & Alignment (Total: 64 bytes - exactly 1 CPU Cache Line):
// ------------------------------------------------------------------------
// Offset | Size | Field       | Description
// -------+------+-------------+-------------------------------------------
//
//	 0..15|  16B | HeaderBuf   | Accumulates incomplete 9-byte H2 frame header
//	16..23|   8B | StatusBuf   | Accumulates HPACK status header bytes
//	24..27|   4B | HeaderCnt   | Bytes currently stored in HeaderBuf (0..9)
//	28..31|   4B | StatusCnt   | Bytes currently stored in StatusBuf (0..8)
//	32..35|   4B | Remaining   | Remaining payload bytes to skip for frame
//	36..39|   4B | State       | FSM state (0=Header, 1=Status, 2=Skip Payload)
//	40..43|   4B | LastTail    | Ring buffer tail index processed in last pass
//	44..47|   4B | LastOffset  | Cumulative offset processed within LastTail
//	48..51|   4B | Init        | Initialization sentinel flag (1=active)
//	52..55|   4B | _           | EXPLICIT PADDING: ensures 8-byte alignment for LeID
//	56..63|   8B | LeID        | 64-bit LogicalEntity ID for telemetry routing
//
// ------------------------------------------------------------------------
type SessionCtx struct {
	HeaderBuf  [16]byte
	StatusBuf  [8]byte
	HeaderCnt  uint32
	StatusCnt  uint32
	Remaining  uint32
	State      uint32
	LastTail   uint32 // Last pipe buffer tail index processed
	LastOffset uint32 // Byte offset reached within LastTail (idempotent drain retry protection)
	Init       uint32 // Initialization sentinel flag
	_          uint32 // 4-byte padding required for 8-byte alignment of LeID
	LeID       uint64 // Target LogicalEntity ID
}

// Manager orchestrates the lifecycle of eBPF programs, maps, and event ingestion loops.
type Manager struct {
	coll       *ebpf.Collection
	link       link.Link
	ringReader *ringbuf.Reader
	sessionMap *ebpf.Map
	metricsMap *ebpf.Map
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	prevCounts [LesPerCPU]uint64
	on200OK    func(ctx context.Context, leID uint32, delta uint64, total uint64)
	onError    func(ctx context.Context, leID uint64, status uint16)
}
