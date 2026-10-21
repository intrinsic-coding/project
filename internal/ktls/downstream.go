package ktls

/*
#cgo CFLAGS: -I${SRCDIR}/lib/openssl/include
#cgo LDFLAGS: ${SRCDIR}/lib/downstream.o ${SRCDIR}/lib/openssl/libssl.a ${SRCDIR}/lib/openssl/libcrypto.a -lpthread -ldl
#include "src/types.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"syscall"
	"unsafe"

	"balancer/internal/ebpf"

	"golang.org/x/sys/unix"
)

// BufferedConn wraps net.Conn with a prefix buffer to replay bytes read during handshake.
type BufferedConn struct {
	net.Conn
	prefix []byte
}

func (b *BufferedConn) Read(p []byte) (int, error) {
	if len(b.prefix) > 0 {
		n := copy(p, b.prefix)
		b.prefix = b.prefix[n:]
		return n, nil
	}
	return b.Conn.Read(p)
}

func (b *BufferedConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := b.Conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, fmt.Errorf("underlying downstream conn does not implement syscall.Conn")
}

// IsKTLSCleanClose determines whether an error signifies a standard session termination
// (e.g., client closed tab, EOF, or clean TLS record shutdown) rather than an abnormal infrastructure failure.
func IsKTLSCleanClose(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errors.Is(errno, unix.EINVAL) ||
			errors.Is(errno, unix.EPIPE) ||
			errors.Is(errno, unix.EIO) ||
			errors.Is(errno, unix.EBADMSG) ||
			errors.Is(errno, unix.ECONNRESET)
	}
	return false
}

// SessionCtxStruct matches the memory layout for session tracing.
type SessionCtxStruct struct {
	HeaderBuf        [16]byte
	HeaderCnt        uint32
	RemainingPayload uint32
	InPayload        uint64
}

const sizeOneMB = 1024 * 1024

// SpliceUpstreamToDownstream executes zero-copy kernel forwarding of HTTP/2 response traffic.
// Data flows: Upstream TCP Socket -> Kernel Pipe -> Downstream Client TCP Socket.
// Concurrently, an eBPF fentry probe on splice_to_socket inspects the pipe buffers directly
// in kernel memory to record metrics without copying data into userspace.
func SpliceUpstreamToDownstream(
	le *LogicalEntity, mgr *ebpf.Manager, upstreamConn, downstreamConn net.Conn, downFd int,
) (int64, error) {
	// Replay any buffered handshake bytes to downstream before initiating zero-copy splice.
	if c, ok := upstreamConn.(*Conn); ok && len(c.prefix) > 0 {
		if _, err := downstreamConn.Write(c.prefix); err != nil {
			return 0, err
		}
		c.prefix = nil
	}

	// Register downstream socket cookie in eBPF session map to associate kernel-traced responses with this LE.
	cookie, err := unix.GetsockoptUint64(downFd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		return 0, fmt.Errorf("couldn't get cookie: %w", err)
	}
	if cookie > 0 {
		err := mgr.RegisterSession(cookie, le.Id)
		if err != nil {
			return 0, fmt.Errorf("failed to register session: %v", err)
		}
	}

	upSys, ok1 := upstreamConn.(syscall.Conn)
	downSys, ok2 := downstreamConn.(syscall.Conn)
	if !ok1 || !ok2 {
		return 0, fmt.Errorf("connections do not support syscall.Conn (up: %v, down: %v)", ok1, ok2)
	}
	upRaw, err1 := upSys.SyscallConn()
	downRaw, err2 := downSys.SyscallConn()
	if err1 != nil || err2 != nil {
		return 0, fmt.Errorf("failed to get SyscallConn: %v, %v", err1, err2)
	}

	pipe, err := GetPipe()
	if err != nil {
		return 0, fmt.Errorf("get pipe failed: %w", err)
	}
	defer PutPipe(pipe)

	var totalSpliced int64
	for {
		var nRead int64
		var spliceReadErr error

		// Splice from upstream socket into intermediate kernel pipe buffer.
		// Returns false on EAGAIN to yield to the Go netpoller until the socket becomes readable.
		netPollerReadErr := upRaw.Read(func(upFD uintptr) bool {
			nRead, spliceReadErr = unix.Splice(
				int(upFD), nil,
				pipe[1], nil,
				sizeOneMB,
				unix.SPLICE_F_NONBLOCK|unix.SPLICE_F_MOVE,
			)
			if errors.Is(unix.EAGAIN, spliceReadErr) {
				return false
			}
			return true
		})
		if netPollerReadErr != nil {
			return totalSpliced, netPollerReadErr
		}
		if spliceReadErr != nil || nRead == 0 {
			if spliceReadErr == io.EOF || nRead == 0 {
				break
			}
			return totalSpliced, spliceReadErr
		}

		// Splice from kernel pipe buffer into downstream client socket.
		var nWritten int64
		var spliceWriteErr error
		netPollerWriteErr := downRaw.Write(func(downFD uintptr) bool {
			nWritten, spliceWriteErr = unix.Splice(
				pipe[0], nil,
				int(downFD), nil,
				int(nRead),
				unix.SPLICE_F_NONBLOCK|unix.SPLICE_F_MOVE,
			)
			if errors.Is(unix.EAGAIN, spliceWriteErr) {
				return false
			}
			return true
		})
		if netPollerWriteErr != nil || spliceWriteErr != nil {
			return totalSpliced, spliceWriteErr
		}
		if nWritten > 0 {
			totalSpliced += nWritten
		}

		// If downstream socket buffer accepted fewer bytes than read into the pipe,
		// drain remaining bytes before attempting the next socket read.
		if nWritten < nRead {
			drained, errDrain := drainRemainingSplice(pipe[0], downRaw, nRead-nWritten)
			totalSpliced += drained
			if errDrain != nil {
				return totalSpliced, errDrain
			}
		}
	}
	return totalSpliced, nil
}

// drainRemainingSplice loops until all bytes remaining in the kernel pipe buffer are fully flushed into the socket.
//
//go:noinline
func drainRemainingSplice(pipeReadFD int, downRaw syscall.RawConn, remaining int64) (int64, error) {
	var totalWritten int64
	for remaining > 0 {
		var nWritten int64
		var spliceWriteErr error
		netPollerWriteErr := downRaw.Write(func(downFD uintptr) bool {
			nWritten, spliceWriteErr = unix.Splice(
				pipeReadFD, nil,
				int(downFD), nil,
				int(remaining),
				unix.SPLICE_F_NONBLOCK|unix.SPLICE_F_MOVE,
			)
			if errors.Is(unix.EAGAIN, spliceWriteErr) {
				return false
			}
			return true
		})
		if netPollerWriteErr != nil || spliceWriteErr != nil {
			return totalWritten, spliceWriteErr
		}
		if nWritten == 0 {
			break
		}
		totalWritten += nWritten
		remaining -= nWritten
	}
	return totalWritten, nil
}

// HandshakeDownstream accepts a raw downstream TCP connection, delegates the TLS handshake
// to OpenSSL via Cgo, pins memory to avoid GC movement, and activates kTLS on success.
func HandshakeDownstream(conn net.Conn) (net.Conn, int, error) {
	slot := contextPool.Get().(*Pool)
	var pin runtime.Pinner
	pin.Pin(&slot.ctx)
	slot.ctx.status = 0
	slot.ctx.rxActive = 0

	rawConn, _ := conn.(syscall.Conn).SyscallConn()
	if err := rawConn.Control(func(fd uintptr) {
		slot.ctx.Fd = int32(fd)
		HandshakeLimiter <- struct{}{}
		C.do_ktls_server_handshake((*C.Context)(unsafe.Pointer(&slot.ctx)))
		<-HandshakeLimiter
	}); err != nil {
		pin.Unpin()
		contextPool.Put(slot)
		return nil, -1, err
	}

	if slot.ctx.status == 0 || slot.ctx.rxActive == 0 {
		pin.Unpin()
		contextPool.Put(slot)
		return nil, -1,
			fmt.Errorf("c-handshake failed: status %d, rxActive %d", slot.ctx.status, slot.ctx.rxActive)
	}

	fd := slot.ctx.Fd
	pin.Unpin()
	contextPool.Put(slot)
	return conn, int(fd), nil
}

// InitServer initializes both server and client global OpenSSL contexts at application startup.
func InitServer() {
	C.init_ktls_server_ctx()
	C.init_ktls_client_ctx()
}
