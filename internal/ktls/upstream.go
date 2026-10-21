package ktls

/*
#cgo LDFLAGS: ${SRCDIR}/lib/upstream.o
#include "src/types.h"
*/
import "C"

import (
	"bytes"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"unsafe"
)

// Conn decorates upstream net.Conn to replay initial handshake bytes on read
// and intercept redundant HTTP/2 connection preface frames on first write.
type Conn struct {
	net.Conn
	onRead  func([]byte) (int, error)
	onWrite func([]byte) (int, error)
	prefix  []byte
	fd      int
}

func (c *Conn) Read(p []byte) (int, error)  { return c.onRead(p) }
func (c *Conn) Write(b []byte) (int, error) { return c.onWrite(b) }

func (c *Conn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, fmt.Errorf("underlying upstream conn does not implement syscall.Conn")
}

var h2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// ConnPreface wraps an established upstream socket connection:
// - Replays server SETTINGS frames pre-read during OpenSSL handshake.
// - Intercepts and strips the duplicate HTTP/2 client preface if already sent by OpenSSL.
func ConnPreface(conn net.Conn, prefix []byte, fd int) net.Conn {
	c := &Conn{Conn: conn, prefix: prefix, fd: fd}
	c.onRead = func(p []byte) (int, error) {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			c.onRead = c.Conn.Read
		}
		return n, nil
	}
	c.onWrite = func(p []byte) (int, error) {
		// If framer attempts to send client preface, strip it to prevent duplicate handshake on wire.
		if len(p) >= 24 && bytes.Equal(p[:24], h2Preface) {
			c.onWrite = c.Conn.Write
			if len(p) > 24 {
				n, err := c.Conn.Write(p[24:])
				return n + 24, err
			}
			return 24, nil
		}
		return c.Conn.Write(p)
	}
	return c
}

// DialUpstream performs client-side TLS handshake with upstream endpoint using OpenSSL kTLS:
// - Pins the Context and scratch buffer to prevent Go GC movement during Cgo execution.
// - Enforces concurrency limits via HandshakeLimiter.
// - Verifies that kernel kTLS RX offload is operational before handing over to splice pipeline.
func DialUpstream(fd int, conn net.Conn, sniPtr unsafe.Pointer) (net.Conn, error) {
	s := contextPool.Get().(*Pool)
	var pin runtime.Pinner
	pin.Pin(&s.ctx)
	pin.Pin(unsafe.SliceData(s.buf))
	s.ctx.SniPtr = uintptr(sniPtr)
	s.ctx.Fd = int32(fd)

	HandshakeLimiter <- struct{}{}
	C.do_ktls_dial((*C.Context)(unsafe.Pointer(&s.ctx)))
	<-HandshakeLimiter

	if s.ctx.status == 0 || s.ctx.rxActive == 0 || s.ctx.pendingLen < 0 {
		pin.Unpin()
		contextPool.Put(s)
		return nil, fmt.Errorf("ktls Dial failed (status %d, rx %d)", s.ctx.status, s.ctx.rxActive)
	}

	prefix := bytes.Clone(s.buf[:s.ctx.pendingLen])
	contextPool.Put(s)
	pin.Unpin()
	return ConnPreface(conn, prefix, fd), nil
}
