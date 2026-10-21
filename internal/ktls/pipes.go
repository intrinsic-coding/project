package ktls

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

type Pipe = [2]int

const SizePipesPool = 1024

// PipePool a limited pool of non-blocking system pipes
type PipePool struct {
	pool chan Pipe
}

// NewPipePool creates a new pool of pipes of a specified capacity
func NewPipePool(capacity int) *PipePool {
	return &PipePool{
		pool: make(chan Pipe, capacity),
	}
}

// Global default pool for 1024 pipe pairs
var defaultPipePool = NewPipePool(SizePipesPool)

// GetPipe takes a warmed-up pipe from the pool or creates a new one via pipe2
func GetPipe() (Pipe, error) {
	return defaultPipePool.Get()
}

// PutPipe returns the pipe to the pool, validating the cleanliness of the kernel buffer
func PutPipe(p Pipe) {
	defaultPipePool.Put(p)
}

// ClosePipePool performs a graceful shutdown of the pool
func ClosePipePool() {
	defaultPipePool.Close()
}

// Get extracts the pipe
func (p *PipePool) Get() (Pipe, error) {
	select {
	case pipe := <-p.pool:
		return pipe, nil
	default:
		var pipe Pipe
		err := unix.Pipe2(pipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK)
		return pipe, err
	}
}

// Put returns the pipe to the pool, ensuring there are no leaks or data poisoning.
func (p *PipePool) Put(pipe Pipe) {
	// Check whether the pipe is clean (i.e., whether there are any remaining bytes in the kernel).
	if !isPipeClean(pipe[0]) {
		_ = unix.Close(pipe[0])
		_ = unix.Close(pipe[1])
		return
	}
	// Returning to the pool
	select {
	case p.pool <- pipe:
	default:
		// If the pool is full, we deterministically close the descriptors.
		_ = unix.Close(pipe[0])
		_ = unix.Close(pipe[1])
	}
}

// Close closes all descriptors held in the pool
func (p *PipePool) Close() {
	close(p.pool)
	for pipe := range p.pool {
		_ = unix.Close(pipe[0])
		_ = unix.Close(pipe[1])
	}
}

// isPipeClean pipe condition check
func isPipeClean(fd int) bool {
	// FIONREAD - https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/ioctls.h around 46 line
	const FIONREAD = 0x541B
	var n int32
	_, _, errno := unix.RawSyscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		FIONREAD,
		uintptr(unsafe.Pointer(&n)),
	)
	return errno == 0 && n == 0
}

func GetAvailablePipes() int {
	return len(defaultPipePool.pool)
}
