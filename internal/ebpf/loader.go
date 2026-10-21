package ebpf

import (
	"bufio"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// getKallsymsAddr scans /proc/kallsyms to resolve the virtual memory address of exported kernel symbols.
func getKallsymsAddr(symbol string) (uint64, error) {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return 0, err
	}
	defer func(file *os.File) {
		errClose := file.Close()
		if errClose != nil {
			slog.Error("Error closing /proc/kallsyms: %s", errClose)
		}
	}(file)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[2] == symbol {
			return strconv.ParseUint(fields[0], 16, 64)
		}
	}
	return 0, fmt.Errorf("symbol %s not found", symbol)
}

// getKernelVarValue inspects /proc/kcore (the kernel's live memory image as an ELF core file)
// to read the 64-bit runtime pointer value of a kernel variable, resolving dynamic KASLR offsets.
func getKernelVarValue(symbolName string) (uint64, error) {
	symAddr, err := getKallsymsAddr(symbolName)
	if err != nil {
		return 0, err
	}
	kcoreElf, err := elf.Open("/proc/kcore")
	if err != nil {
		return 0, fmt.Errorf("failed to open /proc/kcore: %w", err)
	}
	defer func(kcoreElf *elf.File) {
		errElf := kcoreElf.Close()
		if errElf != nil {
			slog.Error("failed to close kcore elf", "error", errElf)
		}
	}(kcoreElf)

	closeKcore := func(f *os.File) {
		if errClose := f.Close(); errClose != nil {
			slog.Error("Error closing /proc/kcore: %s", errClose)
		}
	}

	for _, prog := range kcoreElf.Progs {
		if prog.Type == elf.PT_LOAD {
			if symAddr >= prog.Vaddr && symAddr < prog.Vaddr+prog.Memsz {
				fileOffset := int64(prog.Off + (symAddr - prog.Vaddr))
				f, err := os.Open("/proc/kcore")
				if err != nil {
					return 0, err
				}
				buf := make([]byte, 8)
				if _, err := f.ReadAt(buf, fileOffset); err != nil && err != io.EOF {
					closeKcore(f)
					return 0, err
				}
				closeKcore(f)
				return binary.LittleEndian.Uint64(buf), nil
			}
		}
	}
	return 0, fmt.Errorf("address 0x%x not found in /proc/kcore PT_LOAD", symAddr)
}

// Close gracefully stops the ring buffer reader, detaches tracing links, and unloads BPF maps.
func (m *Manager) Close() error {
	m.cancel()
	err := m.ringReader.Close()
	if err != nil {
		return err
	}
	m.wg.Wait()
	m.coll.Close()
	return m.link.Close()
}

// Load compiles and attaches the eBPF kernel program:
// 1. Removes memlock memory limits (RLIMIT_MEMLOCK).
// 2. Resolves live KASLR base pointers (page_offset_base and vmemmap_base) from /proc/kcore.
// 3. Injects hardware CPU counts, shift masks, and KASLR bases into ELF volatile spec variables.
// 4. Attaches fentry probe to splice_to_socket and spawns telemetry consumers.
func Load(ctx context.Context,
	on200OK func(ctx context.Context, leID uint32, delta uint64, total uint64),
	onError func(ctx context.Context, leID uint64, status uint16),
) (*Manager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("internal/ebpf/lib/bpf_h2_parser.o")
	if err != nil {
		return nil, fmt.Errorf("failed to load spec: %v", err)
	}

	pageOffsetVal, err1 := getKernelVarValue("page_offset_base")
	vmemmapVal, err2 := getKernelVarValue("vmemmap_base")
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("failed to read values from /proc/kcore: %v, %v", err1, err2)
	}

	numCPU := runtime.NumCPU()
	if err := constants(spec, pageOffsetVal, vmemmapVal, numCPU); err != nil {
		return nil, err
	}

	// Dynamically size metrics array to exactly (NumCPU * LesPerCPU) slots.
	spec.Maps["metrics_array"].MaxEntries = uint32(numCPU * LesPerCPU)
	spec.Maps["error_events"].MaxEntries = uint32(256 * LesPerCPU)

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create collection: %v", err)
	}

	prog := coll.Programs["trace_splice_to_socket"]
	l, err := link.AttachTracing(link.TracingOptions{Program: prog})
	if err != nil {
		return nil, fmt.Errorf("attach failed: %v", err)
	}

	ringReader, err := ringbuf.NewReader(coll.Maps["error_events"])
	if err != nil {
		errClose := l.Close()
		if errClose != nil {
			slog.Error("failed to close ringbuf reader", "error", errClose)
		}
		coll.Close()
		return nil, fmt.Errorf("ringbuf open failed: %w", err)
	}

	ctxWithCancel, cancel := context.WithCancel(ctx)
	mgr := &Manager{
		coll:       coll,
		link:       l,
		ringReader: ringReader,
		sessionMap: coll.Maps["session_map"],
		metricsMap: coll.Maps["metrics_array"],
		cancel:     cancel,
		on200OK:    on200OK,
		onError:    onError,
	}
	mgr.start(ctxWithCancel)
	return mgr, nil
}

// constants binds runtime system parameters into ELF global variables prior to loading into the kernel.
func constants(
	spec *ebpf.CollectionSpec, pageOffsetVal, vmemmapVal uint64, cpus int,
) error {
	if v, ok := spec.Variables["KASLR_PAGE_OFFSET"]; ok {
		if err := v.Set(pageOffsetVal); err != nil {
			return fmt.Errorf("set KASLR_PAGE_OFFSET failed: %v", err)
		}
	} else {
		return fmt.Errorf("variable KASLR_PAGE_OFFSET not found in ELF spec")
	}

	if v, ok := spec.Variables["KASLR_VMEMMAP"]; ok {
		if err := v.Set(vmemmapVal); err != nil {
			return fmt.Errorf("set KASLR_VMEMMAP failed: %v", err)
		}
	} else {
		return fmt.Errorf("variable KASLR_VMEMMAP not found in ELF spec")
	}

	if v, ok := spec.Variables["CPUS"]; ok {
		if err := v.Set(uint32(cpus)); err != nil {
			return fmt.Errorf("set CPUS failed: %v", err)
		}
	} else {
		return fmt.Errorf("variable CPUS not found in ELF spec")
	}

	if v, ok := spec.Variables["STATUS_OK_SHIFT"]; ok {
		if err := v.Set(uint32(math.Log2(LesPerCPU))); err != nil {
			return fmt.Errorf("set STATUS_OK_SHIFT failed: %v", err)
		}
	} else {
		return fmt.Errorf("variable STATUS_OK_SHIFT not found in ELF spec")
	}

	if v, ok := spec.Variables["STATUS_OK_MASK"]; ok {
		if err := v.Set(uint32(LesPerCPU - 1)); err != nil {
			return fmt.Errorf("set STATUS_OK_MASK failed: %v", err)
		}
	} else {
		return fmt.Errorf("variable STATUS_OK_MASK not found in ELF spec")
	}
	return nil
}
