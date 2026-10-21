// bpf_h2_parser.c
// Zero-copy HTTP/2 response parser running directly inside Linux kernel space.
// Attached via fentry tracing to splice_to_socket, it snoops HTTP/2 status codes directly
// from pipe_buffer pages while data is being spliced into the downstream socket,
// completely bypassing userspace memory copying and context switches.

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define preserve_acc __attribute__((preserve_access_index))
#define MAX_CPUS 64
#define LE_PER_CPU 512
#define TOTAL_ENTRIES (MAX_CPUS * LE_PER_CPU)
#define MAX_SESSIONS 65535

#ifndef BPF_FUNC_loop
#define BPF_FUNC_loop 181
#endif

// struct session_ctx maintains stateful HTTP/2 stream parsing across fragmented pipe buffers.
// Memory layout is aligned to exactly 64 bytes (1 CPU cache line).
struct session_ctx {
    __u8  header_buf[16]; // Buffer for incomplete 9-byte HTTP/2 frame headers
    __u8  status_buf[8];  // Buffer for HPACK status header bytes
    __u32 header_cnt;     // Bytes accumulated in header_buf (0..9)
    __u32 status_cnt;     // Bytes accumulated in status_buf (0..8)
    __u32 remaining;      // Remaining payload bytes to skip for current frame
    __u32 state;          // FSM state: 0=Frame Header, 1=Status Headers, 2=Skip Payload
    __u32 last_tail;      // Ring buffer tail index processed in previous invocation
    __u32 last_offset;    // Cumulative offset processed within last_tail (prevents drain dupes)
    __u32 initialized;    // 1 if session tracking has started, 0 otherwise
    __u32 padding;        // Explicit 4-byte padding to align le_id on 8-byte boundary
    __u64 le_id;          // Associated LogicalEntity ID for telemetry attribution
};

// struct loop_ctx encapsulates context passed to bpf_loop iterations.
struct loop_ctx {
    void *virt;              // Kernel direct-map virtual memory pointer for current page buffer
    struct session_ctx *ctx; // Active session tracking context
    __u32 len;               // Total readable bytes in current buffer chunk
    __u32 off;               // Current reading cursor offset within buffer chunk
};

// struct error_event_t represents non-200 HTTP/2 responses submitted to userspace via BPF ringbuf.
struct error_event_t {
    __u64 le_id;        // LogicalEntity ID that emitted the error
    __u16 status;       // Decoded HTTP status code (e.g. 429, 500, 502)
    __u16 reserved;     // Reserved for alignment / future flags
    __u64 timestamp_ns; // Kernel monotonic timestamp in nanoseconds (bpf_ktime_get_ns)
    __u32 _pad;         // 4-byte padding for 8-byte struct alignment
};

//static long (*bpf_loop)(__u32 nr_loops, void *callback_fn, void *callback_ctx, __u64 flags) = (void *)BPF_FUNC_loop;
static long (*current_bpf_loop)(__u32 nr_loops, void *callback_fn, void *callback_ctx, __u64 flags) = (void *)BPF_FUNC_loop;

// metrics_array stores per-CPU 200 OK request counters.
// Addressed via: (cpu << STATUS_OK_SHIFT) | (le_id & STATUS_OK_MASK).
// Marked as BPF_F_MMAPABLE for zero-overhead userspace counter scraping.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TOTAL_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
    __uint(map_flags, BPF_F_MMAPABLE);
} metrics_array SEC(".maps");

// error_events emits structured non-200 response events to userspace asynchronously.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * LE_PER_CPU);
} error_events SEC(".maps");

// session_map correlates downstream socket cookies (SO_COOKIE) to active session parser contexts.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_SESSIONS);
    __type(key, __u64);
    __type(value, struct session_ctx);
} session_map SEC(".maps");

// BPF CO-RE kernel structure definitions preserving field offsets across kernel versions.
struct page {} preserve_acc;

struct pipe_buffer {
    struct page *page;
    __u32 offset;
    __u32 len;
} preserve_acc;

struct pipe_inode_info {
    __u32 head;
    __u32 tail;
    __u32 ring_size;
    struct pipe_buffer *bufs;
} preserve_acc;

struct sock_common {
    union {
        struct {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };
    union {
        struct {
            __be16 skc_dport;
            __u16 skc_num;
        };
    };
    unsigned short skc_family;
} preserve_acc;

struct sock {
    struct sock_common __sk_common;
} preserve_acc;

struct socket {
    struct sock *sk;
} preserve_acc;

// Dynamic KASLR base addresses and bitshift parameters injected at ELF load time by loader.go.
const volatile __u64 KASLR_PAGE_OFFSET = 0;
const volatile __u64 KASLR_VMEMMAP = 0;
const volatile __u32 CPUS = 0;
const volatile __u32 STATUS_OK_SHIFT = 0;
const volatile __u32 STATUS_OK_MASK = 0;

// page_to_virt_kaslr translates a physical page structure pointer into a direct-map virtual address:
// PFN = (struct page* - KASLR_VMEMMAP) / sizeof(struct page)
// Virtual Address = (PFN << 12) + KASLR_PAGE_OFFSET
static inline void *page_to_virt_kaslr(struct page *page) {
    __u64 p = (__u64)page;
    if (!p)
        return 0;
    __u32 page_struct_size = bpf_core_type_size(struct page);
    if (!page_struct_size)
        return 0;
    __u64 pfn = (p - KASLR_VMEMMAP) / page_struct_size;
    return (void *)((pfn << 12) + KASLR_PAGE_OFFSET);
}

// decode_h2_status decodes HTTP/2 status codes from raw HPACK header block fragments (RFC 7541):
// 1. Static table indexed 1-byte status headers:
//    - 0x88 = 200 OK (Index 8)
//    - 0x8C = 400 Bad Request (Index 12)
//    - 0x8D = 404 Not Found (Index 13)
//    - 0x8E = 500 Internal Server Error (Index 14)
//    - 0x89 = 204, 0x8A = 206, 0x8B = 304
// 2. Literal status headers with raw 3-digit ASCII values (e.g. "429", "502", "504").
// 3. Huffman-encoded 3-digit status codes packed into 2-byte or 3-byte bit patterns.
static __always_inline __u16 decode_h2_status(const __u8 *buf) {
    __u8 b0 = buf[0]; __u8 b1 = buf[1]; __u8 b2 = buf[2]; __u8 b3 = buf[3]; __u8 b4 = buf[4];

    // Skip optional leading HTTP/2 padding byte if present.
    if (b0 == 0x20) { b0 = b1; b1 = b2; b2 = b3; b3 = b4; b4 = buf[5]; }

    // Fast-path: 1-byte Indexed Header Field (RFC 7541 Section 6.1).
    if (b0 == 0x88) return 200;
    if (b0 == 0x8D) return 404;
    if (b0 == 0x8E) return 500;
    if (b0 == 0x89) return 204;
    if (b0 == 0x8A) return 206;
    if (b0 == 0x8B) return 304;
    if (b0 == 0x8C) return 400;

    __u8 name_idx = b0 & 0x0F;
    __u8 mode_prefix = b0 & 0xF0;

    // Literal Header Field without Indexing / with Incremental Indexing for :status (Indices 8..14).
    if ((name_idx >= 8 && name_idx <= 14) && (mode_prefix == 0x00 || mode_prefix == 0x40 || mode_prefix == 0x10)) {
        // Plain ASCII 3-digit status code.
        if (b1 == 0x03 && (b2 >= '0' && b2 <= '9') && (b3 >= '0' && b3 <= '9') && (b4 >= '0' && b4 <= '9')) {
            return (b2 - '0') * 100 + (b3 - '0') * 10 + (b4 - '0');
        }
        // 2-byte Huffman encoded status code.
        if (b1 == 0x82) {
            __u32 w = ((__u32)b2 << 8) | b3;
            __u32 d1 = (((w >> 11) & 0x1F) <= 2) ? ((w >> 11) & 0x1F) : ((((w >> 10) & 0x3F) - 0x19) + 3);
            w = (w << ((((w >> 11) & 0x1F) <= 2) ? 5 : 6)) & 0xFFFF;
            __u32 d2 = (((w >> 11) & 0x1F) <= 2) ? ((w >> 11) & 0x1F) : ((((w >> 10) & 0x3F) - 0x19) + 3);
            w = (w << ((((w >> 11) & 0x1F) <= 2) ? 5 : 6)) & 0xFFFF;
            __u32 d3 = (((w >> 11) & 0x1F) <= 2) ? ((w >> 11) & 0x1F) : ((((w >> 10) & 0x3F) - 0x19) + 3);
            if (d1 >= 1 && d1 <= 5 && d2 <= 9 && d3 <= 9)
                return (__u16)(d1 * 100 + d2 * 10 + d3);
        }
        // 3-byte Huffman encoded status code.
        if (b1 == 0x83) {
            __u32 w = ((__u32)b2 << 16) | ((__u32)b3 << 8) | b4;
            __u32 d1 = (((w >> 19) & 0x1F) <= 2) ? ((w >> 19) & 0x1F) : ((((w >> 18) & 0x3F) - 0x19) + 3);
            w = (w << ((((w >> 19) & 0x1F) <= 2) ? 5 : 6)) & 0xFFFFFF;
            __u32 d2 = (((w >> 19) & 0x1F) <= 2) ? ((w >> 19) & 0x1F) : ((((w >> 18) & 0x3F) - 0x19) + 3);
            w = (w << ((((w >> 19) & 0x1F) <= 2) ? 5 : 6)) & 0xFFFFFF;
            __u32 d3 = (((w >> 19) & 0x1F) <= 2) ? ((w >> 19) & 0x1F) : ((((w >> 18) & 0x3F) - 0x19) + 3);
            if (d1 >= 1 && d1 <= 5 && d2 <= 9 && d3 <= 9)
                return (__u16)(d1 * 100 + d2 * 10 + d3);
        }
    }
    return 0;
}

// h2_parse_callback implements the core HTTP/2 framing Finite State Machine (FSM):
// - State 0: Accumulates 9-byte HTTP/2 Frame Header (Length, Type, Flags, StreamID).
//            Performs RFC 7540 validation (frame type <= 10, length <= 65536).
// - State 1: For HEADERS frames (type 0x01), inspects initial payload bytes to extract status code.
//            Increments metrics_array on 200 OK or reserves ringbuf entry for non-200 errors.
// - State 2: Skips uninspected payload bytes (DATA frames or extra header fields) across pipe buffers.
static int h2_parse_callback(__u32 index, struct loop_ctx *l) {
    struct session_ctx *ctx = l->ctx;
    if (l->off >= l->len) return 1;

    // FSM State 0: Frame Header Parsing
    if (ctx->state == 0) {
        __u32 avail = l->len - l->off;
        __u32 cnt = ctx->header_cnt & 0x0F;
        if (cnt > 9) cnt = 9;
        __u32 needed = 9 - cnt;
        __u32 to_copy = (avail < needed) ? avail : needed;
        asm volatile("" : "+r"(to_copy)); to_copy &= 0x0F;

        if (to_copy > 0) {
            void *src = l->virt + l->off;
            bpf_probe_read_kernel(&ctx->header_buf[cnt], to_copy, src);
            ctx->header_cnt += to_copy;
            l->off += to_copy;
        }

        if (ctx->header_cnt >= 9) {
            __u32 f_len = ((__u32)ctx->header_buf[0] << 16) | ((__u32)ctx->header_buf[1] << 8) | ctx->header_buf[2];
            __u8 f_type = ctx->header_buf[3];

            // RFC 7540 desynchronization protection: slide 1 byte if header violates framing bounds.
            if (f_type > 10 || f_len > 65536) {
                #pragma unroll
                for (int s = 0; s < 8; s++) {
                    ctx->header_buf[s] = ctx->header_buf[s + 1];
                }
                ctx->header_cnt = 8;
                return 0;
            }

            ctx->header_cnt = 0;
            ctx->remaining = f_len;

            if (f_type == 0x01) { // HEADERS frame
                if (f_len > 0) {
                    ctx->state = 1;
                    ctx->status_cnt = 0;
                    #pragma unroll
                    for (int r = 0; r < 8; r++) ctx->status_buf[r] = 0;
                }
            } else { // DATA or control frame: skip payload
                if (f_len > 0) ctx->state = 2;
            }
        } else {
            return 1;
        }
    }

    // FSM State 1: Status Code Header Inspection
    if (ctx->state == 1) {
        if (l->off >= l->len) return 1;
        __u32 wanted = 8;
        if (wanted > ctx->remaining) wanted = ctx->remaining;
        __u32 cnt = ctx->status_cnt & 0x07;
        __u32 needed = (wanted > cnt) ? (wanted - cnt) : 0;
        __u32 avail = l->len - l->off;
        __u32 to_copy = (avail < needed) ? avail : needed;
        asm volatile("" : "+r"(to_copy)); to_copy &= 0x0F;

        if (to_copy > 0) {
            void *src = l->virt + l->off;
            bpf_probe_read_kernel(&ctx->status_buf[cnt], to_copy, src);
            ctx->status_cnt += to_copy;
            ctx->remaining -= to_copy;
            l->off += to_copy;
        }

        if (ctx->status_cnt >= wanted) {
            __u16 stat = decode_h2_status(ctx->status_buf);
            if (stat == 200) {
                __u32 cpu = bpf_get_smp_processor_id();
                if (cpu < CPUS) {
                    __u32 idx = (cpu << STATUS_OK_SHIFT) | (ctx->le_id & STATUS_OK_MASK);
                    __u64 *metric = bpf_map_lookup_elem(&metrics_array, &idx);
                    // if (metric) (*metric)++;
                    /** NOTE: BPF provides migrate_disable(), but we do not have preempt_disable().
                     * A direct non-atomic increment ((*metric)++) is vulnerable to preemption races
                     * on the same logical CPU core under heavy load:
                     *  1. Thread A reads the metric value into a register.
                     *  2. Thread A gets preempted before writing it back.
                     *  3. Thread B runs on the same CPU, reads the same old value, increments, and writes it.
                     *  4. Thread A resumes, and its stale register value overwrites Thread B's update (lost update).
                     *
                     * Thanks to our per-CPU slot architecture, we completely avoid inter-core false sharing
                     * and cache-coherence bus traffic. However, to prevent this intra-core preemption race,
                     * we use an atomic operation here.
                     */
                    if (metric) __sync_fetch_and_add(metric, 1);
                }
            } else if (stat > 0) {
                struct error_event_t *ev = bpf_ringbuf_reserve(&error_events, sizeof(*ev), 0);
                if (ev) {
                    ev->le_id = ctx->le_id;
                    ev->status = stat;
                    ev->reserved = 0;
                    ev->timestamp_ns = bpf_ktime_get_ns();
                    bpf_ringbuf_submit(ev, 0);
                }
            }
            if (ctx->remaining > 0) { ctx->state = 2; }
            else { ctx->state = 0; }
        } else {
            return 1;
        }
    }

    // FSM State 2: Payload Skipping
    if (ctx->state == 2) {
        if (l->off >= l->len) return 1;
        __u32 avail = l->len - l->off;
        if (avail < ctx->remaining) {
            ctx->remaining -= avail;
            l->off = l->len;
            return 1;
        } else {
            l->off += ctx->remaining;
            ctx->remaining = 0;
            ctx->state = 0;
        }
    }

    if (l->off < l->len) return 0;
    return 1;
}

// BPF_PROG(trace_splice_to_socket): Entrypoint traced on kernel splice_to_socket.
// Iterates active pipe buffers between tail and head, maps physical pages to virtual addresses,
// and feeds bytes into the HTTP/2 FSM parser.
SEC("fentry/splice_to_socket")
int BPF_PROG(trace_splice_to_socket, struct pipe_inode_info *pipe, void *out, void *ppos, __u64 len, __u32 flags) {
    if (len == 0 || !pipe)
        return 0;

    __u32 tail = BPF_CORE_READ(pipe, tail);
    __u32 head = BPF_CORE_READ(pipe, head);
    __u32 ring_size = BPF_CORE_READ(pipe, ring_size);
    struct pipe_buffer *bufs = BPF_CORE_READ(pipe, bufs);
    if (!bufs || ring_size == 0)
        return 0;

    struct socket *sock = bpf_sock_from_file(out);
    if (!sock)
        return 0;
    struct sock *sk = sock->sk;
    if (!sk)
        return 0;

    __u64 cookie = bpf_get_socket_cookie(sk);
    struct session_ctx *s_ctx = bpf_map_lookup_elem(&session_map, &cookie);
    if (!s_ctx)
        return 0;

    __u64 struct_size = bpf_core_type_size(struct pipe_buffer);

    #pragma unroll
    for (int i = 0; i < 16; i++) {
        __u32 current_tail = tail + i;
        if (current_tail >= head) break;

        unsigned int idx = current_tail & (ring_size - 1);
        void *buf_ptr = (void *)bufs + (idx * struct_size);

        struct page *page = BPF_CORE_READ((struct pipe_buffer *)buf_ptr, page);
        __u32 offset = BPF_CORE_READ((struct pipe_buffer *)buf_ptr, offset);
        __u32 buf_len = BPF_CORE_READ((struct pipe_buffer *)buf_ptr, len);
        if (!page || buf_len == 0) continue;

        // IDEMPOTENCY / PARTIAL DRAIN PROTECTION:
        // When splice partial writes occur (downstream socket buffer full), drainRemainingSplice
        // re-invokes splice_to_socket on the same tail buffer with an advanced offset.
        // We skip already-parsed byte ranges to prevent duplicate status counting.
        __u32 skip = 0;
        if (s_ctx->initialized != 0 && current_tail == s_ctx->last_tail) {
            if (offset <= s_ctx->last_offset) {
                continue; // Entirely accounted for in previous pass
            }
            skip = offset - s_ctx->last_offset;
        } else if (s_ctx->initialized != 0 && current_tail < s_ctx->last_tail) {
            continue;
        }

        __u32 real_offset = offset;
        __u32 real_len = buf_len;

        void *virt = page_to_virt_kaslr(page) + real_offset;
        if (virt && real_len > 0) {
            struct loop_ctx l = {
                .virt = virt,
                .ctx = s_ctx,
                .len = real_len,
                .off = 0
            };
            current_bpf_loop(512, h2_parse_callback, &l, 0);
        }

        // Record parser progress
        s_ctx->last_tail = current_tail;
        s_ctx->last_offset = offset + buf_len;
        s_ctx->initialized = 1;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";