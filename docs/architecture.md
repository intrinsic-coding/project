# Data Plane Architecture and Routing

## 1. Asymmetric Data Plane
In traditional proxies, both inbound and outbound traffic pass through application userspace buffers, incurring the overhead of `read`/`write` system calls and userspace TLS encryption/decryption.

`balancer-proxy` implements a hybrid approach:
1. **Inbound Path (Client -> Proxy):** The socket is terminated directly inside the Linux kernel via `kTLS` (`TCP_ULP`). Go reads the headers of the initial HTTP/2 frame (`MetaHeadersFrame`), resolves the target path (`:path`), selects an upstream endpoint using the "Snake" (Host Interleaving) algorithm, and rewrites pseudo-headers (`:authority`, `:path`).
2. **Outbound Path (Proxy -> Backend -> Client):** After establishing an upstream connection, Go spawns a background streaming worker that forwards data in 1 MB blocks using `unix.Splice`:
   `Upstream Socket -> Kernel Pipe (pipe_buffer) -> Downstream Socket`
   The response payload never enters userspace.

## 2. In-Kernel Telemetry (eBPF)
To collect metrics without compromising `splice` throughput:
- An eBPF program is attached via an `fentry` probe to the kernel function `splice_to_socket`.
- During pipe page transfers, the eBPF program executes an inline HTTP/2 finite-state-machine (FSM) parser, decoding HPACK headers (static table entries and literals).
- Successful responses (200 OK) atomically increment counters within `metrics_array` (a `BPF_MAP_TYPE_ARRAY` map initialized with `BPF_F_MMAPABLE`).
- Errors (429, 5xx) are submitted to userspace via a `BPF_MAP_TYPE_RINGBUF` to trigger circuit breaker quarantine procedures.

## 3. Static Arenas and RCU Snapshots
To eliminate heap allocations and reduce GC pressure on hot execution paths:
- IP address arrays (`AllIps`) and logical entities (`LogicalEntities`) are statically pre-allocated at startup.
- Topology updates (such as DNS re-resolutions) never mutate existing structures. Instead, a new `RoutingState` object containing only the active chain index generations (`ChainGeneration`) is constructed and published atomically via an `atomic.Pointer[RoutingState]`.


```mermaid
flowchart TD
    classDef goStep fill:#1e1b4b,stroke:#6366f1,stroke-width:2px,color:#fff;
    classDef cKtls fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#fff;
    classDef bpfHook fill:#451a03,stroke:#f59e0b,stroke-width:2px,color:#fff;
    classDef bpfBranch fill:#374151,stroke:#9ca3af,stroke-width:2px,color:#fff;

    C1["<b>1. Client Connect</b><br/>Inbound client TCP accepted in Go runtime (net.Listen)"]:::goStep
    
    C2["<b>2. C-kTLS Downstream Handshake</b><br/>OpenSSL Cgo: Server TLS handshake -> Enables kTLS (RX/TX) on socket"]:::cKtls
    
    C3["<b>3. Routing & Header Rewrite (Go)</b><br/>Parse HTTP/2 MetaHeadersFrame -> Resolve route from RCU topology -> Rewrite :authority and :path"]:::goStep
    
    C4["<b>4. Upstream TCP Dial</b><br/>Non-blocking L4 connect with kernel TCP_USER_TIMEOUT (RFC 5482)"]:::goStep
    
    C5["<b>5. C-kTLS Upstream Handshake</b><br/>OpenSSL Cgo: Client TLS handshake -> Send H2 Preface -> Activate upstream kTLS"]:::cKtls
    
    C6["<b>6. Zero-Copy Splice Worker</b><br/>Spawn background streaming worker SpliceUpstreamToDownstream()"]:::goStep
    
    C7["<b>7. Upstream RPC Response</b><br/>Backend node streams encrypted HTTP/2 frames into upstream socket"]:::cKtls
    
    C8["<b>8. Kernel splice(2) Pipeline</b><br/>unix.Splice transfers bytes: Upstream Socket -> Pipe Buffer (pipe_buffer) -> Client Socket"]:::cKtls

    C9{"<b>9. Inline eBPF Hook (fentry/splice_to_socket)</b><br/>Triggered during pipe-to-socket transfer:<br/>Decodes HTTP/2 status codes directly from pipe_buffer pages"}:::bpfHook

    C10A["<b>Status == 200 OK</b><br/>Atomic increment in per-CPU metrics_array<br/>(Zero-copy RPS & Total counters)"]:::bpfBranch

    C10B["<b>Status != 200 (429, 5xx)</b><br/>Submit structured event to BPF RingBuffer<br/>-> Go HandleL7Error -> Cluster-wide group quarantine"]:::bpfBranch

    C11["<b>10. Zero-Copy Delivery</b><br/>Frames encrypted by kernel kTLS and delivered to client with 0 userspace context switches!"]:::goStep

    C1 --> C2
    C2 --> C3
    C3 --> C4
    C4 --> C5
    C5 --> C6
    C6 --> C7
    C7 --> C8
    C8 --> C9
    C9 -->|200 OK| C10A
    C9 -->|Errors| C10B
    C10A --> C11
    C10B --> C11
```