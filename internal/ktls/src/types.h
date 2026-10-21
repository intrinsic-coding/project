#ifndef KTLS_BRIDGE_H
#define KTLS_BRIDGE_H
#include <stdint.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Context represents the shared Cgo ABI bridge structure exchanged between Go and C.
// Padded to align cleanly across CPU cache lines and avoid false sharing.
typedef struct {
    uintptr_t sni_ptr;     // Pointer to null-terminated SNI C-string
    uint64_t  buf_ptr;     // Virtual memory address of scratch buffer
    int32_t   buf_cap;     // Capacity of scratch buffer
    int32_t   fd;          // Underlying socket file descriptor
    int32_t   pending_len; // Length of pre-read application bytes during handshake
    int32_t   rx_active;   // 1 if kernel RX kTLS offload is active, 0 otherwise
    int       status;      // 1 on successful handshake, 0 on failure
    uint8_t   pad[24];     // Padding to ensure 64-byte alignment
} Context;

// SSLBundle is a legacy container for SSL state pairs.
typedef struct {
    SSL *ssl;
    SSL_CTX *ctx;
} SSLBundle;

void init_ktls_server_ctx();
void init_ktls_client_ctx();
void do_ktls_dial(Context *ctx);
void do_ktls_server_handshake(Context *ctx);

#endif