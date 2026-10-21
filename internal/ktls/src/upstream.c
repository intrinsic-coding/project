#define _GNU_SOURCE
#include "types.h"

// Singleton OpenSSL client context shared across all upstream dials.
// Reusing a single SSL_CTX avoids heavy heap allocations and context recompilation on every connection.
static SSL_CTX *global_cli_ctx = NULL;

// init_ktls_client_ctx initializes OpenSSL client state once at startup:
// - Enables Kernel TLS (SSL_OP_ENABLE_KTLS).
// - Explicitly disables internal session caching (SSL_SESS_CACHE_OFF) to prevent multi-threaded lock
//   contention and memory corruption when multiple goroutines dial different SNIs concurrently.
// - Configures compile-time certificate verification toggles (dev vs. prod).
// - Configures HTTP/2 ALPN ("h2") globally.
void init_ktls_client_ctx() {
    if (global_cli_ctx != NULL) {
        return;
    }

    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    global_cli_ctx = SSL_CTX_new(TLS_client_method());
    if (!global_cli_ctx) {
        fprintf(stderr, "[C-ERROR] Failed to create global client SSL_CTX\n");
        return;
    }

    // 1. Enable Kernel TLS offload.
    SSL_CTX_set_options(global_cli_ctx, SSL_OP_ENABLE_KTLS);

    // 2. Disable session caching to ensure lock-free concurrent dials across threads.
    SSL_CTX_set_session_cache_mode(global_cli_ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(global_cli_ctx, SSL_OP_NO_TICKET);

    // 3. Certificate verification mode toggle (configured via Makefile -DVERIFY_PEER).
    #ifdef VERIFY_PEER
        SSL_CTX_set_default_verify_paths(global_cli_ctx);
        SSL_CTX_load_verify_locations(global_cli_ctx, "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs");
        SSL_CTX_set_verify(global_cli_ctx, SSL_VERIFY_PEER, NULL);
    #else
        SSL_CTX_set_verify(global_cli_ctx, SSL_VERIFY_NONE, NULL);
    #endif

    // 4. Enforce HTTP/2 ALPN negotiation across all upstream handshakes.
    static const unsigned char alpn[] = { 2, 'h', '2' };
    SSL_CTX_set_alpn_protos(global_cli_ctx, alpn, sizeof(alpn));
}

// setup_base_ktls allocates an SSL handle from the global client context, binds it to the socket fd,
// configures SNI, sets non-blocking timeouts, and executes the client-side TLS handshake.
static SSL* setup_base_ktls(int fd, const char* target_sni) {
    if (!global_cli_ctx) {
        fprintf(stderr, "[C-ERROR] global_cli_ctx is not initialized\n");
        return NULL;
    }

    struct timeval tv = {1, 500000}; // 1.5s handshake timeout
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ERR_clear_error(); // Clear thread-local OpenSSL error queue

    SSL *ssl = SSL_new(global_cli_ctx);
    if (!ssl) {
        return NULL;
    }

    // Disable read-ahead buffer so OpenSSL does not buffer HTTP/2 response frames meant for kernel splice.
    SSL_set_read_ahead(ssl, 0);
    SSL_set_tlsext_host_name(ssl, target_sni);
    SSL_set_fd(ssl, fd);

    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        return NULL;
    }

    #ifdef VERIFY_PEER
        if (SSL_get_verify_result(ssl) != X509_V_OK) {
            fprintf(stderr, "[C-WARN] TLS cert verify failed for SNI: %s (code: %ld)\n",
                    target_sni, SSL_get_verify_result(ssl));
            SSL_free(ssl);
            return NULL;
        }
    #endif

    // Reset timeouts back to default.
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return ssl;
}

// do_ktls_dial establishes the upstream TLS connection, transmits the HTTP/2 connection preface,
// reads initial server settings into the scratch buffer, and verifies kernel kTLS RX activation.
void do_ktls_dial(Context *ctx) {
    SSL *ssl = setup_base_ktls(ctx->fd, (const char*)ctx->sni_ptr);
    if (ssl) {
        // Send initial HTTP/2 client connection preface.
        SSL_write(ssl, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);

        // Read server's initial HTTP/2 frames (e.g. SETTINGS) into buffer.
        ctx->pending_len = SSL_read(ssl, (void*)ctx->buf_ptr, ctx->buf_cap);
        BIO *rbio = SSL_get_rbio(ssl);
        if (rbio && BIO_get_ktls_recv(rbio)) {
            ctx->rx_active = 1;
        }
        ctx->status = 1;

        // Decouple fd from SSL object before freeing to keep kTLS kernel socket operational.
        SSL_set_fd(ssl, -1);
        SSL_free(ssl);

        // Switch socket to non-blocking mode for Go netpoller and splice.
        ioctl(ctx->fd, FIONBIO, &ctx->status);
    } else {
        ctx->status = 0;
    }
}