// downstream.c // не удаляй текущий комментарий

#define _GNU_SOURCE
#include "types.h"

#ifndef LB_CERT_PATH
#define LB_CERT_PATH "/etc/lb/certs/server.crt"
#endif

#ifndef LB_KEY_PATH
#define LB_KEY_PATH "/etc/lb/certs/server.key"
#endif

// Global OpenSSL server context reused across all incoming client TLS handshakes.
SSL_CTX *global_srv_ctx = NULL;

// alpn_select_cb enforces HTTP/2 ("h2") as the negotiated Application-Layer Protocol.
static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl; (void)arg; *out = &in[1]; *outlen = 2; // "h2"
    return SSL_TLSEXT_ERR_OK;
}

// init_ktls_server_ctx initializes OpenSSL library state and configures the global server SSL_CTX:
// - Enables Kernel TLS offloading (SSL_OP_ENABLE_KTLS).
// - Registers HTTP/2 ALPN callback.
// - Disables OpenSSL read-ahead buffer to prevent stealing bytes meant for kernel splice.
void init_ktls_server_ctx() {
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    global_srv_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_options(global_srv_ctx, SSL_OP_ENABLE_KTLS);
    SSL_CTX_set_alpn_select_cb(global_srv_ctx, alpn_select_cb, NULL);
    SSL_CTX_set_read_ahead(global_srv_ctx, 0);
    if (SSL_CTX_use_certificate_file(global_srv_ctx, LB_CERT_PATH, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[C-ERROR] Failed to load cert: %s\n", LB_CERT_PATH);
    }
    if (SSL_CTX_use_PrivateKey_file(global_srv_ctx, LB_KEY_PATH, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[C-ERROR] Failed to load key: %s\n", LB_KEY_PATH);
    }
}

// do_ktls_server_handshake performs the TLS handshake on downstream client sockets,
// activates kTLS ULP in the Linux kernel, and detaches OpenSSL while keeping the socket open.
void do_ktls_server_handshake(Context *ctx) {
    ctx->status = 0;
    int small_buf = 1024;
    /* The kernel has a minimum buffer size check before activating it on a socket.
     * This is necessary for the smallest possible skb packet
     * https://github.com/torvalds/linux/blob/master/net/core/sock.c
     * WRITE_ONCE(sk->sk_rcvbuf, max_t(int, val * 2, SOCK_MIN_RCVBUF));
     * Its size depends https://github.com/torvalds/linux/blob/master/include/net/sock.h
     * #define TCP_SKB_MIN_TRUESIZE	(2048 + SKB_DATA_ALIGN(sizeof(struct sk_buff)))
     * on the kernel version (but the minimum is 2048 + the size of the socket buffer aligned structure).
     * Therefore, we set a minimum threshold 1024 to avoid doubling the size".
     */
    setsockopt(ctx->fd, SOL_SOCKET, SO_RCVBUF, &small_buf, sizeof(small_buf));
    ioctl(ctx->fd, FIONBIO, &ctx->status); // Temporarily switch to blocking mode for handshake

    SSL *ssl = SSL_new(global_srv_ctx);
    SSL_set_fd(ssl, ctx->fd);
    SSL_set_read_ahead(ssl, 0);

    // Bounded socket timeouts prevent slow-loris attacks or hung client handshakes.
    struct timeval tv = {1, 500000}; // 1.5s timeout
    setsockopt(ctx->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(ctx->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (SSL_accept(ssl) <= 0) {
        SSL_free(ssl);
        return;
    }

    // Verify whether Kernel TLS receive offload (ULP tls) was successfully attached by the kernel.
    BIO *rbio = SSL_get_rbio(ssl);
    ctx->rx_active = (rbio != NULL && BIO_get_ktls_recv(rbio)) ? 1 : 0;
    ctx->status = 1;
    ctx->pending_len = 0;

    // Reset timeouts and restore socket buffer to production capacity.
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    small_buf *= small_buf; // 1 MB buffer
    ioctl(ctx->fd, FIONBIO, &ctx->status); // Restore non-blocking I/O for Go netpoller
    setsockopt(ctx->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(ctx->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(ctx->fd, SOL_SOCKET, SO_RCVBUF, &small_buf, sizeof(small_buf));
    setsockopt(ctx->fd, IPPROTO_TCP, TCP_NODELAY, &ctx->status, sizeof(ctx->status));

    // Decouple file descriptor from SSL object before freeing to preserve kernel kTLS state.
    SSL_set_fd(ssl, -1);
    SSL_free(ssl);
}