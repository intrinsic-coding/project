#
# Stage 1: Build Custom Minimal OpenSSL with kTLS Support
#
FROM debian:bookworm AS openssl-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc make perl curl ca-certificates libc6-dev \
    && rm -rf /var/lib/apt/lists/*

ARG OPENSSL_VERSION=4.0.1

WORKDIR /tmp/openssl-src

RUN curl -sL https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz \
    | tar -xz --strip-components=1

RUN ./config \
        enable-ktls no-shared no-tls1 no-tls1_1 no-tls1_2 no-dtls no-dtls1 no-dtls1_2 no-weak-ssl-ciphers \
        no-deprecated no-psk no-srp no-ec2m no-legacy no-comp no-async no-tests no-filenames no-ui-console \
        no-aria no-bf no-blake2 no-camellia no-cast no-des no-idea no-md2 no-md4 \
        no-rc2 no-rc4 no-rmd160 no-seed no-sm2 no-sm3 no-sm4 no-siphash no-whirlpool \
        -O3 -fno-asynchronous-unwind-tables

RUN make -j$(nproc) build_libs

RUN mkdir -p /out/openssl/include && \
    cp -r include/openssl /out/openssl/include/ && \
    cp libssl.a libcrypto.a /out/openssl/

#
# Stage 2: Build Balancer-Proxy (Go + C kTLS + eBPF)
#
FROM debian:bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm gcc make libc6-dev libelf-dev libbpf-dev linux-libc-dev curl ca-certificates file \
    && rm -rf /var/lib/apt/lists/*

ENV GOLANG_VERSION=1.26.4
RUN curl -L https://golang.org/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH=$PATH:/usr/local/go/bin

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

COPY --from=openssl-builder /out/openssl/include/ /app/internal/ktls/lib/openssl/include/
COPY --from=openssl-builder /out/openssl/libssl.a /app/internal/ktls/lib/openssl/libssl.a
COPY --from=openssl-builder /out/openssl/libcrypto.a /app/internal/ktls/lib/openssl/libcrypto.a

RUN go run internal/routes/generator.go

RUN clang -target bpf -O2 -g -I/usr/include/$(uname -m)-linux-gnu -I/usr/include \
    -c ./internal/ebpf/src/bpf_h2_parser.c -o ./internal/ebpf/lib/bpf_h2_parser.o && \
    gcc -O2 -fPIC -I. -I./internal/ktls/lib/openssl/include -no-pie \
        -DLB_CERT_PATH='"./certs/server.crt"' -DLB_KEY_PATH='"./certs/server.key"' \
        -c internal/ktls/src/downstream.c -o internal/ktls/lib/downstream.o && \
    gcc -O2 -fPIC -I. -I./internal/ktls/lib/openssl/include \
        -c internal/ktls/src/upstream.c -o internal/ktls/lib/upstream.o

RUN CGO_CFLAGS="-I./internal/ktls/lib/openssl/include" \
    CGO_LDFLAGS="./internal/ktls/lib/openssl/libssl.a ./internal/ktls/lib/openssl/libcrypto.a -lpthread -ldl" \
    CGO_ENABLED=1 \
    go build -tags netgo -ldflags='-linkmode external -extldflags "-static" -s -w' -o proxy .

RUN echo "nameserver 8.8.8.8" > /tmp/resolv.conf

#
# Stage 3: Minimal Distroless Production Image
#
FROM scratch AS proxy-image
WORKDIR /
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /tmp/resolv.conf /etc/resolv.conf
COPY --from=builder /app/proxy /proxy
COPY --from=builder /app/config.json /config.json
COPY --from=builder /app/certs /certs
COPY --from=builder /app/internal/ebpf/lib/bpf_h2_parser.o /internal/ebpf/lib/bpf_h2_parser.o

EXPOSE 8443 9090
ENTRYPOINT ["/proxy"]