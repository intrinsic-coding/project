.PHONY: all generate c-code go-build docker-build benchmark test clean check-deps certs

# Dynamic CPU detection and proportional load scaling
CORES := $(shell nproc)
BENCH_REQ := $(shell echo $$(($(CORES) * 50000 / 16)))
BENCH_CONNS := $(shell echo $(CORES))
OPENSSL_REPO := https://github.com/openssl/openssl/releases/download/openssl
OPENSSL_VERSION ?= 4.0.1
OPENSSL_DIR := ./internal/ktls/lib/openssl

all: check-deps certs generate c-code go-build
	@echo "Build completed successfully!"

check-deps:
	@echo "Checking system prerequisites..."
	@bash -c '\
		set -e; \
		for cmd in clang gcc curl openssl go; do \
			if ! command -v "$$cmd" &>/dev/null; then \
				echo "Error: required program '\''$$cmd'\'' not found." >&2; \
				exit 1; \
			fi; \
		done; \
		if [ ! -f /usr/include/bpf/bpf.h ] && [ ! -f /usr/local/include/bpf/bpf.h ]; then \
			echo "Error: BPF development headers not found in /usr/include/bpf/!" >&2; \
			echo "Hint: Install them on Debian/Ubuntu via:" >&2; \
			echo " sudo apt-get update && sudo apt-get install -y libbpf-dev linux-libc-dev clang llvm" >&2; \
			exit 1; \
		fi; \
		echo "All system dependencies and BPF headers verified successfully." \
	'

certs:
	@if [ ! -f certs/server.crt ] || [ ! -f certs/server.key ]; then \
		echo "Generating modern ECDSA TLS certificates (secp384r1)..."; \
		mkdir -p certs; \
		openssl ecparam -genkey -name secp384r1 -noout -out certs/server.key; \
		openssl req -new -x509 -sha256 -key certs/server.key -out certs/server.crt -days 365 \
			-subj "/CN=balancer-proxy"; \
	fi

$(OPENSSL_DIR)/libssl.a:
	@echo "Downloading and building OpenSSL $(OPENSSL_VERSION) locally (no system installation)..."
	@rm -rf /tmp/openssl-src && mkdir -p /tmp/openssl-src
	@curl -sL $(OPENSSL_REPO)-$(OPENSSL_VERSION)/openssl-$(OPENSSL_VERSION).tar.gz \
		| tar -xz -C /tmp/openssl-src --strip-components=1
	@cd /tmp/openssl-src && CFLAGS="-w" ./config \
		enable-ktls no-shared no-tls1 no-tls1_1 no-tls1_2 no-dtls no-dtls1 no-dtls1_2 no-weak-ssl-ciphers \
		no-deprecated no-psk no-srp no-ec2m no-legacy no-comp no-async no-tests no-filenames no-ui-console \
		no-aria no-bf no-blake2 no-camellia no-cast no-des no-idea no-md2 no-md4 \
		no-rc2 no-rc4 no-rmd160 no-seed no-sm2 no-sm3 no-sm4 no-siphash no-whirlpool \
		-O3 -fno-asynchronous-unwind-tables
	@cd /tmp/openssl-src && make -j$$(nproc) build_libs > /dev/null
	@mkdir -p $(OPENSSL_DIR)/include
	@cp -r /tmp/openssl-src/include/openssl $(OPENSSL_DIR)/include/
	@cp /tmp/openssl-src/libssl.a /tmp/openssl-src/libcrypto.a $(OPENSSL_DIR)/
	@rm -rf /tmp/openssl-src
	@echo "OpenSSL static libraries built and placed successfully in $(OPENSSL_DIR)"

generate:
	@echo "Running code generator..."
	go run internal/routes/generator.go

update-build-time:
	sed -i 's|// BuildTime: .*|// BuildTime: '"$(shell date +%s)"'|' main.go

c-code: $(OPENSSL_DIR)/libssl.a update-build-time
	@echo "Compiling C components..."
	clang -target bpf -O2 -g -c ./internal/ebpf/src/bpf_h2_parser.c -o ./internal/ebpf/lib/bpf_h2_parser.o
	gcc -O2 -fPIC -I. -I./internal/ktls/lib/openssl/include -no-pie \
		-DLB_CERT_PATH='"./certs/server.crt"' \
		-DLB_KEY_PATH='"./certs/server.key"' \
		-c internal/ktls/src/downstream.c -o internal/ktls/lib/downstream.o
	gcc -O2 -fPIC -I. -I./internal/ktls/lib/openssl/include \
		-c internal/ktls/src/upstream.c -o internal/ktls/lib/upstream.o

go-build:
	@echo "Building Go binary..."
	CGO_CFLAGS="-I./internal/ktls/lib/openssl/include" \
	CGO_LDFLAGS="./internal/ktls/lib/openssl/libssl.a ./internal/ktls/lib/openssl/libcrypto.a -lpthread" \
	go build -ldflags="-linkmode=external -s -w" -o proxy .

docker-build: certs
	@bash -c '\
		set -e; \
	  	if ! command -v docker &>/dev/null; then \
			echo "Error: required program docker not found." >&2; \
			exit 1; \
		fi; \
	'
	@echo "Building all proxy and test containers from tests/..."
	docker build --network=host -t balancer-proxy:latest .
	docker build --network=host -t mock-backend:latest -f tests/Dockerfile.mockserver .
	docker build --network=host -t nginx-bench:latest -f tests/Dockerfile.nginx .
	docker build --network=host -t h2load-runner:latest -f tests/Dockerfile.h2load .

benchmark:
	@echo "RUNNING AUTOMATED BENCHMARK SUITE"
	@echo "Detected Cores : $(CORES)"
	@echo "Scaled Requests: $(BENCH_REQ)"
	@echo "Concurrency    : $(BENCH_CONNS)"
	@echo -n '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' > tests/body.json
	@bash -c '\
		set -e; \
		conns=$(CORES); \
		\
		docker stop balancer-proxy mock-backend nginx-bench 2>/dev/null || true; \
		docker rm balancer-proxy mock-backend nginx-bench 2>/dev/null || true; \
		\
		echo "[1/2] NGINX Baseline Benchmark"; \
		docker run -d --name mock-backend --network=host mock-backend:latest; \
		docker run -d --name nginx-bench --network=host nginx-bench:latest; \
		sleep 2; \
		\
		echo "Executing h2load against NGINX..."; \
		docker run --rm --network=host \
			-v $(PWD)/tests/body.json:/body.json:ro \
			h2load-runner:latest \
			-n $(BENCH_REQ) -c $$conns -m $(BENCH_REQ) -t $$conns \
			-H "content-type: application/json" -d /body.json \
			https://127.0.0.1:8443/solana && h2load --version; \
		\
		docker stop nginx-bench mock-backend 2>/dev/null || true; \
		docker rm nginx-bench mock-backend 2>/dev/null || true; \
		\
		echo "[2/2] Balancer-Proxy Benchmark"; \
		docker run -d --name mock-backend --network=host mock-backend:latest; \
		docker run -d -v "${PWD}/tests/hosts:/etc/hosts:ro" --name balancer-proxy \
			--network=host --privileged --security-opt apparmor=unconfined balancer-proxy:latest; \
		sleep 3; \
		\
		echo "Executing h2load against Balancer-Proxy..."; \
		docker run --rm --network=host \
			-v $(PWD)/tests/body.json:/body.json:ro \
			h2load-runner:latest \
			-n $(BENCH_REQ) -c $$conns -m $(BENCH_REQ) -t $$conns \
			-H "content-type: application/json" -d /body.json \
			https://127.0.0.1:8443/solana; \
		\
		docker stop balancer-proxy mock-backend && docker rm balancer-proxy mock-backend; \
		\
		echo "BENCHMARK FINISHED!"; \
		rm $(PWD)/tests/body.json; \
	'

test:
	@echo "Running unit tests..."
	go test -v -race ./internal/...

clean:
	rm -f proxy internal/ebpf/lib/bpf_h2_parser.o internal/ktls/lib/*.o
	docker stop balancer-proxy mock-backend 2>/dev/null || true
	docker rm balancer-proxy mock-backend 2>/dev/null || true