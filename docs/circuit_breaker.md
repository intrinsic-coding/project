# Fault Tolerance, Quarantine, and Health Checking

## 1. Failure Isolation Levels

The gateway distinguishes between transport-level failures and application-level errors:
- **L4 (Transport Layer):** Connection establishment failures (Dial errors) are handled by MarkDeadL4, isolating the affected IP address. 
The TCP_USER_TIMEOUT socket option (set to 2,000 ms) forces the termination of TCP connections when transmitted data remains unacknowledged beyond the configured timeout.
- **L7 (Application Layer):** Gateway errors and rate-limiting responses (408, 429, 502, 503, 504) are handled by HandleL7Error.

## 2. Group-Based Host Quarantine (Circuit Breaker)

Upon receiving a 429 or 5xx response, the proxy avoids sequentially retrying the remaining IP addresses associated with the same provider. 
Instead, it applies a group-level quarantine:
- Identifies the group by evaluating the combination of ChainID, SniPtr, and Path.
- Transitions all logical entities associated with the exact endpoint tuple to StateUnhealthy for a specified cooldown period, 
immediately directing new connections to backup providers.

## 3. Background Health Checker

An independent background worker periodically checks quarantined targets:

- **IP Addresses:** Connectivity is verified using a lightweight TCP connection and TLS handshake.
- **Logical Entities:** Health is verified using lightweight JSON-RPC probes (ProbePayload) dispatched to modular chain drivers (internal/chains/).
- Upon receiving a successful response, the corresponding target is restored to StateHealthy.