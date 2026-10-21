# Roadmap

1. **Eliminating Hardcoded Values:** Refactoring all remaining hardcoded parameters to be dynamically driven by configuration.
---
2. **Dynamic Limit Calculation (Data-Driven Compilation):** In the current implementation, the capacities of static arenas (MaxIPs = 256, MaxLEs = 512) are defined as constants. The plan is to move their calculation into the code generator (internal/routes/generator.go), which will parse config.json during the go generate phase and automatically determine arena capacities and eBPF bitmask shifts based on the exact number of configured nodes, eliminating hardcoded limits.
---
3. **Block Lag Monitoring:** Activating block-height tracking via ProbeResult.Height in chain drivers to automatically exclude lagging nodes from the active rotation.
---
4. **Management Control Plane:** Introducing an administrative control plane and dashboard for managing configurations, runtime containers, processes, and worker threads, integrated with the hot-reload mechanism described in Step 5.
---
5. **Hot Configuration Reload:** Enabling zero-downtime configuration updates, including host changes and the dynamic addition of blockchain networks, without restarting the process. Node topologies will be recalculated dynamically using standard RCU mechanisms and atomic pointer swaps. Additionally, replacing standard Go plugins with direct shared-library (.so) loading via dlopen, with safe unloading enabled by intercepting __cxa_thread_atexit_impl to prevent segmentation faults caused by dangling thread-local pointers.
---
6. **Anomaly Detection in Data Frames (Small HTTP 200 OK Responses):** Periodically sampling and inspecting suspiciously small HTTP 200 OK responses to detect cases where an upstream node returns HTTP 200 while embedding JSON-RPC error messages, such as node synchronization errors, etc.
---
7. **XDP-Based Packet Routing:** Exploring the use of eXpress Data Path (XDP) for bare-metal packet steering under extremely high client-to-backend traffic loads, with periodic flow sampling, inspired by the architecture of the Katran load balancer.