# Cilium Zero Trust Policy Visualizer

## High-Level Architecture

The project implements a simplified, Cilium-inspired Zero Trust network policy visualizer:

1. **eBPF Layer (XDP)**  
   - `zt_policy_kern.c` is attached as an XDP program on a given interface.  
   - Parses IPv4 + TCP/UDP headers.  
   - Enforces a *default-deny* Zero Trust policy using a `policy_map`.  
   - Records per-flow statistics (allowed / denied counters) in `stats_map`.

2. **User-Space Loader & API (`loader.py`)**  
   - Uses BCC to load and attach the eBPF program.  
   - Loads policy rules from `config/policy.yaml` into `policy_map`.  
   - Periodically reads `stats_map` and exposes REST endpoints:
     - `GET /api/policy` – current Zero Trust rules
     - `GET /api/flows`  – observed flows + allowed / denied counts

3. **Web UI (`webui/`)**  
   - Simple SPA using vanilla JS + HTML.  
   - Polls `/api/policy` and `/api/flows` every few seconds.  
   - Displays a live table of rules and flows.

4. **Container & K8s**  
   - `docker/Dockerfile` packages loader + web UI.  
   - `k8s/daemonset.yaml` deploys a privileged DaemonSet that:
     - Attaches the XDP program on each node
     - Exposes the REST + Web UI on port 8080.

This provides an end-to-end path:
> Traffic -> eBPF (XDP) -> BPF maps -> loader.py (REST API) -> Web UI (browser)
