# Cilium Zero Trust Policy Visualizer

## What problem is it solving?
The project is a mini, Cilium-inspired lab that answers:

# “If I enforce Zero Trust network policies with eBPF, what exactly is being allowed and denied, and can I see it live?”

So it focuses on:
Zero Trust: default deny; only explicitly allowed flows are permitted.
eBPF/XDP: enforcing rules directly in the kernel as early as possible (before the normal network stack).
Visualization: giving a UI + API to see which flows are allowed/denied in real time.

---

## 1. Repository Layout

```text
cilium-zero-trust-policy-visualizer/
├── ebpf/
│   ├── zt_policy_kern.c         # XDP eBPF program
│   └── zt_policy_common.h       # Shared maps & structs
├── user/
│   ├── loader.py                # BCC-based loader + Flask API
│   └── config/
│       └── policy.yaml          # Zero Trust policy rules
├── webui/
│   ├── index.html               # Frontend (tables)
│   ├── styles.css
│   └── app.js
├── scripts/
│   └── demo.sh                  # One-shot local demo script
├── docker/
│   └── Dockerfile               # Container image
├── k8s/
│   └── daemonset.yaml           # DaemonSet manifest
└── docs/
    ├── architecture.md
    └── architecture_diagram.txt
```

---

## 2. Concept: Zero Trust via eBPF

- Default stance: **deny all traffic** unless explicitly allowed.
- The **eBPF program** is attached at the **XDP** hook on a given interface.
- A `policy_map` defines allowed flows; anything else is denied.
- Every packet is classified as allowed/denied and counters are stored in `stats_map`.
- The **user-space loader** reads these maps and exposes them as JSON, which the **Web UI** renders.

---

## 3. eBPF Program (Kernel Space)

File: `ebpf/zt_policy_kern.c`

Key points:

- Runs as an XDP program (`SEC("xdp") int xdp_zt_policy(...)`).
- Parses **Ethernet → IPv4 → TCP/UDP** headers.
- Builds a `flow_key` and looks up `policy_map`.
- Updates `stats_map` with allowed/denied counters.
- Returns `XDP_PASS` for allowed or **`XDP_DROP` for denied** traffic.

The shared structs and BPF maps are defined in `ebpf/zt_policy_common.h`.

---

## 4. User-Space Loader & REST API

File: `user/loader.py`

Responsibilities:

1. **Load & attach eBPF:**
   - Uses `bcc.BPF` to compile `zt_policy_kern.c`.
   - Attaches it as XDP on the specified interface.

2. **Load Zero Trust policy rules:**
   - Reads YAML file `user/config/policy.yaml`.
   - Populates `policy_map` in the kernel.
   - Simple example:

   ```yaml
   rules:
     - src_ip: 10.0.0.10
       dst_ip: 10.0.0.20
       dst_port: 80
       proto: tcp
       action: allow
   ```

3. **Expose REST API (Flask):**
   - `GET /api/policy` → current policy entries.
   - `GET /api/flows`  → flow statistics (allowed / denied counters).

---

## 5. Web UI (Optional but Included)

Directory: `webui/`

- `index.html` + `app.js` + `styles.css`.
- Uses `fetch()` to call:
  - `/api/policy`
  - `/api/flows`
- Renders tables with:
  - Source / destination IPs
  - Ports
  - Protocol
  - Action (allow/deny)
  - Allowed & denied counts.

You can serve it behind the same Flask app (e.g., via reverse proxy or by adding static file handlers).

---

## 6. Local Execution (Bare Metal / VM)

### 6.1. Prerequisites

- Linux host with:
  - Root privileges
  - Modern kernel with eBPF/XDP support
- Packages:

```bash
sudo apt-get update
sudo apt-get install -y   python3 python3-pip clang llvm libbpf-dev linux-headers-$(uname -r)   bpfcc-tools iproute2
pip3 install bcc flask pyyaml
```

Clone the repo structure into a directory, e.g.:

```bash
git clone http:/github/zareen1729/cilium-zero-trust-policy-visualizer
cd cilium-zero-trust-policy-visualizer
```

### 6.2. Run the Demo Script

```bash
sudo ./scripts/demo.sh eth0
```

What it does:

1. Launches `loader.py` (which loads & attaches XDP, populates policy, starts Flask on `:8080`).
2. Shows a message with the loader PID.
3. You can then browse to:

   - `http://localhost:8080/api/policy`
   - `http://localhost:8080/api/flows`

   and/or open `webui/index.html` and point it at the same host.

4. Press Enter to cleanly stop the loader.

---

## 7. Running Dockerized

> Note: eBPF / XDP in a container requires **privileged mode** and access to `/sys/fs/bpf`.  

### 7.1. Build Image

From the project root:

```bash
cd docker
docker build -t cilium-zero-trust-visualizer:latest .
```

### 7.2. Run Container

```bash
docker run --rm -it   --name cztv   --privileged   --net=host   -v /sys/fs/bpf:/sys/fs/bpf   cilium-zero-trust-visualizer:latest
```

This will:

- Attach the XDP program on `eth0` (inside the container / host).
- Start Flask API on `http://localhost:8080`.

---

## 8. Kubernetes Deployment (DaemonSet)

File: `k8s/daemonset.yaml`

Basic idea:

- Run one instance per node.
- Attach the eBPF program on `eth0` on each node.
- Expose port `8080` for each node (for UI / metrics).
- Uses `hostNetwork: true`, `hostPID: true`, and `privileged: true` because of XDP.

### 8.1. Steps

1. Build and push your image:

```bash
cd docker
docker build -t <your-registry>/cilium-zero-trust-visualizer:latest .
docker push <your-registry>/cilium-zero-trust-visualizer:latest
```

2. Edit `k8s/daemonset.yaml` and set:

```yaml
image: <your-registry>/cilium-zero-trust-visualizer:latest
```

3. Apply in your cluster:

```bash
kubectl apply -f k8s/daemonset.yaml
```

4. Access per-node UI via:

```bash
kubectl get pods -o wide -l app=cilium-zero-trust-visualizer
# Then port-forward from a chosen node-pod or use a Service.
```

---

## 9. Notes & Limitations

- Only **IPv4 + TCP/UDP** flows are parsed.
- `policy.yaml` currently supports only exact IP matches (no CIDR expansion).
- Error handling, scalability and security hardening are intentionally simplified.

---

## 10. Extending Toward Cilium

To bring this closer to a real Cilium integration:

- Pull policies from **Cilium CRDs** (K8s) instead of a local YAML file.
- Use **cilium/ebpf** or libbpf-based loaders instead of BCC for production.
- Integrate with **Hubble** flow events rather than direct map reads.
- Add graph visualizations (e.g., D3.js) to show service-to-service Zero Trust topology.

---
