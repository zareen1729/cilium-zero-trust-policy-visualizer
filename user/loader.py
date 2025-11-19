#!/usr/bin/env python3

"""
user/loader.py

User-space loader for the Zero Trust Policy Visualizer.

Responsibilities:
- Load and attach the XDP eBPF program to an interface
- Populate the policy map from a YAML config
- Periodically read stats and expose them over a REST API for the web UI

Requirements (Ubuntu/Debian):
    sudo apt-get install bpfcc-tools libbpf-dev linux-headers-$(uname -r)
    pip install bcc flask pyyaml

Run:
    sudo python3 loader.py --iface eth0 --policy ./config/policy.yaml
"""

import argparse
import ipaddress
import socket
import threading
import time

from bcc import BPF
from flask import Flask, jsonify
import yaml

EBPF_SOURCE_FILE = "../ebpf/zt_policy_kern.c"

app = Flask(__name__)
bpf = None
policy_map = None
stats_map = None

def ipv4_to_int(ip_str: str) -> int:
    return int(ipaddress.IPv4Address(ip_str))

def port_to_be16(port: int) -> int:
    # network byte order
    return socket.htons(port)

def load_policy(policy_file: str):
    """
    policy.yaml example:

    rules:
      - src_ip: 10.0.0.10
        dst_ip: 10.0.0.20
        dst_port: 80
        proto: tcp
        action: allow
      - src_ip: 10.0.0.0/24
        dst_ip: 10.0.1.0/24
        dst_port: 0
        proto: any
        action: deny
    """
    with open(policy_file, "r") as f:
        data = yaml.safe_load(f)

    rules = data.get("rules", [])
    loaded = 0

    for r in rules:
        src = r["src_ip"]
        dst = r["dst_ip"]
        dst_port = int(r.get("dst_port", 0))
        proto = r.get("proto", "any").lower()
        action = r.get("action", "deny").lower()

        if proto == "tcp":
            proto_num = 6
        elif proto == "udp":
            proto_num = 17
        else:
            proto_num = 0

        allowed = 1 if action == "allow" else 0

        # For simplicity, we only support single IPs here; CIDRs could be
        # expanded or represented differently in a more advanced implementation.
        src_ip_int = ipv4_to_int(src)
        dst_ip_int = ipv4_to_int(dst)

        key = bpf["policy_map"].Key(
            src_ip=src_ip_int,
            dst_ip=dst_ip_int,
            src_port=0,
            dst_port=port_to_be16(dst_port),
            proto=proto_num,
        )
        policy_map[key] = bytes([allowed])
        loaded += 1

    print(f"[loader] Loaded {loaded} policy rules into eBPF map")

def flow_key_to_dict(key):
    src_ip = str(ipaddress.IPv4Address(key.src_ip))
    dst_ip = str(ipaddress.IPv4Address(key.dst_ip))
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": socket.ntohs(key.src_port),
        "dst_port": socket.ntohs(key.dst_port),
        "proto": key.proto,
    }

@app.route("/api/flows")
def get_flows():
    flows = []
    for key, value in stats_map.items():
        flows.append({
            **flow_key_to_dict(key),
            "allowed": value.allowed,
            "denied": value.denied,
        })
    return jsonify(flows)

@app.route("/api/policy")
def get_policy():
    rules = []
    for key, value in policy_map.items():
        rules.append({
            **flow_key_to_dict(key),
            "action": "allow" if value[0] == 1 else "deny",
        })
    return jsonify(rules)

def run_flask(host="0.0.0.0", port=8080):
    app.run(host=host, port=port)

def main():
    global bpf, policy_map, stats_map

    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True, help="Interface to attach XDP program to")
    parser.add_argument("--policy", required=True, help="YAML policy file")
    parser.add_argument("--no-attach", action="store_true", help="Do not attach XDP (for debug)")
    args = parser.parse_args()

    # Load eBPF program
    print("[loader] Loading eBPF program...")
    with open(EBPF_SOURCE_FILE, "r") as f:
        src = f.read()

    bpf = BPF(text=src)
    fn = bpf.load_func("xdp_zt_policy", BPF.XDP)

    if not args.no_attach:
        print(f"[loader] Attaching XDP program to {args.iface}")
        bpf.attach_xdp(args.iface, fn, 0)

    policy_map = bpf["policy_map"]
    stats_map = bpf["stats_map"]

    load_policy(args.policy)

    # Start Flask API in a separate thread
    api_thread = threading.Thread(target=run_flask, kwargs={"host": "0.0.0.0", "port": 8080}, daemon=True)
    api_thread.start()

    print("[loader] REST API available at http://localhost:8080")
    print("[loader] Press Ctrl+C to exit")

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("[loader] Detaching XDP program...")
        if not args.no_attach:
            bpf.remove_xdp(args.iface, 0)

if __name__ == "__main__":
    main()
