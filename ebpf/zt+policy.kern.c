# Write eBPF kernel program
ebpf_code = r"""
// ebpf/zt_policy_kern.c
// XDP-based zero trust policy enforcement and flow stats collection

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "zt_policy_common.h"

char _license[] SEC("license") = "GPL";

static __always_inline int parse_ipv4(void *data, void *data_end,
                                      struct iphdr **iphdr_out) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return -1;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    *iphdr_out = iph;
    return 0;
}

static __always_inline int parse_l4(struct iphdr *iph, void *data_end,
                                    __u8 *proto,
                                    __u16 *sport, __u16 *dport) {
    void *l4_hdr = (void *)iph + iph->ihl * 4;
    if (l4_hdr > data_end)
        return -1;

    *proto = iph->protocol;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4_hdr;
        if ((void *)(tcph + 1) > data_end)
            return -1;
        *sport = tcph->source;
        *dport = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4_hdr;
        if ((void *)(udph + 1) > data_end)
            return -1;
        *sport = udph->source;
        *dport = udph->dest;
    } else {
        *sport = 0;
        *dport = 0;
    }

    return 0;
}

// Zero Trust policy:
// - Look up flow in policy_map
// - If found and allowed=1 -> record allowed, pass
// - If found and allowed=0 -> record denied, drop
// - If not found          -> record denied, drop (default deny)

SEC("xdp")
int xdp_zt_policy(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *iph;
    if (parse_ipv4(data, data_end, &iph) < 0)
        return XDP_PASS; // Non-IPv4 traffic is not filtered

    __u8 proto;
    __u16 sport, dport;
    if (parse_l4(iph, data_end, &proto, &sport, &dport) < 0)
        return XDP_PASS;

    struct flow_key key = {};
    key.src_ip   = iph->saddr;
    key.dst_ip   = iph->daddr;
    key.src_port = sport;
    key.dst_port = dport;
    key.proto    = proto;

    // Lookup policy
    __u8 *allowed = bpf_map_lookup_elem(&policy_map, &key);
    bool is_allowed = false;
    if (allowed && *allowed == 1) {
        is_allowed = true;
    }

    // Update stats
    struct flow_stats *st = bpf_map_lookup_elem(&stats_map, &key);
    if (!st) {
        struct flow_stats init = {};
        bpf_map_update_elem(&stats_map, &key, &init, BPF_NOEXIST);
        st = bpf_map_lookup_elem(&stats_map, &key);
    }

    if (st) {
        if (is_allowed) {
            __sync_fetch_and_add(&st->allowed, 1);
        } else {
            __sync_fetch_and_add(&st->denied, 1);
        }
    }

    if (is_allowed) {
        return XDP_PASS;
    } else {
        return XDP_DROP;
    }
}
"""

common_h = r"""
// ebpf/zt_policy_common.h
#ifndef _ZT_POLICY_COMMON_H
#define _ZT_POLICY_COMMON_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

struct flow_stats {
    __u64 allowed;
    __u64 denied;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, __u8); // 1 = allowed, 0 = denied
} policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} stats_map SEC(".maps");

#endif
"""

with open(os.path.join(base_dir, "ebpf", "zt_policy_kern.c"), "w") as f:
    f.write(ebpf_code.strip() + "\n")

with open(os.path.join(base_dir, "ebpf", "zt_policy_common.h"), "w") as f:
    f.write(common_h.strip() + "\n")

"eBPF files written"
