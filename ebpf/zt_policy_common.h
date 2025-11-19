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
