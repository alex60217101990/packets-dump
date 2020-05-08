#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

/* Metadata will be in the perf event before the packet data. */
struct S {
	__u16 cookie;
	__u16 pkt_len;
} __packed;

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct event {
    __u8 type;
    __u32 saddr, daddr;
    __u32 smac, dmac;
    __u16 sport, dport; 
};

_Static_assert(sizeof(struct S) == 4, "wrong size of perf_event_item");

#define SAMPLE_SIZE 1024ul
#define MAX_CPUS 128

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

// Define special, perf_events map where key maps to CPU_ID
BPF_MAP_DEF(perfmap) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = MAX_CPUS,     // Max supported CPUs
};
BPF_MAP_ADD(perfmap);

// char* uuid_generate_func() {
//     uuid_t binuuid;
//     uuid_generate_random(binuuid);
//     char *uuid;
//     uuid = malloc (sizeof (char) * 37);
//     uuid_unparse(binuuid, uuid);
//     return uuid;
// };

SEC("xdp")
int xdp_dump(struct xdp_md *ctx) {
    void *end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 ip_src;
    __u64 offset;
    __u16 eth_type;
    __u64 flags = BPF_F_CURRENT_CPU;
    __u16 sample_size;
    int ret;
    struct S metadata;
	metadata.cookie = 0xdead;
	metadata.pkt_len = (__u16)(end - data);
	sample_size = min(metadata.pkt_len, SAMPLE_SIZE);

    metadata.cookie = 0xdead;
	metadata.pkt_len = (__u16)(end - data);
	sample_size = min(metadata.pkt_len, SAMPLE_SIZE);

	flags |= (__u64)sample_size << 32;

	ret = bpf_perf_event_output(ctx, &perfmap, flags,
				&metadata, sizeof(metadata));
	if (ret)
		bpf_printk("perf_event_output failed: %d\n", ret);

//     if (data + offset > end) {
//         return XDP_ABORTED;
//     }
//     eth_type = eth->h_proto;

//     /* handle VLAN tagged packet */
//     if (eth_type == ETH_P_8021Q || eth_type == ETH_P_8021AD) {
// 	struct vlan_hdr *vlan_hdr;

// 	vlan_hdr = (void *)eth + offset;
// 	offset += sizeof(*vlan_hdr);
// 	if ((void *)eth + offset > end)
// 		return XDP_ABORTED;
// 	eth_type = vlan_hdr->h_vlan_encapsulated_proto; 
//    }

//     /* detect address type (IPv4 or IPv6) */
//     if (eth_type == ETH_P_IPV6 || eth_type == ETH_P_IP) {
//     }

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";