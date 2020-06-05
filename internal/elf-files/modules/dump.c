#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include "../main/bpf_helpers.h"
#include "../dump/dump.h"
#include "../fw/utils.h"

// /* Metadata will be in the perf event before the packet data. */
// struct S {
// 	__u16 cookie;
// 	__u16 pkt_len;
// } __packed;

// struct vlan_hdr {
// 	__be16 h_vlan_TCI;
// 	__be16 h_vlan_encapsulated_proto;
// };

// struct event {
//     __u8 type;
//     __u32 saddr, daddr;
//     __u32 smac, dmac;
//     __u16 sport, dport; 
// };

// _Static_assert(sizeof(struct S) == 4, "wrong size of perf_event_item");

// #define SAMPLE_SIZE 1024ul
// #define MAX_CPUS 128

// #ifndef __packed
// #define __packed __attribute__((packed))
// #endif

// #define min(x, y) ((x) < (y) ? (x) : (y))

// // Define special, perf_events map where key maps to CPU_ID
// BPF_MAP_DEF(perfmap) = {
//     .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//     .max_entries = MAX_CPUS,     // Max supported CPUs
// };
// BPF_MAP_ADD(perfmap);

SEC("xdp")
int xdp_dump(struct xdp_md *ctx) {
    // void *end = (void *)(long)ctx->data_end;
    // void *data = (void *)(long)ctx->data;
    // __u32 ip_src;
    // __u64 offset;
    // __u16 eth_type;
    // __u64 flags = BPF_F_CURRENT_CPU;
    // __u16 sample_size;
    // int ret;
    // struct S metadata;
	// metadata.cookie = 0xdead;
	// metadata.pkt_len = (__u16)(end - data);
	// sample_size = min(metadata.pkt_len, SAMPLE_SIZE);

    // metadata.cookie = 0xdead;
	// metadata.pkt_len = (__u16)(end - data);
	// sample_size = min(metadata.pkt_len, SAMPLE_SIZE);

	// flags |= (__u64)sample_size << 32;

	// ret = bpf_perf_event_output(ctx, &perfmap, flags,
	// 			&metadata, sizeof(metadata));
	// if (ret)
	// 	bpf_printk("perf_event_output failed: %d\n", ret);

    // return XDP_PASS;

     /*
        Convert the supplied 'xdp_md' structure to one of our custom 'context' structures for easy handling
        throughout this program.
    */
    struct context custom_ctx = to_ctx(ctx);

    return send_dump_event(&custom_ctx);
}

char __license[] SEC("license") = "GPL";