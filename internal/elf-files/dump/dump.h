#ifndef _DUMP_H
#define _DUMP_H

#include "../main/bpf_helpers.h"
#include "../fw/common.h"
#include "./common_dump.h"
#include "../main/utils_helpers.h"

#define SAMPLE_SIZE 1024ul
#define MAX_CPUS 128

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))

// Define special, perf_events map where key maps to CPU_ID
BPF_MAP_DEF(perfmap) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = MAX_CPUS,     // Max supported CPUs
};
BPF_MAP_ADD(perfmap);

INTERNAL __u32 send_dump_event(struct context *ctx) {
    __u64 flags = BPF_F_CURRENT_CPU;
    __u16 sample_size;
    int ret;
    struct S metadata;
	metadata.cookie = 0xdead;
	metadata.pkt_len = (__u16)(ctx->length);
	sample_size = min(metadata.pkt_len, SAMPLE_SIZE);

	flags |= (__u64)sample_size << 32;

	ret = bpf_perf_event_output(ctx->base_ctx, &perfmap, flags,
				&metadata, sizeof(metadata));
	if (ret)
		bpf_printk("perf_event_output failed: %d\n", ret);

	return XDP_PASS;
} 

#endif /* _DUMP_H */