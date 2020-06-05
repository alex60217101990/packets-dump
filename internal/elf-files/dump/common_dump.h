#ifndef _COMMON_DUMP_H
#define _COMMON_DUMP_H

#include <linux/types.h>

/* Metadata will be in the perf event before the packet data. */
struct S {
	__u16 cookie;
	__u16 pkt_len;
} __packed;

_Static_assert(sizeof(struct S) == 4, "wrong size of perf_event_item");

#endif /* _COMMON_DUMP_H */