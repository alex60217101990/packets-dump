// SPDX-License-Identifier: GPL-2.0

#ifndef _COMMON_H
#define _COMMON_H

#include <linux/types.h>

/*
    'context' here is the struct we will be passing around between the parsing functions in this XDP program,
    and is responsible for tracking where we are in the packet via 'nh_offset' as well as what the next headers
    protocol is via 'nh_proto'.
    This struct also holds the pointers to the beginning and end of the current packet and overall length,
    to reduce the number of times we have to cast between the 'xdp_md' structs data/data_end ints to void pointers.
    This isn't strictly required, but it is useful to encapsulate this information to clean up the implementation,
    of an XDP program.
*/
struct context
{
    void *data_start;
    void *data_end;
    struct xdp_md *base_ctx;
    __u32 length;

    __u32 nh_proto;
    __u32 nh_offset;

    struct iphdr *iph;
    unsigned short old_daddr;
    unsigned long sum;
};

struct counters
{
    __u64 packets;
    __u64 bytes;
};

#endif /* _COMMON_H */