#ifndef _KERN_L3_H
#define _KERN_L3_H

#include "../main/bpf_helpers.h"
#include "common.h"
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "./common.h"
#include "../main/utils_helpers.h"

/*
    'parse_ipv4' handles parsing the passed in packets IPv4 header. It will parse out the source address of the
    packets and check to see if it exists in the 'v4_blacklist' BPF map defined above.
*/
INTERNAL __u32 parse_ipv4(struct context *ctx)
{
    /*
        We need to access the IPv4 header data so we can find out whether or not this packets source IP address is blacklisted,
        and if not what the next protocol in the header is to continue parsing.
        So we take the pre-casted data start location pointer and adds the next header offset, which is determined in the previously
        called parse_eth function call.
    */
    struct iphdr *ip = ctx->data_start + ctx->nh_offset;

    // /* as a real router, we need to check the TTL to prevent never ending loops*/
	// if (ip->ttl <= 1)
	// 	return XDP_DROP;

    /*
        As always since we are accessing data within the packet we need to ensure that we aren't going out of bounds.
    */
    if (ip + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    /*
        Just as in the case with the ethernet header, if this packets source IP address is not matched in the blacklist we need to
        update the offset to the next header in the packet, and update the protocol of next header in the packet.
    */
    ctx->nh_offset += ip->ihl * 4;
    ctx->nh_proto = ip->protocol;

    ctx->iph = ip;

    /*
        If we got here we are continuing on to the next parser so return XDP_PASS.
    */
    return XDP_PASS;
}

/*
    'parse_ipv6' handles parsing the passed in packets IPv8 header. It will parse out the source address of the
    packets and check to see if it exists in the 'v6_blacklist' BPF map defined above.
*/
INTERNAL __u32 parse_ipv6(struct context *ctx)
{
    /*
        We need to access the IPv6 header data so we can find out whether or not this packets source IP address is blacklisted,
        and if not what the next protocol in the header is to continue parsing.
        So we take the pre-casted data start location pointer and adds the next header offset, which is determined in the previously
        called parse_eth function call.
    */
    struct ipv6hdr *ip = ctx->data_start + ctx->nh_offset;

    /*
        As always since we are accessing data within the packet we need to ensure that we aren't going out of bounds.
    */
    if (ip + 1 > ctx->data_end)
    {   
        return XDP_DROP;
    }

    /*
        Just as in the case with the ethernet header, if this packets source IP address is not matched in the blacklist we need to
        update the offset to the next header in the packet, and update the protocol of next header in the packet.
        Note for the purposes of this workshop we are ignoring IPv6 extension headers.
    */
    ctx->nh_offset += sizeof(*ip);
    ctx->nh_proto = ip->nexthdr;

    /*
        If we got here we are continuing on to the next parser so return XDP_PASS.
    */
    return XDP_PASS;
}

#endif // _KERN_L3_H