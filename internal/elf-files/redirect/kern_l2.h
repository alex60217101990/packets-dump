#ifndef _KERN_L2_H
#define _KERN_L2_H

#include "../main/bpf_helpers.h"
#include "../main/utils_helpers.h"
#include <linux/if_ether.h>
#include "common.h"

/*
    Pulled from $(LINUX)/include/linux/if_vlan.h#L38
    This is used for unwrapping vlan headers if any exist in the packet. This is NOT my code in anyway and is directly
    copied from the above mentioned file in the linux kernel, which can't be directly included.
*/
struct vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

/*
    'parse_eth' handles parsing the passed in packets ethernet and vlan headers if any exist. It will parse out the source MAC address
    of this packet and check to see if it exists in the 'mac_blacklist' BPF map defined above, and also unwrap up to two vlan headers.
*/
INTERNAL __u32 parse_eth(struct context *ctx)
{
    /*
        We need to access the ethernet header data so we can find out whether or not this packets source MAC address is blacklisted,
        and if not what the next protocol in the header is to continue parsing.
        So we take the pre-casted data start location pointer and adds the next header offset, which in this case is always 0.
    */
    struct ethhdr *eth = ctx->data_start + ctx->nh_offset;

    /*
        As always since we are accessing data within the packet we need to ensure that at the very least we have one entire ethernet
        header to work with.
        So take the 'eth' value and add 1 to it to see if the resulting pointer location which would be at this point:
            data_start + sizeof(struct ethhdr)
        is past the data_end pointer.
    */
    if (eth + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    /*
        Give the current packets source MAC address is not present in the blacklist update the offset to the next header in line and update
        the next headers protocol to the protocol contained in the ethernet header.
    */
    ctx->nh_offset += sizeof(*eth);
    ctx->nh_proto = bpf_ntohs(eth->h_proto);

    /*
        This is the first time we are going to use a 'loop' in XDP which is generally forbidden, specifically backwards jumps being forbidden in any
        BPF program not just XDP.
        We are using a C/C++ trick where we are telling the compiler to 'unroll' this loop into its representative executions inside of the loop. This
        only works for loops that have pre-defined beginning and end points. Meaning you can't use the packet data or BPF map data to control the loop itself,
        and only works on 'small' loops in that you are still bound by the total instruction count of 4096.
        This loop is going to attempt to unroll vlan headers as there could be potentially multiple layers of vlan headers contained in a packet.
    */
#pragma unroll
    for (int i = 0; i < 2; i++)
    {
        /*
            Check to see if the next in this packet is a vlan header, i.e. either a 8021Q or 8021AD protocol header.
        */
        if (ctx->nh_proto == ETH_P_8021Q || ctx->nh_proto == ETH_P_8021AD)
        {
            /*
                Preform the same process as the raw ethernet header above to ensure get to the next header.
            */
            struct vlan_hdr *vlan = ctx->data_start + ctx->nh_offset;

            /*
                You will see this particular snippet of code over and over and over again throughout all XDP/eBPF programs.
            */
            if (vlan + 1 > ctx->data_end)
            {
                return XDP_DROP;
            }

            ctx->nh_offset += sizeof(*vlan);
            ctx->nh_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        }
    }

    // // Override mac address
    // eth->h_dest[0] = 0x08;
    // eth->h_dest[1] = 0x00;
    // eth->h_dest[2] = 0x27;
    // eth->h_dest[3] = 0x93;
    // eth->h_dest[4] = 0x08;
    // eth->h_dest[5] = 0xde;

    /*
        If we got here we are continuing on to the next parser so return XDP_PASS.
    */
    return XDP_PASS;
}

#endif // _KERN_L2_H