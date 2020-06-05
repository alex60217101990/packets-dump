// SPDX-License-Identifier: GPL-2.0
#include <linux/if_ether.h>
#include <linux/in.h>
#include "../main/bpf_helpers.h"
#include "../fw/redirect.h"

#include "../fw/utils.h"
#include "../fw/kern_l2.h"
#include "../fw/kern_l3.h"
#include "../fw/kern_l4.h"
#include "../fw/kern_l4.h"

SEC("xdp")
int xdp_fw(struct xdp_md *ctx) {
    /*
        Lets define the default action in our XDP program, in this case we are going to use XDP_PASS.
    */
    __u32 action = XDP_PASS;
    bpf_printk("got packet: %p\n", ctx);

     /*
        Convert the supplied 'xdp_md' structure to one of our custom 'context' structures for easy handling
        throughout this program.
    */
    struct context custom_ctx = to_ctx(ctx);

    /*
        Parse our the ethernet header and unwrap any potential vlan headers from this packet. While also making sure
        that the source MAC address of this packet is not contained in our blacklist.
    */
    action = parse_eth(&custom_ctx);
    if (action != XDP_PASS)
    {
        goto ret;
    }

    /*
        Check the layer 3 protocol contained in this packet, we only care about IPv4 and IPv6 in this case so if its not one
        of those lets short circuit and return the last seen action.
    */
    switch (custom_ctx.nh_proto)
    {
    case ETH_P_IP:
        /*
            We have an IPv4 packet so lets parse out its source address and check it against our blacklist to see if we should drop it.
            If not then grab the next header in line and continue processing the layer 4 protocol.
        */
        action = parse_ipv4(&custom_ctx);
        break;
    case ETH_P_IPV6:
        /*
            We have an IPv6 packet so lets parse out its source address and check it against our blacklist to see if we should drop it.
            If not then grab the next header in line and continue processing the layer 4 protocol.
        */
        action = parse_ipv6(&custom_ctx);
        break;
    default:
        /*
            This packet isn't an IPv4 or IPv6 packet and we don't know what to do with it so return execution based on the last seen action.
        */
        goto ret;
    }

    if (action != XDP_PASS)
    {
        /*
            One of the previous parse functions returned an action other than XDP_PASS so lets return that immediately.
        */
        goto ret;
    }

    /*
        Check the layer 4 protocol contained in this packet, we only care about TCP and UDP in this case so if its not one
        of those lets short circuit and return the last seen action.
    */
    switch (custom_ctx.nh_proto)
    {
    case IPPROTO_UDP:
        /*
            We have a UDP packet so lets parse out its source and destination ports and check them against our blacklist to see if we should
            drop it.
        */
        action = parse_udp(&custom_ctx);
        break;
    case IPPROTO_TCP:
        /*
            We have a TCP packet so lets parse out its source and destination ports and check them against our blacklist to see if we should
            drop it.
        */
        action = parse_tcp(&custom_ctx);
        break; 
    }
ret:
    // if (action == XDP_PASS) {
    //     action = redirect(&custom_ctx);
    // }
    return update_action_stats(&custom_ctx, action);
}

char __license[] SEC("license") = "GPL";