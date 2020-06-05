#include <linux/bpf.h>
#include "../main/bpf_helpers.h"
#include "../main/bpf_endian.h"
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdlib.h>
#include "../main/utils_helpers.h"
#include <stddef.h>
#include <linux/pkt_cls.h>

#include "../redirect/common.h"
#include "../redirect/kern_l2.h"
#include "../redirect/kern_l3.h"
#include "../redirect/kern_l4.h"
#include "../redirect/utils.h"

INTERNAL void print_ip(unsigned int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    // printt("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);        
    printt("%d.%d.%d\n", bytes[2], bytes[1], bytes[0]);        
}

// SEC("xdp")
// int xdp_rd(struct xdp_md *ctx) {
//     int rc = XDP_PASS;
//     __u64 nh_off = 0;
//      // Read data
//     void* data_end = (void*)(long)ctx->data_end;
//     void* data = (void*)(long)ctx->data;

//     // Handle data as an ethernet frame header
//     struct ethhdr *eth = data;

//     // Check frame header size
//     nh_off = sizeof(*eth);
//     if (data + nh_off > data_end) {
//         return rc;
//     }

//     // Check protocol
//     if (eth->h_proto != bpf_htons(ETH_P_IP)) {
//         return rc;
//     }

//     // Check packet header size
//     struct iphdr *iph = data + nh_off;
//     nh_off += sizeof(struct iphdr);
//     if (data + nh_off > data_end) {
//         return rc;
//     }
//     print_ip((unsigned int)iph->saddr);
//     print_ip((unsigned int)iph->daddr);

//     // // Override ip header
//     // iph->tos = 7 << 2;      // DSCP: 7
//     // iph->check = 0;
//     // iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));
//     // return rc;

//     // Check protocol
//     if (iph->protocol != IPPROTO_TCP) {
//         return rc;
//     }

//     // Check tcp header size
//     struct tcphdr *tcph = data + nh_off;
//     nh_off += sizeof(struct tcphdr);
//     if (data + nh_off > data_end) {
//         return rc;
//     }

//     // tcph->check = 0;
//     // tcph->check = (__u16)get_tcp_checksum(iph, tcph);

//     // // Override mac address
//     // eth->h_dest[0] = 0x08;
//     // eth->h_dest[1] = 0x00;
//     // eth->h_dest[2] = 0x27;
//     // eth->h_dest[3] = 0x93;
//     // eth->h_dest[4] = 0x08;
//     // eth->h_dest[5] = 0xde;

//     __u16 new_port = 5555;

//     if ((__u16)bpf_ntohs(tcph->dest) != (__u16)bpf_ntohs(5555)) {
//        //printt("old check: %d, dest port: %d, source port: %d, \n", tcph->check, tcph->dest, tcph->source);
//         // update_header_field(&tcph->check, (__u16 *) &tcph->dest, (__u16 *) &new_port);
//         //return XDP_PASS;
//     } else {
//         printt("new check: %d, dest port: %d, source port: %d\n", tcph->check, tcph->dest, tcph->source);
//     }
//     // __u32 csum = 0;
//     tcph->dest = (__u16) new_port;
//     // compute_tcp_checksum(iph, (unsigned short *) tcph);
//     // update_header_field(&tcph->check, (__u16 *) &tcph->dest, (__u16 *) &new_port);
   
//     unsigned short old_daddr;
//     unsigned long sum;
//     // Backup old dest address
//     old_daddr = bpf_ntohs(*(unsigned short *)&iph->daddr);

//     // Override mac address
//     eth->h_dest[0] = 0x08;
//     eth->h_dest[1] = 0x00;
//     eth->h_dest[2] = 0x27;
//     eth->h_dest[3] = 0x93;
//     eth->h_dest[4] = 0x08;
//     eth->h_dest[5] = 0xde;

//     // Override ip header
//     iph->tos = 7 << 2;      // DSCP: 7
//     iph->daddr = bpf_htonl(2887516418);  // Dest: 192.168.50.5
//     iph->check = 0;
//     iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

//     // Update tcp checksum
//     sum = old_daddr + (~bpf_ntohs(*(unsigned short *)&iph->daddr) & 0xffff);
//     sum += bpf_ntohs(tcph->check);
//     sum = (sum & 0xffff) + (sum>>16);
//     tcph->check = bpf_htons(sum + (sum>>16) - 1);

// 	return XDP_TX;
// }

// SEC("ingress")
// int proxy(struct __sk_buff *skb)
// {
//     const __be32 cluster_ip = 0x846F070A; // 10.7.111.132
//     const __be32 pod_ip = 33627308;     // 172.28.1.2

//     const int l3_off = ETH_HLEN;    // IP header offset
//     const int l4_off = l3_off + 20; // TCP header offset: l3_off + sizeof(struct iphdr)
//     __be32 sum;                     // IP checksum

//     void *data = (void *)(long)skb->data;
//     void *data_end = (void *)(long)skb->data_end;
//     if (data_end < data + l4_off) { // not our packet
//         return TC_ACT_OK;
//     }

//     struct iphdr *ip4 = (struct iphdr *)(data + l3_off);
//     if (ip4->daddr != cluster_ip || ip4->protocol != IPPROTO_TCP /* || tcp->dport == 80 */) {
//         return TC_ACT_OK;
//     }

//     // DNAT: cluster_ip -> pod_ip, then update L3 and L4 checksum
//     sum = bpf_csum_diff((void *)&ip4->daddr, 4, (void *)&pod_ip, 4, 0);
//    // bpf_csum_diff((void *)&ip4->daddr, 4, (void *)&pod_ip, 4, 0);
//     bpf_skb_store_bytes(skb, l3_off + offsetof(struct iphdr, daddr), (void *)&pod_ip, 4, 0);
//     bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0);
// 	bpf_l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check), 0, sum, BPF_F_PSEUDO_HDR);

//     return TC_ACT_OK;
// }

SEC("xdp")
int proxy(struct xdp_md *ctx) {
    /*
        Lets define the default action in our XDP program, in this case we are going to use XDP_PASS.
    */
    __u32 action = XDP_PASS;
    printt("got packet: %p\n", ctx);

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
    return update_action_stats(&custom_ctx, action);
}

char __license[] SEC("license") = "GPL";