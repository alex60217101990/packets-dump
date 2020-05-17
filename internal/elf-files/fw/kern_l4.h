#ifndef _KERN_L4_H
#define _KERN_L4_H

#include "../bpf_helpers.h"
#include "common.h"
#include <linux/tcp.h>
#include <linux/udp.h>

#ifndef PORT_BLACKLIST_MAX_ENTRIES
#define PORT_BLACKLIST_MAX_ENTRIES (65535 * 4) /* src + dest * tcp + udp */
#endif

/*
    'port_blacklist' here represents the combination of the tcp and udp source/destination ports we want to blacklist.
    The only real difference here between this and the 'mac_blacklist' map is that our key is of an arbitrary custom type.
    This shows of one of the best capabilities of BPF maps, and that is their ability to adapt to the situation at hand.
    Note that the sizing here is of paramount importance, and see the notes listed at the definition of the 'port_key'
    structure.
*/
// struct bpf_map_def SEC("maps") port_blacklist = {
//     .map_type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(struct port_key),
//     .value_size = 1,
//     .max_entries = PORT_BLACKLIST_MAX_ENTRIES,
//     .map_flags = BPF_F_NO_PREALLOC,
// };
BPF_MAP_DEF(port_udp_blacklist) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = PORT_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(port_udp_blacklist);

BPF_MAP_DEF(port_tcp_blacklist) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = PORT_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};
BPF_MAP_ADD(port_tcp_blacklist);

/*
    'parse_udp' handles parsing the passed in packets UDP header. It will parse out the source and destination ports of the
    packet and check to see if either exists in the 'port_blacklist' BPF map defined above.
*/
static __always_inline __u32 parse_udp(struct context *ctx)
{
    /*
        We need to access the UDP header data so we can find out whether or not this packets source or destionation ports are
        blacklisted, and finally return the packet to the kernel.
        So we take the pre-casted data start location pointer and adds the next header offset, which is determined in the previously
        called parse_eth function call.
    */
    struct udphdr *udp = ctx->data_start + ctx->nh_offset;

    /*
        As always since we are accessing data within the packet we need to ensure that we aren't going out of bounds.
    */
    if (udp + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    /*
        We need to create two 'port_key' values so that we can search for the source and destination ports in our 'port_blacklist'
        map defined above. One for the source port and then another for the destination port.
    */
    struct {
        __u16 port_type;
        __u16 port;
    } src_key, dst_key;

    /*
        Set the ports for each key, keeping in mind byte order.
    */
    src_key.port = (__u16)bpf_ntohs(udp->source);
    src_key.port_type = 1;
    dst_key.port = (__u16)bpf_ntohs(udp->dest);
    dst_key.port_type = 2;

    /*
        Then we search for both individually as the port_key represents only a single port type at a time.
    */
    if (bpf_map_lookup_elem(&port_udp_blacklist, &src_key) ||
        bpf_map_lookup_elem(&port_udp_blacklist, &dst_key))
    {
        return XDP_DROP;
    }

    /*
        If we got here we are continuing on to the next parser so return XDP_PASS.
    */
    return XDP_PASS;
}

/*
    'parse_tcp' handles parsing the passed in packets TCP header. It will parse out the source and destination ports of the
    packet and check to see if either exists in the 'port_blacklist' BPF map defined above.
*/
static __always_inline __u32 parse_tcp(struct context *ctx)
{
    /*
        We need to access the TCP header data so we can find out whether or not this packets source or destionation ports are
        blacklisted, and finally return the packet to the kernel.
        So we take the pre-casted data start location pointer and adds the next header offset, which is determined in the previously
        called parse_eth function call.
    */
    struct tcphdr *tcp = ctx->data_start + ctx->nh_offset;

    /*
        As always since we are accessing data within the packet we need to ensure that we aren't going out of bounds.
    */
    if (tcp + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    /*
        We need to create two 'port_key' values so that we can search for the source and destination ports in our 'port_blacklist'
        map defined above. One for the source port and then another for the destination port.
    */
    struct {
        __u16 port_type;
        __u16 port;
    } src_key, dst_key;

    /*
        Set the ports for each key, keeping in mind byte order.
    */
    src_key.port = (__u16)bpf_ntohs(tcp->source);
    src_key.port_type = 1;
    dst_key.port = (__u16)bpf_ntohs(tcp->dest);
    dst_key.port_type = 2;

    /*
        We need to create two 'port_key' values so that we can search for the source and destination ports in our 'port_blacklist'
        map defined above. One for the source port and then another for the destination port.
    */
    if (bpf_map_lookup_elem(&port_tcp_blacklist, &src_key) ||
        bpf_map_lookup_elem(&port_tcp_blacklist, &dst_key))
    {
        return XDP_DROP;
    }

    /*
        If we got here we are continuing on to the next parser so return XDP_PASS.
    */
    return XDP_PASS;
}

#endif // _KERN_L4_H