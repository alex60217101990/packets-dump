#ifndef _KERN_L4_H
#define _KERN_L4_H

#include "../main/bpf_helpers.h"
#include "../main/bpf_endian.h"
#include "common.h"
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include "../main/utils_helpers.h"

static inline unsigned short checksum(unsigned short *buf, int bufsz) {
    unsigned long sum = 0;

    while (bufsz > 1) {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if (bufsz == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

/* set tcp checksum: given IP header and tcp segment */
INTERNAL void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
    register unsigned long sum = 0;
    unsigned short tcpLen = bpf_ntohs(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //add the pseudo header 
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += bpf_htons(IPPROTO_TCP);
    //the length
    sum += bpf_htons(tcpLen);
 
    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload)&bpf_htons(0xFF00));
    }
      //Fold 32-bit sum to 16 bits: add carrier to result
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;
}

INTERNAL void update_header_field(__u16 *csum, __u16 *old_val, __u16 *new_val)
{
	__u32 new_csum_value;
	__u32 new_csum_comp;
	__u32 undo;

	/* Get old sum of headers by getting one's compliment and adding
	 * one's compliment of old header value (effectively subtracking)
	 */
	undo = ~((__u32) *csum) + ~((__u32) *old_val);

	/* Check for old header overflow and compensate
	 * Add new header value
	 */
	new_csum_value = undo + (undo < ~((__u32) *old_val)) + (__u32) *new_val;

	/* Check for new header overflow and compensate */
	new_csum_comp = new_csum_value + (new_csum_value < ((__u32) *new_val));

	/* Add any overflow of the 16 bit value to itself */
	new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);

	/* Check that overflow added above did not cause another overflow */
	new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);

	/* Cast to 16 bit one's compliment of sum of headers */
	*csum = (__u16) ~new_csum_comp;

	/* Update header to new value */
	*old_val = *new_val;
    return;
}

INTERNAL void update_tcp_header_port(struct tcphdr* tcp, __u16 *new_val)
{
    __u16 old_check = tcp->check;
	__u32 new_csum_value;
	__u32 new_csum_comp;
	__u32 undo;

	/* Get old sum of headers by getting one's compliment and adding
	 * one's compliment of old header value (effectively subtracking)
	 */
	undo = ~((__u32) tcp->check) + ~((__u32) tcp->dest);

	/* Check for old header overflow and compensate
	 * Add new header value
	 */
	new_csum_value = undo + (undo < ~((__u32) tcp->dest)) + (__u32) *new_val;

	/* Check for new header overflow and compensate */
	new_csum_comp = new_csum_value + (new_csum_value < ((__u32) *new_val));

	/* Add any overflow of the 16 bit value to itself */
	new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);

	/* Check that overflow added above did not cause another overflow */
	new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);

	/* Cast to 16 bit one's compliment of sum of headers */
	// tcp->check = (__u16) ~new_csum_comp;
    tcp->check = (__u16)10494;

    printt("old check: %d, old dest: %d, new port: %d\n", old_check, (__u16)bpf_ntohs(tcp->dest), *new_val);
	/* Update header to new value */
	tcp->dest = (__u16)bpf_ntohs(*new_val);
    return;
}

/*
    'parse_udp' handles parsing the passed in packets UDP header. It will parse out the source and destination ports of the
    packet and check to see if either exists in the 'port_blacklist' BPF map defined above.
*/
INTERNAL __u32 parse_udp(struct context *ctx)
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

//(__u16)bpf_ntohs(udp->dest)

    /*
        If we got here we are continuing on to the next parser so return XDP_PASS.
    */
    return XDP_PASS;
}

/*
    'parse_tcp' handles parsing the passed in packets TCP header. It will parse out the source and destination ports of the
    packet and check to see if either exists in the 'port_blacklist' BPF map defined above.
*/
INTERNAL __u32 parse_tcp(struct context *ctx)
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

    // (__u16)bpf_ntohs(tcp->dest); (__u16)bpf_ntohs(tcp->source);
    __u16 new_port = 5555;
    if ((__u16)bpf_ntohs(tcp->dest) == new_port) {
        // Backup old dest address
    ctx->old_daddr = bpf_ntohs(*(unsigned short *)&ctx->iph->daddr);
// Override ip header
   // ctx->iph->tos = 7 << 2;      // DSCP: 7
    ctx->iph->daddr = (__be32)bpf_htonl(2887516417);  // Dest: 192.168.50.5
    // ctx->iph->check = 0;
    // ctx->iph->check = checksum((unsigned short *)ctx->iph, sizeof(struct iphdr));
// // Update tcp checksum
//     ctx->sum = ctx->old_daddr + (~bpf_ntohs(*(unsigned short *)&ctx->iph->daddr) & 0xffff);
//     ctx->sum += bpf_ntohs(tcp->check);
//     ctx->sum = (ctx->sum & 0xffff) + (ctx->sum>>16);
//     tcp->check = bpf_htons(ctx->sum + (ctx->sum>>16) - 1);

        printt("new check: %d, dest port: %d, source port: %d\n", tcp->check, (__u16)bpf_ntohs(tcp->dest), (__u16)bpf_ntohs(tcp->source));
    //return XDP_TX;
    } else if ((__u16)bpf_ntohs(tcp->dest) == (__u16)4224) {
        // Update tcp checksum
        // update_header_field((__u16*)&tcp->check, (__u16*)&tcp->dest, (__u16*)&new_port);
        //update_tcp_header_port(tcp, &new_port);
        printt("change check: %d, dest port: %d, source port: %d\n", tcp->check, (__u16)bpf_ntohs(tcp->dest), (__u16)bpf_ntohs(tcp->source));
        return XDP_TX;
    }

    /*
        If we got here we are continuing on to the next parser so return XDP_PASS.
    */
   return XDP_PASS;
}

#endif // _KERN_L4_H