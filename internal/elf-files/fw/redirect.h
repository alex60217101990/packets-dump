#ifndef _REDIRECT_H
#define _REDIRECT_H

#include "../main/bpf_helpers.h"
#include "../main/utils_helpers.h"
#include "./common.h"
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/if_ether.h>

#define AF_INET 2
#define AF_INET6 10
#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)

struct bpf_map_def SEC("maps") tx_port = {
	.map_type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 256,
};

/* from include/net/ip.h */
INTERNAL int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

INTERNAL __u32 redirect(struct context *ctx)
{
    struct bpf_fib_lookup fib_params = {};
    __u32 action = XDP_PASS;

    if (ctx->v4 && ctx->tcp)
    {

        /* populate the fib_params fields to prepare for the lookup */
		// fib_params.family	= AF_INET;
		// fib_params.tos		= ctx->v4->tos;
		// fib_params.l4_protocol	= ctx->v4->protocol;
		// fib_params.sport	= 0;
		// fib_params.dport	= 0;
		// fib_params.tot_len	= bpf_ntohs(ctx->v4->tot_len);
		// fib_params.ipv4_src	= ctx->v4->saddr;
		// fib_params.ipv4_dst	= ctx->v4->daddr;

        // ctx->tcp->dest = (__be16)5555;

        /* Set a proper destination address */
	    // memcpy(custom_ctx.eth->h_dest, , ETH_ALEN);
	    action = bpf_redirect_map(&tx_port, 0, 0);

        // __be32 temp;
        // __builtin_memcpy(&temp, &ctx->v4->daddr, sizeof(temp));
        // __builtin_memcpy(&ctx->v4->daddr, &ctx->v4->saddr, sizeof(temp));
        // __builtin_memcpy(&ctx->v4->saddr, &temp, sizeof(temp));

        //ctx->v4->ttl = 64;
    }
    else if (ctx->v6 && ctx->tcp)
    {
        /* IPv6 part of the code */
		// struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
		// struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

        // struct v6_proxy_key key_udp, key_tcp, result;

        // memcpy(key_udp.v6_address, &ctx->v6->daddr, sizeof(key_udp.v6_address));
        // key_udp.port = (__u16)bpf_ntohs(ctx->udp->dest);
        // memcpy(key_tcp.v6_address, &ctx->v6->daddr, sizeof(key_tcp.v6_address));
        // key_tcp.port = (__u16)bpf_ntohs(ctx->tcp->dest);

        /* populate the fib_params fields to prepare for the lookup */
		// fib_params.family	= AF_INET6;
		// fib_params.flowinfo	= *(__be32 *) ctx->v6 & IPV6_FLOWINFO_MASK;
		// fib_params.l4_protocol	= ctx->v6->nexthdr;
		// fib_params.sport	= 0;
		// fib_params.dport	= 0;
		// fib_params.tot_len	= bpf_ntohs(ctx->v6->payload_len);
		// *src			= ctx->v6->saddr;
		// *dst			= ctx->v6->daddr;

        //ctx->tcp->dest = (__be16)5555;

        // struct in6_addr temp;
        // __builtin_memcpy(&temp, &ctx->v6->daddr, sizeof(temp));
        // __builtin_memcpy(&ctx->v6->daddr, &ctx->v6->saddr, sizeof(temp));
        // __builtin_memcpy(&ctx->v6->saddr, &temp, sizeof(temp));

       //ctx->v6->hop_limit = 64;
    }

    // fib_params.ifindex = 1;
    /* this is where the FIB lookup happens. If the lookup is successful */
	/* it will populate the fib_params.ifindex with the egress interface index */
	//__u16 h_proto = ctx->eth->h_proto;
	// int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	// switch (rc) {
	// case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
	// 	   /* we are a router, so we need to decrease the ttl */
	// 	if (h_proto == bpf_htons(ETH_P_IP))
	// 		ip_decrease_ttl(ctx->v4);
	// 	else if (h_proto == bpf_htons(ETH_P_IPV6))
	// 		ctx->v6->hop_limit--;
	// 	/* set the correct new source and destionation mac addresses */
	// 	/* can be found in fib_params.dmac and fib_params.smac */
	// 	memcpy(ctx->eth->h_dest, fib_params.dmac, ETH_ALEN);
	// 	memcpy(ctx->eth->h_source, fib_params.smac, ETH_ALEN);
	// 	/* and done, now we set the action to bpf_redirect_map with fib_params.ifindex which is the egress port as paramater */
	// 	action = bpf_redirect_map(&tx_port, fib_params.ifindex, 0);
	// 	break;
	// case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
	// case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
	// case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
	// 	action = XDP_DROP;
	// 	break;
	// case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
	// case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	// case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
	// case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
	// case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
	// 	/* PASS */
	// 	break;
	// }

    return action; 
}

#endif /* _REDIRECT_H */