#include "../ddos/cookie.h"

SEC("xdp")
int xdp_ddos(struct xdp_md* ctx) {
    struct Packet packet;
    packet.ctx = ctx;

    struct ethhdr* ether = (struct ethhdr*)(void*)ctx->data;
    if ((void*)(ether + 1) > (void*)ctx->data_end) {
        return XDP_PASS; /* what are you? */
    }

    packet.ether = ether;
    return process_ether(&packet);
}

char _license[] SEC("license") = "GPL";