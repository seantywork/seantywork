


// uncomment this to get prints at /sys/kernel/debug/tracing/trace
// #define DEBUG

#define AF_INET		2	/* Internet IP Protocol 	*/
#define ETH_ALEN    6

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/string.h>

/* 
// XDP enabled TX ports for redirect map 
BPF_MAP_DEF(if_redirect) = {
    .map_type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 64,
};
BPF_MAP_ADD(if_redirect);
*/
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} if_redirect SEC(".maps");


SEC("xdp_redirect_dev")
int xdp_sock2_prog(struct xdp_md *ctx)
{
    struct bpf_fib_lookup fib_params;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    eth_header = data;
    if ((void *)eth_header + sizeof(*eth_header) > data_end) {
        return XDP_PASS;
    }

    __u16 h_proto = eth_header->h_proto;

    /* anything that is not IPv4 (including ARP) goes up to the kernel */
    if (h_proto != 0x08U) {  // htons(ETH_P_IP) -> 0x08U
        return XDP_PASS;
    }
    ip_header = data + sizeof(*eth_header);
    if ((void *)ip_header + sizeof(*ip_header) > data_end) {

        bpf_printk("packet len too short: pass\n");

        return XDP_PASS;
    }

    
    if (ip_header->protocol == IPPROTO_ICMP) {

        bpf_printk("proto: icmp\n");
        
        // fill struct with zeroes, so we are sure no data is missing
        __builtin_memset(&fib_params, 0, sizeof(fib_params));

        fib_params.family	= AF_INET;
        // use daddr as source in the lookup, so we refleect packet back (as if it wcame from us)
        fib_params.ipv4_src	= ip_header->daddr;
        // opposite here, the destination is the source of the icmp packet..remote end
        fib_params.ipv4_dst	= ip_header->saddr;
        fib_params.ifindex = ctx->ingress_ifindex;

        bpf_printk("doing route lookup dst: %d\n", fib_params.ipv4_dst);
        int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
        if ((rc != BPF_FIB_LKUP_RET_SUCCESS) && (rc != BPF_FIB_LKUP_RET_NO_NEIGH)) {
            bpf_printk("dropping packet\n");
            return XDP_DROP;
        } else if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
            // here we should let packet pass so we resolve arp.
            bpf_printk("passing packet, lookup returned: %d\n", BPF_FIB_LKUP_RET_NO_NEIGH);
            return XDP_PASS;
        }
        bpf_printk("route lookup success, ifindex: %d\n", fib_params.ifindex);
    
        /*
        ip_header->daddr = bpf_ntohl(fib_params.ipv4_dst);
        ip_header->saddr = bpf_ntohl(fib_params.ipv4_src);
        */
        __u32 oldipdst = ip_header->daddr;
        ip_header->daddr = ip_header->saddr;
        ip_header->saddr = oldipdst;

        bpf_printk("ip to use as dst: %d.%d.%d.%d\n",
            ip_header->daddr & 0xFF,
            (ip_header->daddr >> 8) & 0xFF,
            (ip_header->daddr >> 16) & 0xFF,
            (ip_header->daddr >> 24) & 0xFF
        );


        memcpy(eth_header->h_dest, fib_params.dmac, ETH_ALEN);
        memcpy(eth_header->h_source, fib_params.smac, ETH_ALEN);

        bpf_printk("mac to use as dst: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            eth_header->h_dest[0], 
            eth_header->h_dest[1], 
            eth_header->h_dest[2], 
            eth_header->h_dest[3], 
            eth_header->h_dest[4],
            eth_header->h_dest[5]
            );


        //int action = bpf_redirect_map(&if_redirect, fib_params.ifindex, 0);

        int action = bpf_redirect(fib_params.ifindex,0);

        if (action == XDP_ABORTED){

            bpf_printk("aborted\n");
            return action;
        }

        if(action == XDP_REDIRECT){

            bpf_printk("redirect\n");

            return action;
        }

        return action;



    } else if (ip_header->protocol == IPPROTO_TCP) { 

        bpf_printk("proto: tcp\n");

        tcp_header = data + sizeof(*eth_header) + sizeof(*ip_header);

        if ((void *)tcp_header + sizeof(*tcp_header) > data_end) {

            bpf_printk("packet len too short for tcp: pass\n");

            return XDP_PASS;

        }

        
        // fill struct with zeroes, so we are sure no data is missing
        __builtin_memset(&fib_params, 0, sizeof(fib_params));

        fib_params.family	= AF_INET;
        // use daddr as source in the lookup, so we refleect packet back (as if it wcame from us)
        fib_params.ipv4_src	= ip_header->saddr;
        // opposite here, the destination is the source of the icmp packet..remote end
        fib_params.ipv4_dst	= ip_header->daddr;
        fib_params.ifindex = ctx->ingress_ifindex;

        bpf_printk("doing route lookup dst: %d\n", fib_params.ipv4_dst);
        int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
        if ((rc != BPF_FIB_LKUP_RET_SUCCESS) && (rc != BPF_FIB_LKUP_RET_NO_NEIGH)) {
            bpf_printk("dropping packet\n");
            return XDP_DROP;
        } else if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
            // here we should let packet pass so we resolve arp.
            bpf_printk("passing packet, lookup returned: %d\n", BPF_FIB_LKUP_RET_NO_NEIGH);
            return XDP_PASS;
        }
        bpf_printk("route lookup success, ifindex: %d\n", fib_params.ifindex);
        bpf_printk("mac to use as dst: %lu\n", fib_params.dmac);

        //int action = bpf_redirect_map(&if_redirect, fib_params.ifindex, 0);

        memcpy(eth_header->h_dest, fib_params.dmac, ETH_ALEN);
        memcpy(eth_header->h_source, fib_params.smac, ETH_ALEN);

        bpf_printk("dev: mac to use as src: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            eth_header->h_source[0], 
            eth_header->h_source[1], 
            eth_header->h_source[2], 
            eth_header->h_source[3], 
            eth_header->h_source[4],
            eth_header->h_source[5]
            );

        bpf_printk("dev: mac to use as dst: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            eth_header->h_dest[0], 
            eth_header->h_dest[1], 
            eth_header->h_dest[2], 
            eth_header->h_dest[3], 
            eth_header->h_dest[4],
            eth_header->h_dest[5]
            );




        int action = bpf_redirect(fib_params.ifindex,0);

        if (action == XDP_ABORTED){

            bpf_printk("aborted\n");
            return action;
        }

        if(action == XDP_REDIRECT){

            bpf_printk("redirect\n");

            return action;
        }

        return action;

    } else if (ip_header->protocol == IPPROTO_UDP) {

        bpf_printk("proto: udp\n");

        udp_header = data + sizeof(*eth_header) + sizeof(*ip_header);

        if ((void *)udp_header + sizeof(*udp_header) > data_end) {

            bpf_printk("packet len too short for udp: pass\n");

            return XDP_PASS;

        }

        
        // fill struct with zeroes, so we are sure no data is missing
        __builtin_memset(&fib_params, 0, sizeof(fib_params));

        fib_params.family	= AF_INET;
        // use daddr as source in the lookup, so we refleect packet back (as if it wcame from us)
        fib_params.ipv4_src	= ip_header->saddr;
        // opposite here, the destination is the source of the icmp packet..remote end
        fib_params.ipv4_dst	= ip_header->daddr;
        fib_params.ifindex = ctx->ingress_ifindex;

        bpf_printk("doing route lookup dst: %d\n", fib_params.ipv4_dst);
        int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
        if ((rc != BPF_FIB_LKUP_RET_SUCCESS) && (rc != BPF_FIB_LKUP_RET_NO_NEIGH)) {
            bpf_printk("dropping packet\n");
            return XDP_DROP;
        } else if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
            // here we should let packet pass so we resolve arp.
            bpf_printk("passing packet, lookup returned: %d\n", BPF_FIB_LKUP_RET_NO_NEIGH);
            return XDP_PASS;
        }
        bpf_printk("route lookup success, ifindex: %d\n", fib_params.ifindex);
        bpf_printk("mac to use as dst: %lu\n", fib_params.dmac);

        //int action = bpf_redirect_map(&if_redirect, fib_params.ifindex, 0);



        memcpy(eth_header->h_dest, fib_params.dmac, ETH_ALEN);
        memcpy(eth_header->h_source, fib_params.smac, ETH_ALEN);

        bpf_printk("dev: mac to use as src: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            eth_header->h_source[0], 
            eth_header->h_source[1], 
            eth_header->h_source[2], 
            eth_header->h_source[3], 
            eth_header->h_source[4],
            eth_header->h_source[5]
            );

        bpf_printk("dev: mac to use as dst: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            eth_header->h_dest[0], 
            eth_header->h_dest[1], 
            eth_header->h_dest[2], 
            eth_header->h_dest[3], 
            eth_header->h_dest[4],
            eth_header->h_dest[5]
            );


        int action = bpf_redirect(fib_params.ifindex,0);

        if (action == XDP_ABORTED){

            bpf_printk("aborted\n");
            return action;
        }

        if(action == XDP_REDIRECT){

            bpf_printk("redirect\n");

            return action;
        }

        return action;


    }



    return XDP_PASS;

}

char _license[] SEC("license") = "GPL";