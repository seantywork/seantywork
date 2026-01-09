/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/xdp_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/string.h>
#include "xsk_def_xdp_prog.h"

#define DEFAULT_QUEUE_IDS 64

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, DEFAULT_QUEUE_IDS);
} xsks_map SEC(".maps");

struct {
	__uint(priority, 20);
	__uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xsk_def_prog);

/* Program refcount, in order to work properly,
 * must be declared before any other global variables
 * and initialized with '1'.
 */
volatile int refcnt = 1;

/* This is the program for post 5.3 kernels. */
SEC("xdp")
int xsk_def_prog(struct xdp_md *ctx)
{
	/* Make sure refcount is referenced by the program */
	if (!refcnt)
		return XDP_PASS;

	struct bpf_fib_lookup fib_params;

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth_header;
	struct iphdr *ip_header;

	eth_header = data;

    if ((void *)eth_header + sizeof(*eth_header) > data_end) {

		bpf_printk("invalid eth header\n");

        return XDP_PASS;
    }

	bpf_printk("valid eth header\n");

    __u16 h_proto = eth_header->h_proto;

	bpf_printk("h_proto: %02x\n", bpf_htons(h_proto));

    if (bpf_htons(h_proto) != 0x0800) {  // htons(ETH_P_IP) -> 0x08U

		bpf_printk("proto not ip\n");

        return XDP_PASS;
    }


	bpf_printk("proto ip\n");

    ip_header = data + sizeof(*eth_header);
    if ((void *)ip_header + sizeof(*ip_header) > data_end) {

        bpf_printk("invalid ip header\n");

        return XDP_PASS;
    }

	bpf_printk("valid ip header\n");

	__builtin_memset(&fib_params, 0, sizeof(fib_params));


	fib_params.family	= 2; //AF INET
	fib_params.ipv4_src	= ip_header->saddr;
	fib_params.ipv4_dst	= ip_header->daddr;
	fib_params.ifindex = ctx->ingress_ifindex;


	int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	if ((rc != BPF_FIB_LKUP_RET_SUCCESS) && (rc != BPF_FIB_LKUP_RET_NO_NEIGH)) {
		bpf_printk("dropping packet\n");
		return XDP_DROP;
	} else if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
		bpf_printk("passing packet, lookup returned: %d\n", BPF_FIB_LKUP_RET_NO_NEIGH);
		return XDP_PASS;
	}
    bpf_printk("route lookup success, ifindex: %d\n", fib_params.ifindex);


	memcpy(eth_header->h_dest, fib_params.dmac, 6);
	memcpy(eth_header->h_source, fib_params.smac, 6);
	
	bpf_printk("redirect\n");

	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
__uint(xsk_prog_version, XSK_PROG_VERSION) SEC(XDP_METADATA_SECTION);
