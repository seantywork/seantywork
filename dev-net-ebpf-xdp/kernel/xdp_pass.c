
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


SEC("xdp_pass")
int xdp_pass_prog(struct xdp_md *ctx)
{

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";