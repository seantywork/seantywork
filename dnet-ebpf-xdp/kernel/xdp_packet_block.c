
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "parsing_helpers.h"
#include "rewrite_helpers.h"

//#include "stats_kern_user.h"
//#include "stats_kern.h"

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, __u32);
        __type(value, long);
        __uint(max_entries, 1);
} rxcnt SEC(".maps");

SEC("xdp_block_port")
int xdp_block_port_func(struct xdp_md *ctx)
{
	int action = XDP_PASS;
	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	__u32 key = 0;
	long *value;

	bpf_printk("xdp entered\n");
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	bpf_printk("eth parsed\n");

	if (eth_type == bpf_htons(ETH_P_IP)) {
		bpf_printk("ip\n");
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		bpf_printk("ipv6\n");
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		bpf_printk("not ip nor v6\n");
		goto out;
	}

	if (ip_type == IPPROTO_UDP) {
		bpf_printk("udp\n");
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			bpf_printk("udp abort\n");
			action = XDP_ABORTED;
			goto out;
		}

		/*
		 * We need to update the packet checksum when modifying the header.
		 * RFC1071 contains an algorithm for in-place updating, which is what we use here
		 * since we're always just decrementing the port number. Another option would be
		 * to recompute the full checksum, like:
		 *
		 * struct udphdr udphdr_old;
		 * __u32 csum = udphdr->check;
		 * udphdr_old = *udphdr;
		 * udphdr->dest = bpf_htons(bpf_ntohs(udphdr->dest) - 1);
		 * csum = bpf_csum_diff((__be32 *)&udphdr_old, 4, (__be32 *)udphdr, 4, ~csum);
		 * udphdr->check = csum_fold_helper(csum);
		 */

		udphdr->dest = bpf_htons(bpf_ntohs(udphdr->dest) - 1);
		udphdr->check += bpf_htons(1);
		if (!udphdr->check){
			udphdr->check += bpf_htons(1);
		}
	} else if (ip_type == IPPROTO_TCP) {
		bpf_printk("tcp\n");
		if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
			bpf_printk("tcp abort\n");
			action = XDP_ABORTED;
			goto out;
		}
		tcphdr->dest = bpf_ntohs(tcphdr->dest);
		                
        tcphdr->check += bpf_htons(1);
		if (!tcphdr->check){
			tcphdr->check += bpf_htons(1);
		}
		bpf_printk("port: %d\n", tcphdr->dest);
		
		if(tcphdr->dest == 9999){
				bpf_printk("port 9999: drop\n");

                value = bpf_map_lookup_elem(&rxcnt, &key);
                if (value){
                        *value += 1;
				}
				action = XDP_DROP;
				goto out;
		} else {

			tcphdr->dest = bpf_htons(tcphdr->dest);
		}
	}

out:
	bpf_printk("out\n");
	//return xdp_stats_record_action(ctx, action);

	return action;
}

char _license[] SEC("license") = "GPL";