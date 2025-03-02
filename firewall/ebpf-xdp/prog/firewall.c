
#define PROTO_IP     0x0800

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/xdp_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/string.h>


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u16);
  __type(value, __u16);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 65536); 
} port_verdict SEC(".maps");

struct {
	__uint(priority, 20);
	__uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(firewall_prog);


SEC("xdp")

int firewall_prog(struct xdp_md *ctx) {

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth_header = data;

  if (data + sizeof(*eth_header) > data_end) {

    return XDP_DROP;
  }

  __u16 h_proto = eth_header->h_proto;

  if (bpf_htons(h_proto) != PROTO_IP) { 

    bpf_printk("proto not ip\n");
    return XDP_PASS;
  }

  bpf_printk("proto ip\n");

  struct iphdr *ip = data + sizeof(*eth_header);
  if (data + sizeof(*eth_header) + sizeof(*ip) > data_end) {

    return XDP_DROP;
  }


  if(ip->protocol != IPPROTO_TCP){

    bpf_printk("proto not tcp: allowed\n");

    return XDP_PASS;

  } else {

    bpf_printk("proto tcp: checking\n");

    struct tcphdr *tcp = (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(*tcp) > data_end) {

      return XDP_DROP;
    }
  
    __u32 dest_port = bpf_ntohs(tcp->dest);

    __u16 verdict = 0; 
  
    __u64 *port_v = bpf_map_lookup_elem(&port_verdict, &dest_port);

    if (!port_v) {
      bpf_printk("port verdict not stored, default pass for port: %d\n", dest_port);
      return XDP_PASS;
    }
  
    verdict = *(__u16*)(port_v);

    bpf_printk("port: %d\n: verdict: %d\n", dest_port, verdict);

    if(verdict == 1){

      return XDP_PASS;

    } else if (verdict == 0) {

      return XDP_DROP;

    } else {

      bpf_printk("invalid verdict, we're happily passing though :) %d\n", verdict);
      return XDP_PASS;
    }

  }

  return XDP_PASS;

}


char _license[] SEC("license") = "GPL";