
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


struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};


struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct ipv4_lpm_key);
  __type(value, __u32);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 255);
} allowed_addr SEC(".maps");

struct {
	__uint(priority, 20);
	__uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(allowed_addr_prog);


SEC("xdp")

int allowed_addr_prog(struct xdp_md *ctx) {

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



  struct {
    __u32 prefixlen;
    __u32 data;
  } key;

  __u16 allow_port = 0; 

  key.prefixlen = 32;
  key.data = 0;

  __u64 *allow_port_v = bpf_map_lookup_elem(&allowed_addr, &key);
  if (!allow_port_v) {
    bpf_printk("allow port not stored : %llu\n", allow_port_v);
    return XDP_DROP;
  }

  allow_port = *(__u16*)(allow_port_v);


  if (allow_port == 0) {

    bpf_printk("allow port still zero: drop\n");

    return XDP_DROP;
  }

  bpf_printk("allow port: %d\n", allow_port);

  bpf_printk("ip proto: %d\n", ip->protocol);

  if (ip->protocol == IPPROTO_UDP) { 

    bpf_printk("proto udp \n"); 

    struct udphdr *udp = data + sizeof(*eth_header) + sizeof(*ip);
    if (data + sizeof(*eth_header) + sizeof(*ip) + sizeof(*udp) > data_end) {

      return XDP_DROP;
    }

  
    if (bpf_ntohs(udp->dest) == allow_port){
      bpf_printk("coming in allowed packet\n");
      return XDP_PASS;
    } else {
      bpf_printk("udp dest not allowed port: %d\n", bpf_ntohs(udp->dest));
      return XDP_DROP;
    }

  }

  bpf_printk("not udp: drop\n");

  return XDP_DROP;

}


char _license[] SEC("license") = "GPL";