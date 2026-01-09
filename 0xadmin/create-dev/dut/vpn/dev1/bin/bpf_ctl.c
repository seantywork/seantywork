
#define AF_INET		2	/* Internet IP Protocol 	*/
#define ETH_ALEN    6
#define PROTO_IP     0x0800

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/string.h>

#include "xsk_def_xdp_prog.h"

struct hwaddr {
  __u8 data[6];
  __u8 rsvd[2];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, struct hwaddr);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 64); 
} inline_hw SEC(".maps");


SEC("xdp_pass")
int xdp_pass_prog(struct xdp_md *ctx){

  unsigned char *data_end = (unsigned char *)(long)ctx->data_end;
  unsigned char *data = (unsigned char *)(long)ctx->data;


  struct ethhdr *ether = (struct ethhdr *)data;
  if (data + sizeof(*ether) > data_end) {

    return XDP_DROP;
  }

//  bpf_printk("h proto: %d\n", bpf_ntohs(ether->h_proto));
  __u16 h_proto = ether->h_proto;

  //bpf_printk("h_proto orig: %02x\n", h_proto);
  //bpf_printk("h_proto hton: %02x\n", bpf_htons(h_proto));

  if (bpf_htons(h_proto) != PROTO_IP) { 
    // bpf_printk("proto not ip\n");
    return XDP_PASS;
  }

  //broadcast & multicast
  if(ether->h_dest[0] & 0x01){
    return XDP_PASS;
  }

  __u32 key = 0;
  struct hwaddr *value = NULL;

  value = bpf_map_lookup_elem(&inline_hw, &key);

  if(!value){
    bpf_printk("inline hw addr not found\n");
    return XDP_DROP;
  }

  //bpf_printk("inline hwaddr: %02x:%02x:%02x:%02x:%02x:%02x\n", value->data[0], value->data[1], value->data[2], value->data[3], value->data[4], value->data[5]);

  memcpy(ether->h_dest, value->data, 6);

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";