#ifndef _KXDP_X_H_ 
#define _KXDP_X_H_ 



#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/slab.h> 
#include <linux/errno.h>  
#include <linux/types.h>  
#include <linux/interrupt.h> 

#include <linux/netdevice.h>  
#include <linux/etherdevice.h> 
  
#include <linux/skbuff.h>
#include <linux/version.h> 

#include <linux/in6.h>
#include <asm/checksum.h>

#include <linux/in.h>
#include <linux/ip.h>          
#include <linux/tcp.h>       
#include <linux/udp.h>

#include <net/neighbour.h>
#include <net/route.h>
#include <net/arp.h>

#include <net/xdp.h>
#include <linux/filter.h>


#define DRV_NAME	"kxdp"
#define DRV_COUNT   2


#define KXDP_RX_INTR 0x0001
#define KXDP_TX_INTR 0x0002


#define KXDP_TIMEOUT 5   

#define RT_GC_TIMEOUT (300*HZ)

#define KXDP_XDP_FLAG		BIT(0)
#define KXDP_XDP_HEADROOM	(XDP_PACKET_HEADROOM + NET_IP_ALIGN)

#define KXDP_XDP_TX_BULK_SIZE	16
#define KDXP_XDP_BATCH		16

struct kxdp_packet {
	struct kxdp_packet *next;
	struct net_device *dev;
	int	datalen;
	u8 data[ETH_DATA_LEN];
};

struct kxdp_priv {
    struct net_device_stats stats;
    int status;
    struct kxdp_packet *ppool;
    struct kxdp_packet *rx_queue; 
    int rx_int_enabled;
    int tx_packetlen;
    u8 *tx_packetdata;
    struct sk_buff *skb;
    spinlock_t lock;
	struct net_device *dev;
	struct napi_struct napi;
    struct bpf_prog *xdp_prog;
    struct xdp_rxq_info xdp_rxq;
    struct xdp_mem_info	xdp_mem;
};

struct kxdp_xdp_buff {
	struct xdp_buff xdp;
	struct sk_buff *skb;
};


extern struct net_device *kxdp_devs[DRV_COUNT];
extern struct kxdp_priv *kxdp_privs[DRV_COUNT];
extern int setup_ptr;

extern const struct net_device_ops kxdp_netdev_ops;

extern const struct header_ops kxdp_header_ops;

extern int lockup;

extern int timeout;

extern int pool_size;

extern void (*kxdp_interrupt)(int, void *, struct pt_regs *);



void kxdp_setup_pool(struct net_device *dev);

void kxdp_teardown_pool(struct net_device *dev);

struct kxdp_packet *kxdp_tx_cons_buffer(struct net_device *dev);

void kxdp_tx_release_buffer(struct kxdp_packet *pkt);

void kxdp_rx_prod_buf(struct net_device *dev, struct kxdp_packet *pkt);

struct kxdp_packet *kxdp_rx_cons_buf(struct net_device *dev);



void kxdp_rx_ints(struct net_device *dev, int enable);

void kxdp_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs);

int kxdp_poll(struct napi_struct *napi, int budget);



netdev_tx_t kxdp_xmit(struct sk_buff *skb, struct net_device *dev);

void kxdp_hw_tx(char *buf, int len, struct net_device *dev);


int kxdp_open(struct net_device *dev);

int kxdp_stop(struct net_device *dev);




#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)

void kxdp_tx_timeout(struct net_device *dev);

#else 

void kxdp_tx_timeout(struct net_device *dev, unsigned int txqueue);

#endif 


/* module entry */

void kxdp_setup(struct net_device *dev);

#endif