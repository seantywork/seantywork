#ifndef _KNEIGH_X_H_ 
#define _KNEIGH_X_H_ 



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


#define DRV_NAME	"kneigh"
#define DRV_COUNT   2


#define KNEIGH_RX_INTR 0x0001
#define KNEIGH_TX_INTR 0x0002


#define KNEIGH_TIMEOUT 5   

#define RT_GC_TIMEOUT (300*HZ)

struct kneigh_packet {
	struct kneigh_packet *next;
	struct net_device *dev;
	int	datalen;
	u8 data[ETH_DATA_LEN];
};

struct kneigh_priv {
    struct net_device_stats stats;
    int status;
    struct kneigh_packet *ppool;
    struct kneigh_packet *rx_queue; 
    int rx_int_enabled;
    int tx_packetlen;
    u8 *tx_packetdata;
    struct sk_buff *skb;
    spinlock_t lock;
	struct net_device *dev;
	struct napi_struct napi;
};


extern struct net_device *kneigh_devs[DRV_COUNT];
extern struct kneigh_priv *kneigh_privs[DRV_COUNT];
extern int setup_ptr;

extern const struct net_device_ops kneigh_netdev_ops;

extern const struct header_ops kneigh_header_ops;

extern int lockup;

extern int timeout;

extern int pool_size;

extern void (*kneigh_interrupt)(int, void *, struct pt_regs *);



void kneigh_setup_pool(struct net_device *dev);

void kneigh_teardown_pool(struct net_device *dev);

struct kneigh_packet *kneigh_tx_reserve_buffer(struct net_device *dev);

void kneigh_tx_release_buffer(struct kneigh_packet *pkt);

void kneigh_rx_prod_buf(struct net_device *dev, struct kneigh_packet *pkt);

struct kneigh_packet *kneigh_rx_cons_buf(struct net_device *dev);



void kneigh_rx_ints(struct net_device *dev, int enable);

void kneigh_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs);

int kneigh_poll(struct napi_struct *napi, int budget);



netdev_tx_t kneigh_xmit(struct sk_buff *skb, struct net_device *dev);

void kneigh_hw_tx(char *buf, int len, struct net_device *dev);


int kneigh_open(struct net_device *dev);

int kneigh_stop(struct net_device *dev);




#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)

void kneigh_tx_timeout(struct net_device *dev);

#else 

void kneigh_tx_timeout(struct net_device *dev, unsigned int txqueue);

#endif 


/* module entry */

void kneigh_setup(struct net_device *dev);

#endif