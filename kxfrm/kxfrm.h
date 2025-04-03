#ifndef _KXFRM_X_H_ 
#define _KXFRM_X_H_ 



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

#include <linux/socket.h>
#include <net/xfrm.h>
#include <crypto/aead.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>



#define DRV_NAME	"kxfrm"
#define DRV_COUNT   2


#define KXFRM_RX_INTR 0x0001
#define KXFRM_TX_INTR 0x0002


#define KXFRM_TIMEOUT 5   

#define RT_GC_TIMEOUT (300*HZ)

struct kxfrm_packet {
	struct kxfrm_packet *next;
	struct net_device *dev;
	int	datalen;
	u8 data[ETH_DATA_LEN];
};

struct kxfrm_priv {
    struct net_device_stats stats;
    int status;
    struct kxfrm_packet *ppool;
    struct kxfrm_packet *rx_queue; 
    int rx_int_enabled;
    int tx_packetlen;
    u8 *tx_packetdata;
    struct sk_buff *skb;
    spinlock_t lock;
	struct net_device *dev;
	struct napi_struct napi;
};


extern struct net_device *kxfrm_devs[DRV_COUNT];
extern struct kxfrm_priv *kxfrm_privs[DRV_COUNT];
extern int setup_ptr;

extern const struct net_device_ops kxfrm_netdev_ops;

extern const struct header_ops kxfrm_header_ops;

extern int lockup;

extern int timeout;

extern int pool_size;

extern void (*kxfrm_interrupt)(int, void *, struct pt_regs *);



void kxfrm_setup_pool(struct net_device *dev);

void kxfrm_teardown_pool(struct net_device *dev);

struct kxfrm_packet *kxfrm_tx_cons_buffer(struct net_device *dev);

void kxfrm_tx_release_buffer(struct kxfrm_packet *pkt);

void kxfrm_rx_prod_buf(struct net_device *dev, struct kxfrm_packet *pkt);

struct kxfrm_packet *kxfrm_rx_cons_buf(struct net_device *dev);



void kxfrm_rx_ints(struct net_device *dev, int enable);

void kxfrm_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs);

int kxfrm_poll(struct napi_struct *napi, int budget);



netdev_tx_t kxfrm_xmit(struct sk_buff *skb, struct net_device *dev);

void kxfrm_hw_tx(char *buf, int len, struct net_device *dev);


int kxfrm_open(struct net_device *dev);

int kxfrm_stop(struct net_device *dev);




#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)

void kxfrm_tx_timeout(struct net_device *dev);

#else 

void kxfrm_tx_timeout(struct net_device *dev, unsigned int txqueue);

#endif 


/* module entry */

void kxfrm_setup(struct net_device *dev);




#endif