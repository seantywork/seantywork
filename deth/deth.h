#ifndef _DETH_X_H_ 
#define _DETH_X_H_ 



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


#define DRV_NAME	"deth"
#define DRV_COUNT   2


#define DETH_RX_INTR 0x0001
#define DETH_TX_INTR 0x0002


#define DETH_TIMEOUT 5   



struct deth_packet {
	struct deth_packet *next;
	struct net_device *dev;
	int	datalen;
	u8 data[ETH_DATA_LEN];
};

struct deth_priv {
    struct net_device_stats stats;
    int status;
    struct deth_packet *ppool;
    struct deth_packet *rx_queue; 
    int rx_int_enabled;
    int tx_packetlen;
    u8 *tx_packetdata;
    struct sk_buff *skb;
    spinlock_t lock;
	struct net_device *dev;
	struct napi_struct napi;
};


extern struct net_device *deth_devs[DRV_COUNT];
extern struct deth_priv *deth_privs[DRV_COUNT];
extern int setup_ptr;

extern const struct net_device_ops deth_netdev_ops;

extern const struct header_ops deth_header_ops;

extern int lockup;

extern int timeout;

extern int pool_size;

extern void (*deth_interrupt)(int, void *, struct pt_regs *);



void deth_setup_pool(struct net_device *dev);

void deth_teardown_pool(struct net_device *dev);

struct deth_packet *deth_tx_cons_buffer(struct net_device *dev);

void deth_tx_release_buffer(struct deth_packet *pkt);

void deth_rx_prod_buf(struct net_device *dev, struct deth_packet *pkt);

struct deth_packet *deth_rx_cons_buf(struct net_device *dev);



void deth_rx_ints(struct net_device *dev, int enable);

void deth_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs);

int deth_poll(struct napi_struct *napi, int budget);



netdev_tx_t deth_xmit(struct sk_buff *skb, struct net_device *dev);

void deth_hw_tx(char *buf, int len, struct net_device *dev);


int deth_open(struct net_device *dev);

int deth_stop(struct net_device *dev);




#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)

void deth_tx_timeout(struct net_device *dev);

#else 

void deth_tx_timeout(struct net_device *dev, unsigned int txqueue);

#endif 


/* module entry */

void deth_setup(struct net_device *dev);

#endif