#ifndef _DUMMVETH_X_H_ 
#define _DUMMVETH_X_H_ 



#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>

#include <linux/sched.h>
#include <linux/kernel.h> /* printk() */
#include <linux/slab.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> 

#include <linux/in.h>
#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/skbuff.h>
#include <linux/version.h> 

#include <linux/in6.h>
#include <asm/checksum.h>

#define DRV_NAME	"dummveth"
#define DRV_COUNT   2


#define DUMMVETH_RX_INTR 0x0001
#define DUMMVETH_TX_INTR 0x0002

/* Default timeout period */
#define DUMMVETH_TIMEOUT 5   /* In jiffies */



struct dummveth_packet {
	struct dummveth_packet *next;
	struct net_device *dev;
	int	datalen;
	u8 data[ETH_DATA_LEN];
};

struct dummveth_priv {
    struct net_device_stats stats;
    int status;
    struct dummveth_packet *ppool;
    struct dummveth_packet *rx_queue; /* List of incoming packets */
    int rx_int_enabled;
    int tx_packetlen;
    u8 *tx_packetdata;
    struct sk_buff *skb;
    spinlock_t lock;
	struct net_device *dev;
	struct napi_struct napi;
};


extern struct net_device *dummveth_devs[DRV_COUNT];
extern struct dummveth_priv *dummveth_privs[DRV_COUNT];
extern int setup_ptr;

extern const struct net_device_ops dummveth_netdev_ops;

extern const struct header_ops dummveth_header_ops;

extern int lockup;

extern int timeout;

extern int use_napi;

extern int pool_size;

extern void (*dummveth_interrupt)(int, void *, struct pt_regs *);

/* util functions */

void dummveth_setup_pool(struct net_device *dev);

void dummveth_teardown_pool(struct net_device *dev);

struct dummveth_packet *dummveth_get_tx_buffer(struct net_device *dev);

void dummveth_release_buffer(struct dummveth_packet *pkt);

void dummveth_enqueue_buf(struct net_device *dev, struct dummveth_packet *pkt);

struct dummveth_packet *dummveth_dequeue_buf(struct net_device *dev);


/* rx, interrupt functions */

void dummveth_rx_ints(struct net_device *dev, int enable);

void dummveth_rx(struct net_device *dev, struct dummveth_packet *pkt);

int dummveth_poll(struct napi_struct *napi, int budget);

void dummveth_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs);

void dummveth_napi_interrupt(int irq, void *dev_id, struct pt_regs *regs);

/* device specific hw tx functions */

void dummveth_hw_tx(char *buf, int len, struct net_device *dev);


/* header and etc */

int dummveth_rebuild_header(struct sk_buff *skb);

int dummveth_header(struct sk_buff *skb, struct net_device *dev,
                unsigned short type, const void *daddr, const void *saddr,
                unsigned len);

int dummveth_change_mtu(struct net_device *dev, int new_mtu);


/* netdev */

int dummveth_open(struct net_device *dev);

int dummveth_stop(struct net_device *dev);

int dummveth_set_config(struct net_device *dev, struct ifmap *map);

netdev_tx_t dummveth_xmit(struct sk_buff *skb, struct net_device *dev);

int dummveth_do_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd);

//int dummveth_get_stats(struct net_device *dev);

struct net_device_stats* dummveth_get_stats(struct net_device *dev);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)

void dummveth_tx_timeout(struct net_device *dev);

#else 

void dummveth_tx_timeout(struct net_device *dev, unsigned int txqueue);

#endif 


/* module entry */

void dummveth_setup(struct net_device *dev);

#endif